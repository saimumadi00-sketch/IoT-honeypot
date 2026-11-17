"""Shared plumbing for the raw TCP decoys.

Provides:

* ``TCPDecoyServer`` - accept loop with global and per-IP connection caps,
  per-connection threads, error isolation and clean shutdown.
* ``LineReader`` - buffered line input with idle and total-session timeouts
  and a maximum line length, with optional Telnet option-negotiation handling.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
import uuid
from collections import defaultdict
from collections.abc import Callable

from app.config import settings

logger = logging.getLogger(__name__)

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240


class ConnectionLimiter:
    """Caps concurrent connections overall and per source IP."""

    def __init__(self, max_total: int, max_per_ip: int) -> None:
        self.max_total = max_total
        self.max_per_ip = max_per_ip
        self._lock = threading.Lock()
        self._total = 0
        self._per_ip: dict[str, int] = defaultdict(int)

    def acquire(self, ip: str) -> bool:
        with self._lock:
            if self._total >= self.max_total or self._per_ip[ip] >= self.max_per_ip:
                return False
            self._total += 1
            self._per_ip[ip] += 1
            return True

    def release(self, ip: str) -> None:
        with self._lock:
            self._total = max(0, self._total - 1)
            self._per_ip[ip] -= 1
            if self._per_ip[ip] <= 0:
                del self._per_ip[ip]

    @property
    def active(self) -> int:
        return self._total


# One limiter for every TCP decoy, so the cap is process-wide.
limiter = ConnectionLimiter(settings.max_connections, settings.max_connections_per_ip)


def new_session_id() -> str:
    return uuid.uuid4().hex[:16]


class SessionExpired(Exception):
    """Raised when a session exceeds its idle or total time budget."""


class LineReader:
    """Reads newline-terminated input from a socket safely."""

    def __init__(self, conn: socket.socket, telnet: bool = False) -> None:
        self.conn = conn
        self.telnet = telnet
        self._buffer = bytearray()
        self._pending = bytearray()  # incomplete Telnet sequence
        self._deadline = time.monotonic() + settings.session_timeout
        self.truncated = False
        self._discarding = False

    def _strip_telnet(self, data: bytes) -> bytes:
        """Remove Telnet commands and refuse every option the client offers."""
        data = bytes(self._pending) + data
        self._pending.clear()
        clean = bytearray()
        reply = bytearray()
        i, n = 0, len(data)

        while i < n:
            byte = data[i]
            if byte != IAC:
                clean.append(byte)
                i += 1
                continue
            if i + 1 >= n:
                self._pending += data[i:]
                break
            command = data[i + 1]
            if command == IAC:
                clean.append(IAC)
                i += 2
            elif command in (DO, DONT, WILL, WONT):
                if i + 2 >= n:
                    self._pending += data[i:]
                    break
                option = data[i + 2]
                if command == DO:
                    reply += bytes((IAC, WONT, option))
                elif command == WILL:
                    reply += bytes((IAC, DONT, option))
                i += 3
            elif command == SB:
                end = data.find(bytes((IAC, SE)), i + 2)
                if end == -1:
                    # Keep waiting, but never buffer an unbounded subnegotiation.
                    if n - i <= settings.max_line_bytes:
                        self._pending += data[i:]
                    break
                i = end + 2
            else:
                i += 2

        if reply:
            try:
                self.conn.sendall(bytes(reply))
            except OSError:
                pass
        return bytes(clean)

    def _pop_line(self) -> str | None:
        for index, byte in enumerate(self._buffer):
            if byte in (0x0A, 0x0D):
                line = bytes(self._buffer[:index])
                rest = index + 1
                # Swallow the second half of CRLF / CR NUL.
                if (
                    byte == 0x0D
                    and rest < len(self._buffer)
                    and self._buffer[rest] in (0x0A, 0x00)
                ):
                    rest += 1
                del self._buffer[:rest]
                if self._discarding:
                    # Tail of an over-long line that was already returned.
                    self._discarding = False
                    return self._pop_line()
                if len(line) > settings.max_line_bytes:
                    line = line[: settings.max_line_bytes]
                    self.truncated = True
                return line.decode("utf-8", errors="replace").strip("\x00")
        return None

    def readline(self) -> str | None:
        """Return the next line, or ``None`` when the peer disconnects.

        A line longer than ``max_line_bytes`` is cut off: the first part is
        returned with ``truncated`` set and the rest, up to the next newline,
        is thrown away instead of being buffered or run as further commands.
        """
        self.truncated = False
        while True:
            line = self._pop_line()
            if line is not None:
                return line

            if self._discarding:
                self._buffer.clear()
            elif len(self._buffer) >= settings.max_line_bytes:
                line = bytes(self._buffer[: settings.max_line_bytes]).decode(
                    "utf-8", errors="replace"
                )
                self._buffer.clear()
                self._discarding = True
                self.truncated = True
                return line

            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise SessionExpired("session time limit reached")
            self.conn.settimeout(min(settings.idle_timeout, remaining))

            try:
                data = self.conn.recv(4096)
            except TimeoutError as exc:
                raise SessionExpired("idle timeout") from exc

            if not data:
                if self._buffer and not self._discarding:
                    line = bytes(self._buffer).decode("utf-8", errors="replace")
                    self._buffer.clear()
                    return line
                return None

            if self.telnet:
                data = self._strip_telnet(data)
            self._buffer += data


Handler = Callable[[socket.socket, str, int, str], None]


class TCPDecoyServer:
    """Threaded TCP listener that hands each connection to ``handler``."""

    def __init__(self, name: str, host: str, port: int, handler: Handler) -> None:
        self.name = name
        self.host = host
        self.port = port
        self.handler = handler
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()

    def start(self) -> None:
        """Bind and start accepting. Raises ``OSError`` if the port is unavailable."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((self.host, self.port))
        except OSError:
            server.close()
            raise
        server.listen(64)
        server.settimeout(0.25)
        self._socket = server
        self.port = server.getsockname()[1]

        self._thread = threading.Thread(
            target=self._accept_loop, name=f"{self.name}-accept", daemon=True
        )
        self._thread.start()
        logger.info("%s listening on %s:%d", self.name, self.host, self.port)

    def stop(self) -> None:
        self._stopping.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3)

    def _accept_loop(self) -> None:
        assert self._socket is not None
        while not self._stopping.is_set():
            try:
                conn, addr = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stopping.is_set():
                    return
                logger.exception("%s accept failed", self.name)
                time.sleep(0.5)
                continue

            ip, port = addr[0], addr[1]
            if not limiter.acquire(ip):
                logger.warning("%s refused %s: connection limit reached", self.name, ip)
                conn.close()
                continue

            threading.Thread(
                target=self._serve,
                args=(conn, ip, port),
                name=f"{self.name}-{ip}",
                daemon=True,
            ).start()

    def _serve(self, conn: socket.socket, ip: str, port: int) -> None:
        session_id = new_session_id()
        try:
            conn.settimeout(settings.idle_timeout)
            self.handler(conn, ip, port, session_id)
        except SessionExpired as exc:
            logger.info("%s session %s from %s closed: %s", self.name, session_id, ip, exc)
        except (TimeoutError, ConnectionError, OSError) as exc:
            logger.debug("%s session %s from %s dropped: %s", self.name, session_id, ip, exc)
        except Exception:  # noqa: BLE001 - one bad session must not stop the decoy
            logger.exception("%s session %s from %s crashed", self.name, session_id, ip)
        finally:
            try:
                conn.close()
            except OSError:
                pass
            limiter.release(ip)
