"""Fake IoT login shell (raw TCP and Telnet variants).

Flow: banner -> login/password prompt (credentials are captured) -> stateful
fake BusyBox shell. Every step is logged against one session id.
"""

from __future__ import annotations

import socket
import time

from analyzer.classifier import classify_input
from app.config import settings
from app.database import log_event
from services.shell_emulator import ShellSession
from services.tcp_base import LineReader, SessionExpired, TCPDecoyServer

MAX_LOGIN_ATTEMPTS = 3

SHELL_BANNER = "\nIoT-CAM-3000 Remote Console\nFirmware: 1.0.7\n\n"
TELNET_BANNER = "\nIoT-CAM-3000 Telnet Service\nFirmware: 1.0.7\n\n"


def _send(conn: socket.socket, text: str) -> None:
    conn.sendall(text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8", "replace"))


def _login(conn, reader, log) -> str | None:
    """Prompt for credentials. Returns the username, or ``None`` if refused."""
    for _ in range(MAX_LOGIN_ATTEMPTS):
        _send(conn, "login: ")
        username = reader.readline()
        if username is None:
            return None
        username = username.strip()
        if not username:
            continue

        _send(conn, "Password: ")
        password = reader.readline()
        if password is None:
            return None
        password = password.strip()

        raw = f"login_attempt username={username} password={password}"
        result = classify_input(raw, service=log.service)
        log("login_attempt", raw, result.classification, result.risk_level)

        # Accept any non-empty password so the attacker proceeds to the shell,
        # where the interesting behaviour is.
        if password:
            return username[:32]
        _send(conn, "Login incorrect\n\n")

    return None


class _SessionLog:
    def __init__(self, service: str, ip: str, port: int, session_id: str) -> None:
        self.service = service
        self.ip = ip
        self.port = port
        self.session_id = session_id

    def __call__(self, event_type, raw_input, classification, risk_level) -> None:
        log_event(
            source_ip=self.ip,
            source_port=self.port,
            session_id=self.session_id,
            service=self.service,
            event_type=event_type,
            raw_input=raw_input,
            classification=classification,
            risk_level=risk_level,
        )


def make_handler(service: str, banner: str, telnet: bool):
    def handle(conn: socket.socket, ip: str, port: int, session_id: str) -> None:
        log = _SessionLog(service, ip, port, session_id)
        reader = LineReader(conn, telnet=telnet)
        started = time.monotonic()
        commands = 0
        reason = "client_closed"

        log("session_start", "connection_opened", "session_started", "low")
        try:
            _send(conn, banner)
            username = _login(conn, reader, log)
            if username is None:
                reason = "login_failed"
                return

            shell = ShellSession(username="root" if username in {"root", "admin"} else username)
            _send(conn, "\nBusyBox v1.24.1 (2021-04-12 09:10:33 CST) built-in shell (ash)\n\n")

            while not shell.closed:
                if commands >= settings.max_commands_per_session:
                    reason = "command_limit"
                    break

                _send(conn, shell.prompt)
                line = reader.readline()
                if line is None:
                    break
                command = line.strip()
                if not command:
                    continue

                commands += 1
                result = classify_input(command, service=service)
                log(
                    "command_truncated" if reader.truncated else "command",
                    command,
                    result.classification,
                    result.risk_level,
                )
                _send(conn, shell.run(command))
            else:
                reason = "client_exit"
        except SessionExpired:
            reason = "timeout"
            raise
        except OSError:
            reason = "connection_error"
            raise
        finally:
            duration = int(time.monotonic() - started)
            log(
                "session_end",
                f"reason={reason} commands={commands} duration={duration}s",
                "session_ended",
                "low",
            )

    return handle


def create_shell_server(host: str, port: int) -> TCPDecoyServer:
    return TCPDecoyServer(
        "fake_shell", host, port, make_handler("fake_shell", SHELL_BANNER, telnet=False)
    )
