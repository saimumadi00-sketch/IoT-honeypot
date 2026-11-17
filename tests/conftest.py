"""Shared fixtures. Environment is set before any project module is imported."""

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="honeypot-tests-")
os.environ["HONEYPOT_DATA_DIR"] = _TMP
os.environ["HONEYPOT_LOG_DIR"] = _TMP
os.environ["HONEYPOT_IDLE_TIMEOUT"] = "2"
os.environ["HONEYPOT_SESSION_TIMEOUT"] = "5"
os.environ["HONEYPOT_MAX_CONNECTIONS_PER_IP"] = "50"
os.environ["HONEYPOT_MAX_LINE_BYTES"] = "256"
os.environ["HONEYPOT_MAX_COMMANDS"] = "20"
os.environ.pop("DASHBOARD_PASSWORD", None)

import socket  # noqa: E402
import time  # noqa: E402

import pytest  # noqa: E402

from app import database  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    database.set_db_path(tmp_path / "test.db")
    database.init_db()
    yield
    database.close_connection()


class Client:
    """Tiny blocking TCP client for talking to the decoys."""

    def __init__(self, port: int) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.buffer = b""

    def read_until(self, marker: bytes, timeout: float = 5.0) -> bytes:
        deadline = time.monotonic() + timeout
        while marker not in self.buffer:
            self.sock.settimeout(max(0.05, deadline - time.monotonic()))
            try:
                chunk = self.sock.recv(4096)
            except TimeoutError:
                raise AssertionError(f"timed out waiting for {marker!r}; got {self.buffer!r}")
            if not chunk:
                raise AssertionError(f"closed before {marker!r}; got {self.buffer!r}")
            self.buffer += chunk
        index = self.buffer.index(marker) + len(marker)
        data, self.buffer = self.buffer[:index], self.buffer[index:]
        return data

    def read_exact(self, count: int) -> bytes:
        while len(self.buffer) < count:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise AssertionError(f"closed early; got {self.buffer!r}")
            self.buffer += chunk
        data, self.buffer = self.buffer[:count], self.buffer[count:]
        return data

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def wait_closed(self, timeout: float = 8.0) -> bool:
        self.sock.settimeout(timeout)
        try:
            while True:
                if not self.sock.recv(4096):
                    return True
        except TimeoutError:
            return False
        except OSError:
            return True

    def close(self) -> None:
        self.sock.close()


def wait_for_event(event_type: str, timeout: float = 5.0, **filters):
    """Poll until an event of this type is stored (handlers run in threads)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for event in database.get_events(limit=200, **filters):
            if event["event_type"] == event_type:
                return event
        time.sleep(0.05)
    raise AssertionError(f"no {event_type} event; have {database.get_events(limit=200)}")
