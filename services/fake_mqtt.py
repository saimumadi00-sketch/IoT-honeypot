"""Fake MQTT broker.

Parses real MQTT 3.1 / 3.1.1 / 5.0 control packets so the log shows what
the client actually tried (client id, credentials, topics, payloads) and
answers well enough that scanners and bots keep talking.
"""

from __future__ import annotations

import socket
import time

from analyzer.classifier import classify_input
from app.config import settings
from app.database import log_event
from services.tcp_base import SessionExpired, TCPDecoyServer

MAX_PACKET_BYTES = 65536
MAX_PACKETS_PER_SESSION = 500
MAX_PAYLOAD_PREVIEW = 256

CONNECT, PUBLISH, PUBREL, SUBSCRIBE, UNSUBSCRIBE, PINGREQ, DISCONNECT = 1, 3, 6, 8, 10, 12, 14


class MalformedPacket(Exception):
    pass


class _Cursor:
    """Bounds-checked reader over one packet body."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.data):
            raise MalformedPacket("packet shorter than its fields claim")
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def binary(self) -> bytes:
        return self.take(self.u16())

    def string(self) -> str:
        return self.binary().decode("utf-8", errors="replace")

    def varint(self) -> int:
        value, shift = 0, 0
        for _ in range(4):
            byte = self.u8()
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7
        raise MalformedPacket("bad variable-length integer")

    def skip_properties(self) -> None:
        self.take(self.varint())


def _preview(payload: bytes) -> str:
    text = payload[:MAX_PAYLOAD_PREVIEW].decode("utf-8", errors="replace")
    suffix = "..." if len(payload) > MAX_PAYLOAD_PREVIEW else ""
    return f"{text}{suffix}"


def parse_connect(body: bytes) -> tuple[str, int]:
    """Return (description, protocol level) for a CONNECT packet."""
    cursor = _Cursor(body)
    protocol = cursor.string()
    level = cursor.u8()
    flags = cursor.u8()
    cursor.u16()  # keep-alive
    if level == 5:
        cursor.skip_properties()

    parts = [f"connect protocol={protocol}/{level}", f"client_id={cursor.string()}"]

    if flags & 0x04:  # will
        if level == 5:
            cursor.skip_properties()
        will_topic = cursor.string()
        will_payload = cursor.binary()
        parts.append(f"will_topic={will_topic} will_payload={_preview(will_payload)}")
    if flags & 0x80:
        parts.append(f"username={cursor.string()}")
    if flags & 0x40:
        parts.append(f"password={_preview(cursor.binary())}")
    return " ".join(parts), level


def parse_publish(flags: int, body: bytes, level: int) -> tuple[str, int, int]:
    """Return (description, qos, packet id)."""
    cursor = _Cursor(body)
    topic = cursor.string()
    qos = (flags >> 1) & 0x03
    packet_id = cursor.u16() if qos else 0
    if level == 5:
        cursor.skip_properties()
    payload = cursor.take(cursor.remaining())
    return f"publish topic={topic} qos={qos} payload={_preview(payload)}", qos, packet_id


def parse_subscribe(body: bytes, level: int, with_options: bool = True) -> tuple[list[str], int]:
    """Return (topics, packet id) for SUBSCRIBE / UNSUBSCRIBE."""
    cursor = _Cursor(body)
    packet_id = cursor.u16()
    if level == 5:
        cursor.skip_properties()
    topics = []
    while cursor.remaining() > 0 and len(topics) < 50:
        topics.append(cursor.string())
        if with_options:
            cursor.u8()
    if not topics:
        raise MalformedPacket("subscription without topics")
    return topics, packet_id


def _read_exact(conn: socket.socket, count: int, deadline: float) -> bytes | None:
    chunks = bytearray()
    while len(chunks) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SessionExpired("session time limit reached")
        conn.settimeout(min(settings.idle_timeout, remaining))
        try:
            data = conn.recv(count - len(chunks))
        except TimeoutError as exc:
            raise SessionExpired("idle timeout") from exc
        if not data:
            return None
        chunks += data
    return bytes(chunks)


def _read_packet(conn: socket.socket, deadline: float) -> tuple[int, int, bytes] | None:
    """Read one control packet. Returns (type, flags, body) or ``None`` on EOF."""
    header = _read_exact(conn, 1, deadline)
    if header is None:
        return None

    length, shift = 0, 0
    for _ in range(4):
        byte = _read_exact(conn, 1, deadline)
        if byte is None:
            return None
        length |= (byte[0] & 0x7F) << shift
        if not byte[0] & 0x80:
            break
        shift += 7
    else:
        raise MalformedPacket("remaining length too long")

    if length > MAX_PACKET_BYTES:
        raise MalformedPacket(f"packet of {length} bytes exceeds limit")

    body = _read_exact(conn, length, deadline) if length else b""
    if body is None:
        return None
    return header[0] >> 4, header[0] & 0x0F, body


def handle_client(conn: socket.socket, ip: str, port: int, session_id: str) -> None:
    def log(event_type: str, raw_input: str, classification=None, risk_level=None) -> None:
        if classification is None:
            result = classify_input(raw_input, service="fake_mqtt")
            classification, risk_level = result.classification, result.risk_level
        log_event(
            source_ip=ip,
            source_port=port,
            session_id=session_id,
            service="fake_mqtt",
            event_type=event_type,
            raw_input=raw_input,
            classification=classification,
            risk_level=risk_level,
        )

    deadline = time.monotonic() + settings.session_timeout
    started = time.monotonic()
    level = 4
    connected = False
    packets = 0
    reason = "client_closed"

    log("session_start", "connection_opened", "session_started", "low")
    try:
        # Peek at the first byte: anything that is not a CONNECT packet is not
        # MQTT (port scan, HTTP request, garbage). Log what was sent and stop,
        # rather than waiting for a "packet body" that will never arrive.
        conn.settimeout(settings.idle_timeout)
        try:
            first = conn.recv(1, socket.MSG_PEEK)
        except TimeoutError as exc:
            raise SessionExpired("idle timeout") from exc
        if first and first[0] >> 4 != CONNECT:
            conn.settimeout(1.0)
            try:
                raw = conn.recv(256)
            except TimeoutError:
                raw = first
            log(
                "mqtt_malformed",
                f"non_mqtt_data hex={raw.hex()} text={raw.decode('utf-8', 'replace')}",
                "general_probe",
                "low",
            )
            reason = "protocol_error"
            return

        while packets < MAX_PACKETS_PER_SESSION:
            packet = _read_packet(conn, deadline)
            if packet is None:
                break
            packet_type, flags, body = packet
            packets += 1

            if not connected and packet_type != CONNECT:
                reason = "protocol_error"
                break

            if packet_type == CONNECT:
                description, level = parse_connect(body)
                log("mqtt_connect", description)
                connected = True
                conn.sendall(b"\x20\x03\x00\x00\x00" if level == 5 else b"\x20\x02\x00\x00")
            elif packet_type == PUBLISH:
                description, qos, packet_id = parse_publish(flags, body, level)
                log("mqtt_publish", description)
                if qos:
                    ack = 0x40 if qos == 1 else 0x50
                    conn.sendall(bytes([ack, 0x02]) + packet_id.to_bytes(2, "big"))
            elif packet_type == PUBREL:
                conn.sendall(b"\x70\x02" + body[:2].ljust(2, b"\x00"))
            elif packet_type == SUBSCRIBE:
                topics, packet_id = parse_subscribe(body, level)
                log("mqtt_subscribe", "subscribe " + " ".join(f"topic={t}" for t in topics))
                payload = packet_id.to_bytes(2, "big")
                if level == 5:
                    payload += b"\x00"
                payload += b"\x00" * len(topics)
                conn.sendall(bytes([0x90, len(payload)]) + payload)
            elif packet_type == UNSUBSCRIBE:
                topics, packet_id = parse_subscribe(body, level, with_options=False)
                log("mqtt_unsubscribe", "unsubscribe " + " ".join(f"topic={t}" for t in topics))
                conn.sendall(b"\xb0\x02" + packet_id.to_bytes(2, "big"))
            elif packet_type == PINGREQ:
                log("mqtt_ping", "pingreq")
                conn.sendall(b"\xd0\x00")
            elif packet_type == DISCONNECT:
                reason = "client_disconnect"
                break
            else:
                log("mqtt_other", f"mqtt packet type={packet_type} flags={flags} hex={body[:64].hex()}")
        else:
            reason = "packet_limit"
    except MalformedPacket as exc:
        reason = "malformed_packet"
        log("mqtt_malformed", f"malformed mqtt packet: {exc}", "general_probe", "low")
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
            f"reason={reason} packets={packets} duration={duration}s",
            "session_ended",
            "low",
        )


def create_mqtt_server(host: str, port: int) -> TCPDecoyServer:
    return TCPDecoyServer("fake_mqtt", host, port, handle_client)
