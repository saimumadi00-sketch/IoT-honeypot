import socket
import threading

from analyzer.classifier import classify_input
from app.database import log_event


CONNACK = b"\x20\x02\x00\x00"


def _format_raw_input(data: bytes) -> str:
    decoded = data.decode(errors="ignore").strip()
    hex_payload = data.hex()

    if decoded:
        return f"hex={hex_payload} text={decoded}"

    return f"hex={hex_payload}"


def _fake_suback(data: bytes) -> bytes:
    packet_id = data[2:4] if len(data) >= 4 else b"\x00\x01"
    return b"\x90\x03" + packet_id + b"\x00"


def handle_client(conn: socket.socket, addr):
    source_ip = addr[0]

    with conn:
        log_event(
            source_ip=source_ip,
            service="fake_mqtt",
            event_type="session_start",
            raw_input="connection_opened",
            classification="session_started",
            risk_level="low",
        )

        while True:
            data = conn.recv(1024)

            if not data:
                break

            decoded = data.decode(errors="ignore").strip()
            raw_input = _format_raw_input(data)
            result = classify_input(decoded, service="fake_mqtt")
            first_byte = data[0]

            if first_byte == 0x10:
                event_type = "mqtt_connect"
                response = CONNACK
            elif first_byte == 0x82:
                event_type = "mqtt_subscribe"
                response = _fake_suback(data)
            else:
                event_type = "mqtt_probe"
                response = b""

            log_event(
                source_ip=source_ip,
                service="fake_mqtt",
                event_type=event_type,
                raw_input=raw_input,
                classification=result.classification,
                risk_level=result.risk_level,
            )

            if response:
                conn.sendall(response)

        log_event(
            source_ip=source_ip,
            service="fake_mqtt",
            event_type="session_end",
            raw_input="connection_closed",
            classification="session_ended",
            risk_level="low",
        )


def start_fake_mqtt(host: str, port: int):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(10)

    print(f"[+] Fake MQTT service listening on {host}:{port}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()
