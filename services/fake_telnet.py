import socket
import threading

from analyzer.classifier import classify_input
from app.database import log_event
from services.fake_shell import fake_response


BANNER = """
IoT-CAM-3000 Telnet Service
Firmware: 1.0.7

login: admin
Password:
Access granted.

"""


def handle_client(conn: socket.socket, addr):
    source_ip = addr[0]

    with conn:
        conn.sendall(BANNER.encode())

        log_event(
            source_ip=source_ip,
            service="fake_telnet",
            event_type="session_start",
            raw_input="connection_opened",
            classification="session_started",
            risk_level="low",
        )

        while True:
            conn.sendall(b"root@iot-camera:~# ")
            data = conn.recv(1024)

            if not data:
                break

            command = data.decode(errors="ignore").strip()
            result = classify_input(command, service="fake_telnet")

            log_event(
                source_ip=source_ip,
                service="fake_telnet",
                event_type="command",
                raw_input=command,
                classification=result.classification,
                risk_level=result.risk_level,
            )

            response = fake_response(command)
            conn.sendall(response.encode())

            if command.lower() in {"exit", "quit"}:
                break

        log_event(
            source_ip=source_ip,
            service="fake_telnet",
            event_type="session_end",
            raw_input="connection_closed",
            classification="session_ended",
            risk_level="low",
        )


def start_fake_telnet(host: str, port: int):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(10)

    print(f"[+] Fake Telnet service listening on {host}:{port}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()
