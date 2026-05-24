import socket
import threading

from analyzer.classifier import classify_input
from app.database import log_event


BANNER = """
IoT-CAM-3000 Secure Shell
Firmware: 1.0.7
Type 'help' for commands.

login: admin
Password: 
Access granted.

"""


def fake_response(command: str) -> str:
    """
    Adaptive fake response logic.
    The honeypot changes output based on attacker commands.
    """
    cmd = command.lower().strip()

    if cmd in {"exit", "quit"}:
        return "Goodbye.\n"

    if cmd == "help":
        return "Available commands: status, version, ifconfig, ps, reboot, exit\n"

    if "uname" in cmd:
        return "Linux iot-camera 4.4.0 armv7l GNU/Linux\n"

    if "whoami" in cmd or cmd == "id":
        return "root\n"

    if "cat /etc/passwd" in cmd:
        return (
            "root:x:0:0:root:/root:/bin/sh\n"
            "admin:x:1000:1000:admin:/home/admin:/bin/sh\n"
            "camera:x:1001:1001:camera:/opt/camera:/bin/false\n"
        )

    if "ifconfig" in cmd or "ip addr" in cmd:
        return (
            "eth0      Link encap:Ethernet  HWaddr 00:16:3e:11:22:33\n"
            "          inet addr:192.168.1.64  Bcast:192.168.1.255  Mask:255.255.255.0\n"
        )

    if "ps" in cmd:
        return (
            "PID   USER     COMMAND\n"
            "1     root     /sbin/init\n"
            "72    root     /usr/bin/camera-daemon\n"
            "88    root     /usr/bin/httpd\n"
        )

    if "wget" in cmd or "curl" in cmd:
        return "Connecting... saved payload to /tmp/update.sh\n"

    if "chmod" in cmd:
        return ""

    if "./" in cmd or "sh " in cmd:
        return "Segmentation fault\n"

    if "reboot" in cmd:
        return "System reboot scheduled.\n"

    return "sh: command not found\n"


def handle_client(conn: socket.socket, addr):
    source_ip = addr[0]

    with conn:
        conn.sendall(BANNER.encode())

        log_event(
            source_ip=source_ip,
            service="fake_shell",
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
            result = classify_input(command, service="fake_shell")

            log_event(
                source_ip=source_ip,
                service="fake_shell",
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
            service="fake_shell",
            event_type="session_end",
            raw_input="connection_closed",
            classification="session_ended",
            risk_level="low",
        )


def start_fake_shell(host: str, port: int):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(10)

    print(f"[+] Fake IoT shell listening on {host}:{port}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()
