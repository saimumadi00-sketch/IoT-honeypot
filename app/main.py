"""Entry point: starts the decoys and the dashboard.

Run with ``python -m app.main`` or ``python app/main.py``.
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
from pathlib import Path

# Allow running with: python app/main.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from waitress.server import create_server  # noqa: E402

from analyzer import classifier  # noqa: E402
from app.config import settings  # noqa: E402
from app.dashboard import create_dashboard_app  # noqa: E402
from app.database import init_db  # noqa: E402
from app.logging_setup import configure_logging  # noqa: E402
from services.fake_http import SERVER_IDENT, create_fake_http_app  # noqa: E402
from services.fake_mqtt import create_mqtt_server  # noqa: E402
from services.fake_shell import create_shell_server  # noqa: E402
from services.fake_telnet import create_telnet_server  # noqa: E402

logger = logging.getLogger("honeypot")


class WebService:
    """A Flask app served by waitress in a background thread."""

    def __init__(self, name: str, app, host: str, port: int, **options) -> None:
        self.name = name
        self.host = host
        self.port = port
        self._app = app
        self._options = options
        self._server = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._server = create_server(self._app, host=self.host, port=self.port, **self._options)
        self._thread = threading.Thread(target=self._server.run, name=self.name, daemon=True)
        self._thread.start()
        logger.info("%s listening on %s:%d", self.name, self.host, self.port)

    def stop(self) -> None:
        if self._server is not None:
            self._server.close()


def build_services() -> list:
    services = []
    if settings.enable_shell:
        services.append(create_shell_server(settings.shell_host, settings.shell_port))
    if settings.enable_telnet:
        services.append(create_telnet_server(settings.telnet_host, settings.telnet_port))
    if settings.enable_mqtt:
        services.append(create_mqtt_server(settings.mqtt_host, settings.mqtt_port))
    if settings.enable_http:
        services.append(
            WebService(
                "fake_http",
                create_fake_http_app(),
                settings.http_host,
                settings.http_port,
                ident=SERVER_IDENT,
                threads=8,
                connection_limit=settings.max_connections,
                channel_timeout=settings.idle_timeout,
                max_request_body_size=settings.max_http_body_bytes,
            )
        )
    return services


def main() -> int:
    configure_logging()

    if settings.dashboard_is_public and not settings.dashboard_auth_enabled:
        logger.error(
            "Refusing to start: DASHBOARD_HOST=%s exposes the dashboard beyond this "
            "machine but DASHBOARD_PASSWORD is not set.",
            settings.dashboard_host,
        )
        return 2

    init_db()
    classifier.warm_up()

    dashboard = WebService(
        "dashboard",
        create_dashboard_app(),
        settings.dashboard_host,
        settings.dashboard_port,
        threads=4,
    )

    started = []
    failed = []
    for service in [*build_services(), dashboard]:
        try:
            service.start()
            started.append(service)
        except OSError as exc:
            failed.append(service.name)
            logger.error(
                "Could not start %s on %s:%s: %s", service.name, service.host, service.port, exc
            )

    if dashboard not in started or len(started) == 1:
        logger.error("Nothing useful is running; shutting down.")
        for service in started:
            service.stop()
        return 1
    if failed:
        logger.warning("Running without: %s", ", ".join(failed))

    stop = threading.Event()

    def request_stop(signum, _frame):
        logger.info("Received signal %s, shutting down", signum)
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    logger.info(
        "Honeypot running. Dashboard: http://%s:%d (auth %s). Press CTRL+C to stop.",
        settings.dashboard_host,
        settings.dashboard_port,
        "on" if settings.dashboard_auth_enabled else "OFF",
    )
    while not stop.wait(1.0):
        pass

    for service in started:
        try:
            service.stop()
        except Exception:  # noqa: BLE001
            logger.exception("Error while stopping %s", service.name)
    logger.info("Honeypot stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
