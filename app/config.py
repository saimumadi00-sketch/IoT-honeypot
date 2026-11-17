"""Runtime configuration.

Every setting can be overridden with an environment variable (see
``.env.example``). Defaults are safe for local use: everything binds to
loopback and nothing needs root.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_str(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # Storage
    data_dir: Path
    log_dir: Path
    db_path: Path
    log_level: str

    # Dashboard (operator-facing, keep private)
    dashboard_host: str
    dashboard_port: int
    dashboard_username: str
    dashboard_password: str

    # Decoy services (attacker-facing)
    http_host: str
    http_port: int
    shell_host: str
    shell_port: int
    mqtt_host: str
    mqtt_port: int
    telnet_host: str
    telnet_port: int

    # Which decoys to run
    enable_http: bool
    enable_shell: bool
    enable_mqtt: bool
    enable_telnet: bool

    # Abuse limits
    max_connections: int
    max_connections_per_ip: int
    session_timeout: int
    idle_timeout: int
    max_line_bytes: int
    max_commands_per_session: int
    max_raw_input_chars: int
    max_http_body_bytes: int
    max_events: int

    # Classifier
    use_ml: bool
    ml_min_confidence: float

    @property
    def dashboard_auth_enabled(self) -> bool:
        return bool(self.dashboard_password)

    @property
    def dashboard_is_public(self) -> bool:
        return self.dashboard_host not in {"127.0.0.1", "localhost", "::1"}


def load_settings() -> Settings:
    data_dir = Path(_env_str("HONEYPOT_DATA_DIR", str(BASE_DIR / "data")))
    log_dir = Path(_env_str("HONEYPOT_LOG_DIR", str(BASE_DIR / "logs")))

    confidence_raw = _env_str("HONEYPOT_ML_MIN_CONFIDENCE", "0.45")
    try:
        confidence = float(confidence_raw)
    except ValueError as exc:
        raise ValueError(
            f"HONEYPOT_ML_MIN_CONFIDENCE must be a number, got {confidence_raw!r}"
        ) from exc

    return Settings(
        data_dir=data_dir,
        log_dir=log_dir,
        db_path=Path(_env_str("HONEYPOT_DB_PATH", str(data_dir / "honeypot.db"))),
        log_level=_env_str("HONEYPOT_LOG_LEVEL", "INFO").upper(),
        dashboard_host=_env_str("DASHBOARD_HOST", "127.0.0.1"),
        dashboard_port=_env_int("DASHBOARD_PORT", 5000, 1),
        dashboard_username=_env_str("DASHBOARD_USERNAME", "admin"),
        dashboard_password=os.environ.get("DASHBOARD_PASSWORD", ""),
        http_host=_env_str("FAKE_HTTP_HOST", "127.0.0.1"),
        http_port=_env_int("FAKE_HTTP_PORT", 8080, 1),
        shell_host=_env_str("FAKE_SHELL_HOST", "127.0.0.1"),
        shell_port=_env_int("FAKE_SHELL_PORT", 2222, 1),
        mqtt_host=_env_str("FAKE_MQTT_HOST", "127.0.0.1"),
        mqtt_port=_env_int("FAKE_MQTT_PORT", 1883, 1),
        telnet_host=_env_str("FAKE_TELNET_HOST", "127.0.0.1"),
        # 2323 by default: binding port 23 needs root. Map 23 -> 2323 with
        # Docker or a firewall rule instead of running the honeypot as root.
        telnet_port=_env_int("FAKE_TELNET_PORT", 2323, 1),
        enable_http=_env_bool("ENABLE_HTTP", True),
        enable_shell=_env_bool("ENABLE_SHELL", True),
        enable_mqtt=_env_bool("ENABLE_MQTT", True),
        enable_telnet=_env_bool("ENABLE_TELNET", True),
        max_connections=_env_int("HONEYPOT_MAX_CONNECTIONS", 200, 1),
        max_connections_per_ip=_env_int("HONEYPOT_MAX_CONNECTIONS_PER_IP", 10, 1),
        session_timeout=_env_int("HONEYPOT_SESSION_TIMEOUT", 300, 1),
        idle_timeout=_env_int("HONEYPOT_IDLE_TIMEOUT", 60, 1),
        max_line_bytes=_env_int("HONEYPOT_MAX_LINE_BYTES", 4096, 64),
        max_commands_per_session=_env_int("HONEYPOT_MAX_COMMANDS", 500, 1),
        max_raw_input_chars=_env_int("HONEYPOT_MAX_RAW_INPUT", 2000, 64),
        max_http_body_bytes=_env_int("HONEYPOT_MAX_HTTP_BODY", 65536, 1024),
        max_events=_env_int("HONEYPOT_MAX_EVENTS", 500000, 0),
        use_ml=_env_bool("HONEYPOT_USE_ML", True),
        ml_min_confidence=confidence,
    )


settings = load_settings()
