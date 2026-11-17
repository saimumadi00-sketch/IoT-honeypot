"""SQLite event store.

Thread-safe: each thread gets its own connection, WAL mode lets the
dashboard read while the decoys write. Everything an attacker sends is
treated as untrusted text: it is sanitised, truncated and only ever passed
as a bound parameter.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from app.config import settings

logger = logging.getLogger(__name__)

EVENT_FIELDS = [
    "id",
    "timestamp",
    "session_id",
    "source_ip",
    "source_port",
    "service",
    "event_type",
    "raw_input",
    "classification",
    "risk_level",
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    service TEXT NOT NULL,
    event_type TEXT NOT NULL,
    raw_input TEXT,
    classification TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    session_id TEXT,
    source_port INTEGER
)
"""

# Columns added after the first release, applied to databases created before them.
_MIGRATIONS = {
    "session_id": "ALTER TABLE events ADD COLUMN session_id TEXT",
    "source_port": "ALTER TABLE events ADD COLUMN source_port INTEGER",
}

_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)",
    "CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_classification ON events(classification)",
    "CREATE INDEX IF NOT EXISTS idx_events_service ON events(service)",
]

_PRUNE_EVERY = 1000

_local = threading.local()
_init_lock = threading.Lock()
_initialised_for: Path | None = None
_db_path: Path = settings.db_path
_writes_since_prune = 0


def set_db_path(path: Path | str) -> None:
    """Point the store at a different file (used by tests)."""
    global _db_path, _initialised_for
    close_connection()
    _db_path = Path(path)
    _initialised_for = None


def close_connection() -> None:
    conn = getattr(_local, "conn", None)
    if conn is not None:
        conn.close()
    _local.conn = None
    _local.path = None


def _connect() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is not None and getattr(_local, "path", None) == _db_path:
        return conn
    if conn is not None:
        conn.close()

    _db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=10000")
    _local.conn = conn
    _local.path = _db_path
    return conn


def init_db() -> None:
    """Create or upgrade the schema. Safe to call repeatedly."""
    global _initialised_for
    if _initialised_for == _db_path:
        return

    with _init_lock:
        if _initialised_for == _db_path:
            return
        conn = _connect()
        with conn:
            conn.execute(_SCHEMA)
            existing = {row["name"] for row in conn.execute("PRAGMA table_info(events)")}
            for column, statement in _MIGRATIONS.items():
                if column not in existing:
                    conn.execute(statement)
                    logger.info("Database migrated: added column %s", column)
            for statement in _INDEXES:
                conn.execute(statement)
        _initialised_for = _db_path


def sanitize(text: str | None, limit: int | None = None) -> str:
    """Make attacker-controlled text safe to store and display."""
    if not text:
        return ""
    limit = settings.max_raw_input_chars if limit is None else limit
    cleaned = "".join(
        ch if ch.isprintable() or ch in "\t" else f"\\x{ord(ch):02x}" if ord(ch) < 256 else "?"
        for ch in text[: limit * 2]
    )
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "...[truncated]"
    return cleaned


def log_event(
    source_ip: str,
    service: str,
    event_type: str,
    raw_input: str,
    classification: str,
    risk_level: str,
    session_id: str | None = None,
    source_port: int | None = None,
) -> None:
    """Store one event. Never raises: a logging failure must not kill a decoy."""
    global _writes_since_prune
    try:
        init_db()
        conn = _connect()
        with conn:
            conn.execute(
                """
                INSERT INTO events (
                    timestamp, session_id, source_ip, source_port, service,
                    event_type, raw_input, classification, risk_level
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    session_id,
                    sanitize(source_ip, 64) or "unknown",
                    source_port,
                    service,
                    event_type,
                    sanitize(raw_input),
                    classification,
                    risk_level,
                ),
            )

        _writes_since_prune += 1
        if settings.max_events and _writes_since_prune >= _PRUNE_EVERY:
            _writes_since_prune = 0
            prune_events(settings.max_events)
    except sqlite3.Error:
        logger.exception("Failed to store event from %s (%s)", source_ip, service)


def prune_events(keep: int) -> int:
    """Drop the oldest rows so at most ``keep`` remain. Returns rows removed."""
    conn = _connect()
    with conn:
        cursor = conn.execute(
            """
            DELETE FROM events
            WHERE id <= (SELECT COALESCE(MAX(id), 0) FROM events) - ?
            """,
            (keep,),
        )
    if cursor.rowcount:
        logger.info("Pruned %d old events (cap %d)", cursor.rowcount, keep)
    return cursor.rowcount


def _filters(
    service: str | None,
    classification: str | None,
    risk_level: str | None,
    source_ip: str | None,
    session_id: str | None,
) -> tuple[str, list]:
    clauses, params = [], []
    for column, value in (
        ("service", service),
        ("classification", classification),
        ("risk_level", risk_level),
        ("source_ip", source_ip),
        ("session_id", session_id),
    ):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def get_events(
    limit: int = 100,
    offset: int = 0,
    service: str | None = None,
    classification: str | None = None,
    risk_level: str | None = None,
    source_ip: str | None = None,
    session_id: str | None = None,
) -> list[dict]:
    init_db()
    where, params = _filters(service, classification, risk_level, source_ip, session_id)
    rows = _connect().execute(
        f"SELECT {', '.join(EVENT_FIELDS)} FROM events {where} "
        "ORDER BY id DESC LIMIT ? OFFSET ?",
        (*params, max(1, limit), max(0, offset)),
    )
    return [dict(row) for row in rows]


def iter_events(batch_size: int = 1000) -> Iterator[dict]:
    """Stream every event oldest-first without loading the table into memory."""
    init_db()
    conn = _connect()
    last_id = 0
    while True:
        rows = conn.execute(
            f"SELECT {', '.join(EVENT_FIELDS)} FROM events WHERE id > ? ORDER BY id LIMIT ?",
            (last_id, batch_size),
        ).fetchall()
        if not rows:
            return
        for row in rows:
            yield dict(row)
        last_id = rows[-1]["id"]


def _grouped(conn: sqlite3.Connection, column: str, limit: int | None = None) -> list[dict]:
    query = f"SELECT {column}, COUNT(*) AS count FROM events GROUP BY {column} ORDER BY count DESC"
    if limit:
        query += f" LIMIT {int(limit)}"
    return [dict(row) for row in conn.execute(query)]


def get_stats() -> dict:
    init_db()
    conn = _connect()
    total = conn.execute("SELECT COUNT(*) AS total FROM events").fetchone()["total"]
    unique_ips = conn.execute(
        "SELECT COUNT(DISTINCT source_ip) AS n FROM events"
    ).fetchone()["n"]
    sessions = conn.execute(
        "SELECT COUNT(DISTINCT session_id) AS n FROM events WHERE session_id IS NOT NULL"
    ).fetchone()["n"]

    return {
        "total_events": total,
        "unique_source_ips": unique_ips,
        "total_sessions": sessions,
        "by_classification": _grouped(conn, "classification"),
        "by_service": _grouped(conn, "service"),
        "by_risk": _grouped(conn, "risk_level"),
        "top_source_ips": _grouped(conn, "source_ip", limit=10),
    }


def ping() -> bool:
    try:
        init_db()
        _connect().execute("SELECT 1").fetchone()
        return True
    except sqlite3.Error:
        return False
