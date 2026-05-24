import sqlite3
from datetime import datetime
from pathlib import Path

from app.config import DB_PATH, DATA_DIR


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                service TEXT NOT NULL,
                event_type TEXT NOT NULL,
                raw_input TEXT,
                classification TEXT NOT NULL,
                risk_level TEXT NOT NULL
            )
            """
        )
        conn.commit()


def log_event(
    source_ip: str,
    service: str,
    event_type: str,
    raw_input: str,
    classification: str,
    risk_level: str,
) -> None:
    init_db()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO events (
                timestamp, source_ip, service, event_type,
                raw_input, classification, risk_level
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().isoformat(timespec="seconds") + "Z",
                source_ip,
                service,
                event_type,
                raw_input,
                classification,
                risk_level,
            ),
        )
        conn.commit()


def get_events(limit: int = 100):
    init_db()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]


def get_stats():
    init_db()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) AS total FROM events")
        total = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT classification, COUNT(*) AS count
            FROM events
            GROUP BY classification
            ORDER BY count DESC
            """
        )
        by_classification = [dict(row) for row in cursor.fetchall()]

        cursor.execute(
            """
            SELECT service, COUNT(*) AS count
            FROM events
            GROUP BY service
            ORDER BY count DESC
            """
        )
        by_service = [dict(row) for row in cursor.fetchall()]

        cursor.execute(
            """
            SELECT risk_level, COUNT(*) AS count
            FROM events
            GROUP BY risk_level
            ORDER BY count DESC
            """
        )
        by_risk = [dict(row) for row in cursor.fetchall()]

        return {
            "total_events": total,
            "by_classification": by_classification,
            "by_service": by_service,
            "by_risk": by_risk,
        }
