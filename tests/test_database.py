import sqlite3
import threading

from app import database


def _log(**overrides):
    event = dict(
        source_ip="203.0.113.5", service="fake_shell", event_type="command",
        raw_input="whoami", classification="reconnaissance", risk_level="medium",
    )
    event.update(overrides)
    database.log_event(**event)


def test_roundtrip_and_filters():
    _log(session_id="abc", source_port=4242)
    _log(service="http", classification="web_admin_scan", raw_input="GET /admin")

    events = database.get_events()
    assert [event["service"] for event in events] == ["http", "fake_shell"]
    assert events[1]["session_id"] == "abc" and events[1]["source_port"] == 4242
    assert len(database.get_events(service="http")) == 1
    assert len(database.get_events(session_id="abc")) == 1
    assert database.get_events(limit=1, offset=1)[0]["service"] == "fake_shell"


def test_sql_injection_is_stored_as_text():
    payload = "'; DROP TABLE events; --"
    _log(raw_input=payload, source_ip=payload)
    assert database.get_events(source_ip=payload)[0]["raw_input"] == payload
    assert database.get_stats()["total_events"] == 1


def test_control_characters_and_length_are_sanitised():
    _log(raw_input="a\x1b[2Jb\x00c" + "x" * 10_000)
    stored = database.get_events()[0]["raw_input"]
    assert "\x1b" not in stored and "\x00" not in stored
    assert stored.startswith("a\\x1b[2Jb\\x00c")
    assert stored.endswith("...[truncated]") and len(stored) < 2100


def test_stats():
    for ip in ("1.1.1.1", "1.1.1.1", "2.2.2.2"):
        _log(source_ip=ip, session_id=ip)
    stats = database.get_stats()
    assert stats["total_events"] == 3
    assert stats["unique_source_ips"] == 2
    assert stats["total_sessions"] == 2
    assert stats["top_source_ips"][0] == {"source_ip": "1.1.1.1", "count": 2}


def test_prune_keeps_newest():
    for index in range(10):
        _log(raw_input=f"cmd{index}")
    assert database.prune_events(4) == 6
    assert [event["raw_input"] for event in database.get_events()] == ["cmd9", "cmd8", "cmd7", "cmd6"]


def test_iter_events_streams_everything_in_order():
    for index in range(25):
        _log(raw_input=f"cmd{index}")
    assert [e["raw_input"] for e in database.iter_events(batch_size=7)] == [f"cmd{i}" for i in range(25)]


def test_concurrent_writers():
    def worker(number):
        for index in range(50):
            _log(raw_input=f"{number}-{index}")
        database.close_connection()

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert database.get_stats()["total_events"] == 400


def test_migrates_first_release_schema(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,"
        " source_ip TEXT NOT NULL, service TEXT NOT NULL, event_type TEXT NOT NULL,"
        " raw_input TEXT, classification TEXT NOT NULL, risk_level TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO events (timestamp, source_ip, service, event_type, raw_input,"
        " classification, risk_level) VALUES ('2026-01-01T00:00:00Z','9.9.9.9','http',"
        "'http_request','GET /','general_probe','low')"
    )
    conn.commit()
    conn.close()

    database.set_db_path(path)
    _log(session_id="new")
    events = database.get_events()
    assert len(events) == 2
    assert events[0]["session_id"] == "new" and events[1]["session_id"] is None
