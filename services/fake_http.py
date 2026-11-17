"""Fake IoT camera web admin panel."""

from __future__ import annotations

import base64
import binascii

from flask import Flask, Response, request
from werkzeug.exceptions import HTTPException

from analyzer.classifier import classify_input
from app.config import settings
from app.database import log_event

# Passed to waitress as the Server header so the decoy does not announce itself.
SERVER_IDENT = "GoAhead-Webs"

_ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

_INDEX_PAGE = """<html>
  <head><title>IoT-CAM-3000</title></head>
  <body>
    <h2>IoT-CAM-3000</h2>
    <p>Firmware Version: 1.0.7</p>
    <p>Status: Online</p>
    <a href="/login">Admin Login</a>
  </body>
</html>
"""

_LOGIN_PAGE = """<html>
  <head><title>IoT-CAM-3000 Admin Login</title></head>
  <body>
    <h2>IoT-CAM-3000 Admin Panel</h2>
    <form method="POST" action="/login">
      <label>Username:</label><br>
      <input name="username"><br><br>
      <label>Password:</label><br>
      <input name="password" type="password"><br><br>
      <button type="submit">Login</button>
    </form>
    {message}
  </body>
</html>
"""


def _request_line() -> str:
    target = request.full_path.rstrip("?") if request.query_string else request.path
    return f"{request.method} {target}"


def _log(event_type: str, raw: str) -> None:
    result = classify_input(raw, service="http")
    agent = request.headers.get("User-Agent", "")
    log_event(
        source_ip=request.remote_addr or "unknown",
        source_port=request.environ.get("REMOTE_PORT") and int(request.environ["REMOTE_PORT"]),
        service="http",
        event_type=event_type,
        raw_input=f"{raw} ua={agent[:200]}" if agent else raw,
        classification=result.classification,
        risk_level=result.risk_level,
    )


def _basic_auth_credentials() -> tuple[str, str] | None:
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None
    username, _, password = decoded.partition(":")
    return username, password


def create_fake_http_app() -> Flask:
    fake_http = Flask("fake_iot_http")
    fake_http.config["MAX_CONTENT_LENGTH"] = settings.max_http_body_bytes
    fake_http.config["MAX_FORM_MEMORY_SIZE"] = settings.max_http_body_bytes

    @fake_http.before_request
    def capture_basic_auth():
        credentials = _basic_auth_credentials()
        if credentials is not None:
            username, password = credentials
            _log(
                "login_attempt",
                f"login_attempt basic_auth username={username} password={password} "
                f"path={request.path}",
            )

    @fake_http.route("/")
    def index():
        _log("http_request", _request_line())
        return _INDEX_PAGE

    @fake_http.route("/admin", methods=["GET", "POST"])
    @fake_http.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            _log(
                "login_attempt",
                f"login_attempt username={username} password={password} path={request.path}",
            )
            page = _LOGIN_PAGE.format(message='<p style="color:red;">Invalid credentials</p>')
            return Response(page, status=401, mimetype="text/html")

        _log("http_request", _request_line())
        return _LOGIN_PAGE.format(message="")

    @fake_http.route("/<path:any_path>", methods=_ALL_METHODS)
    def catch_all(any_path):
        raw = _request_line()
        body = request.get_data(cache=False, as_text=True)[:512] if request.method != "GET" else ""
        if body:
            raw = f"{raw} body={body}"
        _log("http_probe", raw)
        return Response("404 Not Found\n", status=404, mimetype="text/plain")

    @fake_http.errorhandler(413)
    def too_large(_error):
        _log("http_probe", f"{request.method} {request.path} oversized_body")
        return Response("413 Request Entity Too Large\n", status=413, mimetype="text/plain")

    @fake_http.errorhandler(405)
    def bad_method(_error):
        _log("http_probe", _request_line())
        return Response("405 Method Not Allowed\n", status=405, mimetype="text/plain")

    @fake_http.errorhandler(Exception)
    def unexpected(error):
        if isinstance(error, HTTPException):
            return Response(f"{error.code} {error.name}\n", status=error.code, mimetype="text/plain")
        fake_http.logger.exception("Fake HTTP handler failed")
        return Response("500 Internal Server Error\n", status=500, mimetype="text/plain")

    return fake_http
