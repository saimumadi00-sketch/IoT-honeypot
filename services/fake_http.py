from flask import Flask, request, Response

from analyzer.classifier import classify_input
from app.database import log_event


def create_fake_http_app() -> Flask:
    fake_http = Flask("fake_iot_http")

    @fake_http.route("/")
    def index():
        source_ip = request.remote_addr or "unknown"
        raw = f"GET {request.path}"
        result = classify_input(raw, service="http")

        log_event(
            source_ip=source_ip,
            service="http",
            event_type="http_request",
            raw_input=raw,
            classification=result.classification,
            risk_level=result.risk_level,
        )

        return """
        <html>
          <head><title>IoT-CAM-3000</title></head>
          <body>
            <h2>IoT-CAM-3000</h2>
            <p>Firmware Version: 1.0.7</p>
            <p>Status: Online</p>
            <a href="/login">Admin Login</a>
          </body>
        </html>
        """

    @fake_http.route("/admin")
    @fake_http.route("/login", methods=["GET", "POST"])
    def login():
        source_ip = request.remote_addr or "unknown"

        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            raw = f"{username}:{password} password={password}"
            event_type = "login_attempt"
        else:
            raw = f"GET {request.path}"
            event_type = "http_request"

        result = classify_input(raw, service="http")

        log_event(
            source_ip=source_ip,
            service="http",
            event_type=event_type,
            raw_input=raw,
            classification=result.classification,
            risk_level=result.risk_level,
        )

        return """
        <html>
          <head><title>RouterOS Admin Login</title></head>
          <body>
            <h2>RouterOS Admin Panel</h2>
            <form method="POST" action="/login">
              <label>Username:</label><br>
              <input name="username"><br><br>
              <label>Password:</label><br>
              <input name="password" type="password"><br><br>
              <button type="submit">Login</button>
            </form>
            <p style="color:red;">Invalid credentials</p>
          </body>
        </html>
        """

    @fake_http.route("/<path:any_path>", methods=["GET", "POST"])
    def catch_all(any_path):
        source_ip = request.remote_addr or "unknown"
        raw = f"{request.method} /{any_path}"
        result = classify_input(raw, service="http")

        log_event(
            source_ip=source_ip,
            service="http",
            event_type="http_probe",
            raw_input=raw,
            classification=result.classification,
            risk_level=result.risk_level,
        )

        return Response("404 Not Found\n", status=404, mimetype="text/plain")

    return fake_http
