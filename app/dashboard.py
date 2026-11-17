"""Operator dashboard and JSON API.

This is the only part of the project meant for you rather than attackers.
It displays attacker-controlled text, so: templates auto-escape everything,
a strict Content-Security-Policy forbids all scripts, and HTTP Basic auth is
enforced whenever a password is configured.
"""

from __future__ import annotations

import csv
import hmac
import io
import json
from urllib.parse import urlencode

from flask import Flask, Response, jsonify, render_template_string, request

from app import database
from app.config import settings

PAGE_SIZE = 50
MAX_API_LIMIT = 1000
FILTERS = ("service", "classification", "risk_level", "source_ip", "session_id")

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Adaptive IoT Honeypot</title>
  <style>
    :root { --bg:#f4f6fa; --card:#fff; --ink:#1c2330; --muted:#667085; --line:#e4e7ec;
            --accent:#2f6fed; --high:#c0392b; --medium:#b7791f; --low:#2e7d5b; }
    * { box-sizing: border-box; }
    body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 0;
           background: var(--bg); color: var(--ink); }
    main { max-width: 1200px; margin: 0 auto; padding: 24px 16px 48px; }
    h1 { font-size: 22px; margin: 0 0 16px; }
    h2 { font-size: 15px; margin: 0 0 12px; color: var(--muted); font-weight: 600; }
    .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); }
    .wide { grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); margin-top: 16px; }
    .card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 16px; }
    .stat { font-size: 28px; font-weight: 700; }
    .label { color: var(--muted); font-size: 13px; }
    .bar-row { display: grid; grid-template-columns: 190px 1fr 56px; gap: 8px; align-items: center;
               font-size: 13px; margin: 6px 0; }
    .bar-row a { color: inherit; text-decoration: none; overflow: hidden; text-overflow: ellipsis;
                 white-space: nowrap; }
    .bar-row a:hover { text-decoration: underline; }
    progress { width: 100%; height: 12px; accent-color: var(--accent); }
    .count { text-align: right; font-variant-numeric: tabular-nums; }
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { border-bottom: 1px solid var(--line); padding: 8px; text-align: left; vertical-align: top; }
    th { color: var(--muted); font-weight: 600; white-space: nowrap; }
    td.raw { font-family: ui-monospace, Menlo, Consolas, monospace; word-break: break-all;
             max-width: 460px; }
    .risk { font-weight: 600; text-transform: uppercase; font-size: 11px; }
    .risk-high { color: var(--high); } .risk-medium { color: var(--medium); }
    .risk-low { color: var(--low); }
    .toolbar { display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
               justify-content: space-between; margin-bottom: 12px; font-size: 13px; }
    .toolbar a, td a { color: var(--accent); text-decoration: none; }
    .chip { background: #e8effd; border-radius: 12px; padding: 2px 10px; margin-right: 6px; }
    .warn { background: #fff4e5; border: 1px solid #f5c26b; border-radius: 10px; padding: 12px 16px;
            margin-bottom: 16px; font-size: 14px; }
  </style>
</head>
<body>
<main>
  <h1>Adaptive IoT Honeypot</h1>

  {% if not auth_enabled %}
  <div class="warn">Dashboard authentication is off. Set <code>DASHBOARD_PASSWORD</code>
  before making this reachable from another machine.</div>
  {% endif %}

  <div class="grid">
    <div class="card"><div class="stat">{{ stats.total_events }}</div><div class="label">Events</div></div>
    <div class="card"><div class="stat">{{ stats.unique_source_ips }}</div><div class="label">Source IPs</div></div>
    <div class="card"><div class="stat">{{ stats.total_sessions }}</div><div class="label">Sessions</div></div>
    <div class="card"><div class="stat">{{ high_risk }}</div><div class="label">High-risk events</div></div>
  </div>

  <div class="grid wide">
    {% for title, field, items in charts %}
    <div class="card">
      <h2>{{ title }}</h2>
      {% for item in items %}
      <div class="bar-row">
        <a href="?{{ field }}={{ item[field] | urlencode }}" title="{{ item[field] }}">{{ item[field] }}</a>
        <progress max="{{ stats.total_events or 1 }}" value="{{ item.count }}"></progress>
        <span class="count">{{ item.count }}</span>
      </div>
      {% else %}
      <div class="label">No data yet.</div>
      {% endfor %}
    </div>
    {% endfor %}
  </div>

  <div class="card" style="margin-top:16px">
    <div class="toolbar">
      <div>
        <strong>Events</strong>
        {% for key, value in active_filters.items() %}
          <span class="chip">{{ key }}: {{ value }}</span>
        {% endfor %}
        {% if active_filters %}<a href="?">clear filters</a>{% endif %}
      </div>
      <div>
        <a href="/api/export?format=csv">Export CSV</a> &middot;
        <a href="/api/export?format=json">Export JSON</a>
      </div>
    </div>
    <div class="table-wrap">
    <table>
      <tr><th>Time (UTC)</th><th>Source</th><th>Service</th><th>Event</th>
          <th>Classification</th><th>Risk</th><th>Session</th><th>Input</th></tr>
      {% for event in events %}
      <tr>
        <td style="white-space:nowrap">{{ event.timestamp }}</td>
        <td><a href="?source_ip={{ event.source_ip | urlencode }}">{{ event.source_ip }}</a></td>
        <td>{{ event.service }}</td>
        <td>{{ event.event_type }}</td>
        <td>{{ event.classification }}</td>
        <td><span class="risk risk-{{ event.risk_level }}">{{ event.risk_level }}</span></td>
        <td>{% if event.session_id %}<a href="?session_id={{ event.session_id | urlencode }}">{{ event.session_id[:8] }}</a>{% endif %}</td>
        <td class="raw">{{ event.raw_input }}</td>
      </tr>
      {% else %}
      <tr><td colspan="8" class="label">No events match.</td></tr>
      {% endfor %}
    </table>
    </div>
    <div class="toolbar" style="margin:12px 0 0">
      <span class="label">Page {{ page }}</span>
      <span>
        {% if page > 1 %}<a href="?{{ page_query(page - 1) }}">&larr; Newer</a>{% endif %}
        {% if has_next %}&nbsp; <a href="?{{ page_query(page + 1) }}">Older &rarr;</a>{% endif %}
      </span>
    </div>
  </div>
</main>
</body>
</html>
"""


def _int_arg(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def _active_filters() -> dict[str, str]:
    return {key: request.args[key][:128] for key in FILTERS if request.args.get(key)}


def create_dashboard_app() -> Flask:
    app = Flask("honeypot_dashboard")

    @app.before_request
    def require_auth():
        if request.path == "/healthz" or not settings.dashboard_auth_enabled:
            return None
        auth = request.authorization
        if (
            auth is not None
            and auth.type == "basic"
            and hmac.compare_digest(
                (auth.username or "").encode(), settings.dashboard_username.encode()
            )
            and hmac.compare_digest(
                (auth.password or "").encode(), settings.dashboard_password.encode()
            )
        ):
            return None
        return Response(
            "Authentication required.\n",
            status=401,
            mimetype="text/plain",
            headers={"WWW-Authenticate": 'Basic realm="Honeypot dashboard"'},
        )

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/")
    def home():
        filters = _active_filters()
        page = _int_arg("page", 1, 1, 100000)
        events = database.get_events(
            limit=PAGE_SIZE + 1, offset=(page - 1) * PAGE_SIZE, **filters
        )
        stats = database.get_stats()

        def page_query(number: int) -> str:
            return urlencode({**filters, "page": number})

        high_risk = next(
            (item["count"] for item in stats["by_risk"] if item["risk_level"] == "high"), 0
        )
        charts = [
            ("By classification", "classification", stats["by_classification"]),
            ("By service", "service", stats["by_service"]),
            ("Top source IPs", "source_ip", stats["top_source_ips"]),
        ]
        return render_template_string(
            _TEMPLATE,
            stats=stats,
            charts=charts,
            high_risk=high_risk,
            events=events[:PAGE_SIZE],
            has_next=len(events) > PAGE_SIZE,
            page=page,
            page_query=page_query,
            active_filters=filters,
            auth_enabled=settings.dashboard_auth_enabled,
        )

    @app.route("/api/events")
    def api_events():
        return jsonify(
            database.get_events(
                limit=_int_arg("limit", 100, 1, MAX_API_LIMIT),
                offset=_int_arg("offset", 0, 0, 10**9),
                **_active_filters(),
            )
        )

    @app.route("/api/stats")
    def api_stats():
        return jsonify(database.get_stats())

    @app.route("/api/export")
    def api_export():
        export_format = request.args.get("format", "json").lower()

        if export_format == "json":

            def generate_json():
                yield "["
                for index, event in enumerate(database.iter_events()):
                    yield ("," if index else "") + "\n  " + json.dumps(event)
                yield "\n]\n"

            return Response(
                generate_json(),
                mimetype="application/json",
                headers={"Content-Disposition": "attachment; filename=honeypot_events.json"},
            )

        if export_format == "csv":

            def generate_csv():
                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=database.EVENT_FIELDS)
                writer.writeheader()
                for event in database.iter_events():
                    row = {}
                    for field in database.EVENT_FIELDS:
                        value = event.get(field)
                        value = "" if value is None else value
                        # Neutralise spreadsheet formula injection.
                        if isinstance(value, str) and value[:1] in ("=", "+", "-", "@"):
                            value = "'" + value
                        row[field] = value
                    writer.writerow(row)
                    yield output.getvalue()
                    output.seek(0)
                    output.truncate(0)
                yield output.getvalue()

            return Response(
                generate_csv(),
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=honeypot_events.csv"},
            )

        return Response(
            "Unsupported export format. Use format=csv or format=json.\n",
            status=400,
            mimetype="text/plain",
        )

    @app.route("/healthz")
    def healthz():
        healthy = database.ping()
        return jsonify({"status": "ok" if healthy else "degraded"}), 200 if healthy else 503

    return app
