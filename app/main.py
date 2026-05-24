import sys
import threading
from pathlib import Path
from flask import Flask, jsonify

# Allow running with: python app/main.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.config import (
    DASHBOARD_HOST,
    DASHBOARD_PORT,
    FAKE_HTTP_HOST,
    FAKE_HTTP_PORT,
    FAKE_SHELL_HOST,
    FAKE_SHELL_PORT,
)
from app.database import init_db, get_events, get_stats
from services.fake_http import create_fake_http_app
from services.fake_shell import start_fake_shell


dashboard = Flask("honeypot_dashboard")


@dashboard.route("/")
def home():
    stats = get_stats()
    events = get_events(limit=30)

    rows = ""
    for event in events:
        rows += f"""
        <tr>
          <td>{event['timestamp']}</td>
          <td>{event['source_ip']}</td>
          <td>{event['service']}</td>
          <td>{event['event_type']}</td>
          <td>{event['classification']}</td>
          <td>{event['risk_level']}</td>
          <td><code>{event['raw_input']}</code></td>
        </tr>
        """

    return f"""
    <html>
      <head>
        <title>Adaptive IoT Honeypot Dashboard</title>
        <style>
          body {{
            font-family: Arial, sans-serif;
            margin: 30px;
            background: #f5f7fb;
          }}
          .card {{
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
          }}
          table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
          }}
          th, td {{
            border-bottom: 1px solid #ddd;
            padding: 8px;
            text-align: left;
            font-size: 14px;
          }}
          th {{
            background: #222;
            color: white;
          }}
          code {{
            background: #eee;
            padding: 2px 5px;
            border-radius: 4px;
          }}
        </style>
      </head>
      <body>
        <h1>Adaptive IoT Honeypot Dashboard</h1>

        <div class="card">
          <h2>Summary</h2>
          <p><strong>Total events:</strong> {stats['total_events']}</p>
          <p><strong>Fake HTTP panel:</strong> http://127.0.0.1:{FAKE_HTTP_PORT}</p>
          <p><strong>Fake shell:</strong> nc 127.0.0.1 {FAKE_SHELL_PORT}</p>
        </div>

        <div class="card">
          <h2>Recent Events</h2>
          <table>
            <tr>
              <th>Time</th>
              <th>Source IP</th>
              <th>Service</th>
              <th>Event</th>
              <th>Classification</th>
              <th>Risk</th>
              <th>Raw Input</th>
            </tr>
            {rows}
          </table>
        </div>
      </body>
    </html>
    """


@dashboard.route("/api/events")
def api_events():
    return jsonify(get_events(limit=100))


@dashboard.route("/api/stats")
def api_stats():
    return jsonify(get_stats())


def run_fake_http():
    fake_http = create_fake_http_app()
    fake_http.run(
        host=FAKE_HTTP_HOST,
        port=FAKE_HTTP_PORT,
        debug=False,
        use_reloader=False,
    )


def run_dashboard():
    dashboard.run(
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        debug=False,
        use_reloader=False,
    )


def main():
    init_db()

    print("[+] Starting Adaptive IoT Honeypot Starter")

    threads = [
        threading.Thread(target=start_fake_shell, args=(FAKE_SHELL_HOST, FAKE_SHELL_PORT), daemon=True),
        threading.Thread(target=run_fake_http, daemon=True),
        threading.Thread(target=run_dashboard, daemon=True),
    ]

    for thread in threads:
        thread.start()

    print(f"[+] Dashboard: http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    print(f"[+] Fake HTTP IoT Admin: http://{FAKE_HTTP_HOST}:{FAKE_HTTP_PORT}")
    print(f"[+] Fake IoT Shell: nc {FAKE_SHELL_HOST} {FAKE_SHELL_PORT}")
    print("[+] Press CTRL+C to stop.")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[+] Honeypot stopped.")


if __name__ == "__main__":
    main()
