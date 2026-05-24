import csv
import io
import json
import sys
import threading
from html import escape
from pathlib import Path
from flask import Flask, Response, jsonify, request

# Allow running with: python app/main.py
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.config import (
    DASHBOARD_HOST,
    DASHBOARD_PORT,
    FAKE_HTTP_HOST,
    FAKE_HTTP_PORT,
    FAKE_MQTT_HOST,
    FAKE_MQTT_PORT,
    FAKE_SHELL_HOST,
    FAKE_SHELL_PORT,
    FAKE_TELNET_HOST,
    FAKE_TELNET_PORT,
)
from app.database import init_db, get_events, get_stats
from services.fake_http import create_fake_http_app
from services.fake_mqtt import start_fake_mqtt
from services.fake_shell import start_fake_shell
from services.fake_telnet import start_fake_telnet


dashboard = Flask("honeypot_dashboard")


@dashboard.route("/")
def home():
    stats = get_stats()
    events = get_events(limit=30)
    chart_data = {
        "classifications": {
            "labels": [item["classification"] for item in stats["by_classification"]],
            "counts": [item["count"] for item in stats["by_classification"]],
        },
        "services": {
            "labels": [item["service"] for item in stats["by_service"]],
            "counts": [item["count"] for item in stats["by_service"]],
        },
    }
    chart_data_json = json.dumps(chart_data)

    rows = ""
    for event in events:
        rows += f"""
        <tr>
          <td>{escape(str(event['timestamp']))}</td>
          <td>{escape(str(event['source_ip']))}</td>
          <td>{escape(str(event['service']))}</td>
          <td>{escape(str(event['event_type']))}</td>
          <td>{escape(str(event['classification']))}</td>
          <td>{escape(str(event['risk_level']))}</td>
          <td><code>{escape(str(event['raw_input']))}</code></td>
        </tr>
        """

    chart_script = """
        <script>
          const chartData = CHART_DATA_JSON;

          new Chart(document.getElementById("classificationChart"), {
            type: "bar",
            data: {
              labels: chartData.classifications.labels,
              datasets: [{
                label: "Events",
                data: chartData.classifications.counts,
                backgroundColor: "#2f80ed"
              }]
            },
            options: {
              responsive: true,
              plugins: {
                legend: {
                  display: false
                }
              },
              scales: {
                y: {
                  beginAtZero: true,
                  ticks: {
                    precision: 0
                  }
                }
              }
            }
          });

          new Chart(document.getElementById("serviceChart"), {
            type: "bar",
            data: {
              labels: chartData.services.labels,
              datasets: [{
                label: "Events",
                data: chartData.services.counts,
                backgroundColor: "#27ae60"
              }]
            },
            options: {
              responsive: true,
              plugins: {
                legend: {
                  display: false
                }
              },
              scales: {
                y: {
                  beginAtZero: true,
                  ticks: {
                    precision: 0
                  }
                }
              }
            }
          });
        </script>
    """.replace("CHART_DATA_JSON", chart_data_json)

    return f"""
    <html>
      <head>
        <title>Adaptive IoT Honeypot Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
          .charts {{
            display: grid;
            gap: 20px;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
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
          <p><strong>Fake MQTT:</strong> 127.0.0.1:{FAKE_MQTT_PORT}</p>
          <p><strong>Fake Telnet:</strong> telnet 127.0.0.1 {FAKE_TELNET_PORT}</p>
        </div>

        <div class="card">
          <h2>Charts</h2>
          <div class="charts">
            <div>
              <h3>Events by Classification</h3>
              <canvas id="classificationChart"></canvas>
            </div>
            <div>
              <h3>Events by Service</h3>
              <canvas id="serviceChart"></canvas>
            </div>
          </div>
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
        {chart_script}
      </body>
    </html>
    """


@dashboard.route("/api/events")
def api_events():
    return jsonify(get_events(limit=100))


@dashboard.route("/api/stats")
def api_stats():
    return jsonify(get_stats())


@dashboard.route("/api/export")
def api_export():
    export_format = request.args.get("format", "json").lower()
    events = get_events(limit=-1)

    if export_format == "json":
        return Response(
            json.dumps(events, indent=2),
            mimetype="application/json",
        )

    if export_format == "csv":
        fieldnames = [
            "id",
            "timestamp",
            "source_ip",
            "service",
            "event_type",
            "raw_input",
            "classification",
            "risk_level",
        ]

        def generate_csv():
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

            for event in events:
                writer.writerow({field: event.get(field, "") for field in fieldnames})
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)

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
        threading.Thread(target=start_fake_mqtt, args=(FAKE_MQTT_HOST, FAKE_MQTT_PORT), daemon=True),
        threading.Thread(target=start_fake_telnet, args=(FAKE_TELNET_HOST, FAKE_TELNET_PORT), daemon=True),
        threading.Thread(target=run_fake_http, daemon=True),
        threading.Thread(target=run_dashboard, daemon=True),
    ]

    for thread in threads:
        thread.start()

    print(f"[+] Dashboard: http://{DASHBOARD_HOST}:{DASHBOARD_PORT}")
    print(f"[+] Fake HTTP IoT Admin: http://{FAKE_HTTP_HOST}:{FAKE_HTTP_PORT}")
    print(f"[+] Fake IoT Shell: nc {FAKE_SHELL_HOST} {FAKE_SHELL_PORT}")
    print(f"[+] Fake MQTT: {FAKE_MQTT_HOST}:{FAKE_MQTT_PORT}")
    print(f"[+] Fake Telnet: telnet {FAKE_TELNET_HOST} {FAKE_TELNET_PORT}")
    print("[+] Press CTRL+C to stop.")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[+] Honeypot stopped.")


if __name__ == "__main__":
    main()
