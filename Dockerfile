FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HONEYPOT_DATA_DIR=/data \
    HONEYPOT_LOG_DIR=/data/logs \
    DASHBOARD_HOST=0.0.0.0 \
    FAKE_HTTP_HOST=0.0.0.0 \
    FAKE_SHELL_HOST=0.0.0.0 \
    FAKE_MQTT_HOST=0.0.0.0 \
    FAKE_TELNET_HOST=0.0.0.0

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer ./analyzer
COPY app ./app
COPY services ./services

# Never run a honeypot as root.
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin honeypot \
    && mkdir -p /data/logs \
    && chown -R honeypot:honeypot /data
USER honeypot

VOLUME ["/data"]
EXPOSE 5000 8080 2222 1883 2323

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=3).status == 200 else 1)"]

CMD ["python", "-m", "app.main"]
