from dataclasses import dataclass


@dataclass
class ClassificationResult:
    classification: str
    risk_level: str


def classify_input(raw_input: str, service: str = "unknown") -> ClassificationResult:
    """
    Rule-based attack classifier.

    This is intentionally simple for the starter version.
    Later you can replace or combine it with ML.
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
