import json

from seclog.cli import load_events, alert_to_dict, build_parser
from seclog.analyzer import SecurityAlert


def test_alert_to_dict():
    alert = SecurityAlert(
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        username="admin",
        ip_address="192.168.1.10",
        failed_attempts=3,
    )

    result = alert_to_dict(alert)

    assert result == {
        "alert_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "username": "admin",
        "ip_address": "192.168.1.10",
        "failed_attempts": 3,
    }


def test_cli_default_arguments():
    parser = build_parser()

    args = parser.parse_args(["examples/auth.log"])

    assert args.threshold == 3
    assert args.window == 60
    assert args.format == "text"


def test_cli_custom_arguments():
    parser = build_parser()

    args = parser.parse_args(
        [
            "examples/auth.log",
            "--threshold",
            "5",
            "--window",
            "120",
            "--format",
            "json",
        ]
    )

    assert args.threshold == 5
    assert args.window == 120
    assert args.format == "json"


def test_load_events(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "2026-08-13 10:15:21 "
        "LOGIN_FAILED user=admin ip=192.168.1.10\n",
        encoding="utf-8",
    )

    events = load_events(log_file)

    assert len(events) == 1
    assert events[0].username == "admin"
    assert events[0].ip_address == "192.168.1.10"