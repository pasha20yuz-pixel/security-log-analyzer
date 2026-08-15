import json
import pytest
from datetime import datetime

from seclog.cli import load_events, alert_to_dict, build_parser, main
from seclog.analyzer import SecurityAlert


def test_alert_to_dict():
    alert = SecurityAlert(
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        username="admin",
        ip_address="192.168.1.10",
        failed_attempts=3,
        timestamp=datetime(2026, 8, 13, 10, 15, 21),
    )

    result = alert_to_dict(alert)

    assert result == {
        "alert_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "username": "admin",
        "ip_address": "192.168.1.10",
        "failed_attempts": 3,
        "timestamp": "2026-08-13T10:15:21",
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

def test_load_events_skips_invalid_lines(tmp_path, capsys):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "invalid log line\n"
        "2026-08-13 10:15:21 "
        "LOGIN_FAILED user=admin ip=192.168.1.10\n",
        encoding="utf-8",
    )

    events = load_events(log_file)

    assert len(events) == 1
    assert events[0].username == "admin"

    captured = capsys.readouterr()

    assert "Warning: line 1:" in captured.out

def test_main_text_output(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "seclog",
            "examples/auth.log",
        ],
    )

    main()

    captured = capsys.readouterr()

    assert "Security Log Analyzer" in captured.out
    assert "Events analyzed: 17" in captured.out
    assert "Alerts detected: 6" in captured.out
    assert "[HIGH] BRUTE_FORCE" in captured.out

def test_main_json_output(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "seclog",
            "examples/auth.log",
            "--format",
            "json",
        ],
    )

    main()

    captured = capsys.readouterr()
    result = json.loads(captured.out)

    assert result["events_analyzed"] == 17
    assert result["alerts_detected"] == 6
    assert len(result["alerts"]) == 6

    assert result["alerts"][0]["alert_type"] == "BRUTE_FORCE"
    assert "timestamp" in result["alerts"][0]

def test_main_custom_detection_parameters(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "seclog",
            "examples/auth.log",
            "--threshold",
            "5",
            "--window",
            "120",
        ],
    )

    main()

    captured = capsys.readouterr()

    assert "Events analyzed: 17" in captured.out
    assert "Alerts detected: 0" in captured.out

def test_main_rejects_invalid_threshold(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "seclog",
            "examples/auth.log",
            "--threshold",
            "0",
        ],
    )

    with pytest.raises(SystemExit):
        main()

def test_main_rejects_invalid_window(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "seclog",
            "examples/auth.log",
            "--window",
            "0",
        ],
    )

    with pytest.raises(SystemExit):
        main()    