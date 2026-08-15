from datetime import UTC, datetime, timedelta

from seclog.analyzer import (
    SecurityAlert,
    analyze,
    detect_account_enumeration,
    detect_brute_force,
    detect_password_spraying,
    detect_suspicious_success,
)
from seclog.parser import LogEvent


def test_detect_brute_force():
    start = datetime(2026, 8, 13, 10, 15, 21, tzinfo=UTC)

    events = [
        LogEvent(
            timestamp=start,
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=2),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=4),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
    ]

    alerts = detect_brute_force(events)

    assert alerts == [
        SecurityAlert(
            alert_type="BRUTE_FORCE",
            severity="HIGH",
            username="admin",
            ip_address="192.168.1.10",
            failed_attempts=3,
            timestamp=start + timedelta(seconds=4),
        )
    ]


def test_success_resets_failed_attempts():
    start = datetime(2026, 8, 13, 10, 15, 21, tzinfo=UTC)

    events = [
        LogEvent(
            timestamp=start,
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=2),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=4),
            event_type="LOGIN_SUCCESS",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=6),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
    ]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_different_users_are_tracked_separately():
    start = datetime(2026, 8, 13, 10, 15, 21, tzinfo=UTC)

    events = [
        LogEvent(
            timestamp=start,
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=1),
            event_type="LOGIN_FAILED",
            username="root",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=2),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=3),
            event_type="LOGIN_FAILED",
            username="root",
            ip_address="192.168.1.10",
        ),
    ]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_old_failed_attempts_do_not_trigger_brute_force():
    start = datetime(2026, 8, 13, 10, 15, 21, tzinfo=UTC)

    events = [
        LogEvent(
            timestamp=start,
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=30),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=61),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
    ]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_custom_threshold():
    start = datetime(2026, 8, 13, 10, 15, 21, tzinfo=UTC)

    events = [
        LogEvent(
            timestamp=start,
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=5),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=10),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=15),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
    ]

    alerts = detect_brute_force(
        events,
        threshold=4,
        window_seconds=60,
    )

    assert len(alerts) == 1
    assert alerts[0].failed_attempts == 4


def test_detect_password_spraying():
    start = datetime(2026, 8, 13, 10, 15, 21, tzinfo=UTC)

    events = [
        LogEvent(
            timestamp=start,
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="10.0.0.5",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=5),
            event_type="LOGIN_FAILED",
            username="root",
            ip_address="10.0.0.5",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=10),
            event_type="LOGIN_FAILED",
            username="test",
            ip_address="10.0.0.5",
        ),
    ]

    alerts = detect_password_spraying(events)

    assert alerts == [
        SecurityAlert(
            alert_type="PASSWORD_SPRAYING",
            severity="HIGH",
            username="*",
            ip_address="10.0.0.5",
            failed_attempts=3,
            timestamp=start + timedelta(seconds=10),
        )
    ]


def test_same_user_does_not_trigger_password_spraying():
    start = datetime(2026, 8, 13, 10, 15, 21, tzinfo=UTC)

    events = [
        LogEvent(
            timestamp=start,
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="10.0.0.5",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=5),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="10.0.0.5",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=10),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="10.0.0.5",
        ),
    ]

    alerts = detect_password_spraying(events)

    assert alerts == []


def test_password_spraying_different_ips_are_tracked_separately():
    start = datetime(2026, 8, 13, 10, 15, 21, tzinfo=UTC)

    events = [
        LogEvent(
            timestamp=start,
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="10.0.0.5",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=1),
            event_type="LOGIN_FAILED",
            username="root",
            ip_address="10.0.0.5",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=2),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="10.0.0.6",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=3),
            event_type="LOGIN_FAILED",
            username="root",
            ip_address="10.0.0.6",
        ),
    ]

    alerts = detect_password_spraying(events)

    assert alerts == []


def test_analyze_runs_all_detectors():
    start = datetime(2026, 8, 13, 10, 15, 21, tzinfo=UTC)

    events = [
        # Brute force against admin
        LogEvent(
            timestamp=start,
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=2),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=4),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        # Password spraying from another IP
        LogEvent(
            timestamp=start,
            event_type="LOGIN_FAILED",
            username="root",
            ip_address="10.0.0.5",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=2),
            event_type="LOGIN_FAILED",
            username="test",
            ip_address="10.0.0.5",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=4),
            event_type="LOGIN_FAILED",
            username="guest",
            ip_address="10.0.0.5",
        ),
    ]

    alerts = analyze(events)

    assert len(alerts) == 2

    alert_types = {alert.alert_type for alert in alerts}

    assert alert_types == {
        "BRUTE_FORCE",
        "PASSWORD_SPRAYING",
    }


def test_detect_account_enumeration():
    events = [
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 0, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="10.0.0.50",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 10, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="root",
            ip_address="10.0.0.50",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 20, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="guest",
            ip_address="10.0.0.50",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 30, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="test",
            ip_address="10.0.0.50",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 40, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="backup",
            ip_address="10.0.0.50",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 50, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="service",
            ip_address="10.0.0.50",
        ),
    ]

    alerts = detect_account_enumeration(
        events,
        threshold=3,
        window_seconds=60,
    )

    assert len(alerts) == 1
    assert alerts[0].alert_type == "ACCOUNT_ENUMERATION"
    assert alerts[0].severity == "HIGH"
    assert alerts[0].username == "*"
    assert alerts[0].ip_address == "10.0.0.50"
    assert alerts[0].failed_attempts == 6


def test_detect_suspicious_success():
    events = [
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 0, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 10, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 20, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 30, tzinfo=UTC),
            event_type="LOGIN_SUCCESS",
            username="admin",
            ip_address="192.168.1.10",
        ),
    ]

    alerts = detect_suspicious_success(
        events,
        threshold=3,
        window_seconds=60,
    )

    assert len(alerts) == 1
    assert alerts[0].alert_type == "SUSPICIOUS_SUCCESS"
    assert alerts[0].severity == "HIGH"
    assert alerts[0].username == "admin"
    assert alerts[0].ip_address == "192.168.1.10"
    assert alerts[0].failed_attempts == 3


def test_suspicious_success_ignores_old_failed_attempts():
    events = [
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 0, 0, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 0, 10, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 0, 20, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 2, 0, tzinfo=UTC),
            event_type="LOGIN_SUCCESS",
            username="admin",
            ip_address="192.168.1.10",
        ),
    ]

    alerts = detect_suspicious_success(
        events,
        threshold=3,
        window_seconds=60,
    )

    assert alerts == []


def test_suspicious_success_isolated_between_users():
    events = [
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 0, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 5, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 10, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 15, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="root",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 20, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="root",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 25, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="root",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 30, tzinfo=UTC),
            event_type="LOGIN_SUCCESS",
            username="admin",
            ip_address="192.168.1.10",
        ),
    ]

    alerts = detect_suspicious_success(
        events,
        threshold=3,
        window_seconds=60,
    )

    assert len(alerts) == 1
    assert alerts[0].alert_type == "SUSPICIOUS_SUCCESS"
    assert alerts[0].username == "admin"
    assert alerts[0].ip_address == "192.168.1.10"
    assert alerts[0].failed_attempts == 3


def test_suspicious_success_isolated_between_ips():
    events = [
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 0, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 5, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 10, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 15, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="10.0.0.5",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 20, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="10.0.0.5",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 25, tzinfo=UTC),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="10.0.0.5",
        ),
        LogEvent(
            timestamp=datetime(2026, 8, 13, 10, 15, 30, tzinfo=UTC),
            event_type="LOGIN_SUCCESS",
            username="admin",
            ip_address="192.168.1.10",
        ),
    ]

    alerts = detect_suspicious_success(
        events,
        threshold=3,
        window_seconds=60,
    )

    assert len(alerts) == 1
    assert alerts[0].alert_type == "SUSPICIOUS_SUCCESS"
    assert alerts[0].username == "admin"
    assert alerts[0].ip_address == "192.168.1.10"
    assert alerts[0].failed_attempts == 3


def test_account_enumeration_state_resets_after_success():
    start = datetime(2026, 8, 13, 10, 30, 0, tzinfo=UTC)

    events = [
        LogEvent(
            timestamp=start,
            event_type="LOGIN_FAILED",
            username="user1",
            ip_address="10.0.0.50",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=1),
            event_type="LOGIN_FAILED",
            username="user2",
            ip_address="10.0.0.50",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=2),
            event_type="LOGIN_FAILED",
            username="user3",
            ip_address="10.0.0.50",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=3),
            event_type="LOGIN_FAILED",
            username="user4",
            ip_address="10.0.0.50",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=4),
            event_type="LOGIN_FAILED",
            username="user5",
            ip_address="10.0.0.50",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=5),
            event_type="LOGIN_SUCCESS",
            username="user5",
            ip_address="10.0.0.50",
        ),
    ]

    alerts = detect_account_enumeration(events)

    assert alerts == []


def test_suspicious_success_not_triggered_below_threshold():
    start = datetime(2026, 8, 13, 10, 40, 0, tzinfo=UTC)

    events = [
        LogEvent(
            timestamp=start,
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=2),
            event_type="LOGIN_FAILED",
            username="admin",
            ip_address="192.168.1.10",
        ),
        LogEvent(
            timestamp=start + timedelta(seconds=4),
            event_type="LOGIN_SUCCESS",
            username="admin",
            ip_address="192.168.1.10",
        ),
    ]

    alerts = detect_suspicious_success(events)

    assert alerts == []
