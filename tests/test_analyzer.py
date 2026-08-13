from datetime import datetime, timedelta

from seclog.analyzer import SecurityAlert, detect_brute_force
from seclog.parser import LogEvent


def test_detect_brute_force():
    start = datetime(2026, 8, 13, 10, 15, 21)

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
        )
    ]


def test_success_resets_failed_attempts():
    start = datetime(2026, 8, 13, 10, 15, 21)

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
    start = datetime(2026, 8, 13, 10, 15, 21)

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