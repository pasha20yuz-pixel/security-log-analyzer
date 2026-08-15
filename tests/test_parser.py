from datetime import UTC, datetime

import pytest

from seclog.parser import LogEvent, parse_log_line


def test_parse_valid_log_line():
    line = "2026-08-13 10:15:21 LOGIN_FAILED user=admin ip=192.168.1.10"

    event = parse_log_line(line)

    assert event == LogEvent(
        timestamp=datetime(2026, 8, 13, 10, 15, 21, tzinfo=UTC,),
        event_type="LOGIN_FAILED",
        username="admin",
        ip_address="192.168.1.10",
    )


def test_parse_invalid_log_line():
    line = "invalid log line"

    with pytest.raises(ValueError):
        parse_log_line(line)


def test_parse_empty_username():
    line = "2026-08-13 10:15:21 LOGIN_FAILED user= ip=192.168.1.10"

    with pytest.raises(ValueError):
        parse_log_line(line)


def test_parse_invalid_ip():
    line = "2026-08-13 10:15:21 LOGIN_FAILED user=admin ip=not-an-ip"

    with pytest.raises(ValueError):
        parse_log_line(line)


def test_parse_invalid_timestamp():
    line = "2026-99-99 10:15:21 LOGIN_FAILED user=admin ip=192.168.1.10"

    with pytest.raises(ValueError):
        parse_log_line(line)
