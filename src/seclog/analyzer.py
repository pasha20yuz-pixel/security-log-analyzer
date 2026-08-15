from dataclasses import dataclass
from datetime import timedelta

from .parser import LogEvent


@dataclass(frozen=True)
class SecurityAlert:
    alert_type: str
    severity: str
    username: str
    ip_address: str
    failed_attempts: int


def detect_brute_force(
    events: list[LogEvent],
    threshold: int = 3,
    window_seconds: int = 60,
) -> list[SecurityAlert]:
    alerts = []

    failed_attempts: dict[tuple[str, str], list[LogEvent]] = {}

    for event in events:
        key = (event.username, event.ip_address)

        if event.event_type == "LOGIN_FAILED":
            attempts = failed_attempts.setdefault(key, [])

            attempts.append(event)

            window_start = event.timestamp - timedelta(
                seconds=window_seconds
            )

            attempts[:] = [
                attempt
                for attempt in attempts
                if attempt.timestamp >= window_start
            ]

            if len(attempts) == threshold:
                alerts.append(
                    SecurityAlert(
                        alert_type="BRUTE_FORCE",
                        severity="HIGH",
                        username=event.username,
                        ip_address=event.ip_address,
                        failed_attempts=len(attempts),
                    )
                )

        elif event.event_type == "LOGIN_SUCCESS":
            failed_attempts[key] = []

    return alerts

def detect_password_spraying(
    events: list[LogEvent],
    threshold: int = 3,
    window_seconds: int = 60,
) -> list[SecurityAlert]:
    alerts = []

    failed_users: dict[str, list[LogEvent]] = {}

    for event in events:
        ip_address = event.ip_address

        if event.event_type == "LOGIN_FAILED":
            attempts = failed_users.setdefault(ip_address, [])
            attempts.append(event)

            window_start = event.timestamp - timedelta(
                seconds=window_seconds
            )

            attempts[:] = [
                attempt
                for attempt in attempts
                if attempt.timestamp >= window_start
            ]

            unique_users = {
                attempt.username
                for attempt in attempts
            }

            if len(unique_users) == threshold:
                alerts.append(
                    SecurityAlert(
                        alert_type="PASSWORD_SPRAYING",
                        severity="HIGH",
                        username="*",
                        ip_address=ip_address,
                        failed_attempts=len(attempts),
                    )
                )

        elif event.event_type == "LOGIN_SUCCESS":
            failed_users[ip_address] = []

    return alerts

def detect_account_enumeration(
    events: list[LogEvent],
    threshold: int = 3,
    window_seconds: int = 60,
) -> list[SecurityAlert]:
    alerts = []

    enumeration_threshold = threshold * 2

    failed_users: dict[str, list[LogEvent]] = {}

    for event in events:
        ip_address = event.ip_address

        if event.event_type == "LOGIN_FAILED":
            attempts = failed_users.setdefault(ip_address, [])
            attempts.append(event)

            window_start = event.timestamp - timedelta(
                seconds=window_seconds
            )

            attempts[:] = [
                attempt
                for attempt in attempts
                if attempt.timestamp >= window_start
            ]

            unique_users = {
                attempt.username
                for attempt in attempts
            }

            if len(unique_users) >= enumeration_threshold:
                alerts.append(
                    SecurityAlert(
                        alert_type="ACCOUNT_ENUMERATION",
                        severity="HIGH",
                        username="*",
                        ip_address=ip_address,
                        failed_attempts=len(attempts),
                    )
                )

                failed_users[ip_address] = []

        elif event.event_type == "LOGIN_SUCCESS":
            failed_users[ip_address] = []

    return alerts

def detect_suspicious_success(
    events: list[LogEvent],
    threshold: int = 3,
    window_seconds: int = 60,
) -> list[SecurityAlert]:
    alerts = []

    failed_attempts: dict[tuple[str, str], list[LogEvent]] = {}

    for event in events:
        key = (event.username, event.ip_address)

        if event.event_type == "LOGIN_FAILED":
            attempts = failed_attempts.setdefault(key, [])
            attempts.append(event)

            window_start = event.timestamp - timedelta(
                seconds=window_seconds
            )

            attempts[:] = [
                attempt
                for attempt in attempts
                if attempt.timestamp >= window_start
            ]

        elif event.event_type == "LOGIN_SUCCESS":
            attempts = failed_attempts.get(key, [])

            window_start = event.timestamp - timedelta(
                seconds=window_seconds
            )

            recent_attempts = [
                attempt
                for attempt in attempts
                if attempt.timestamp >= window_start
            ]

            if len(recent_attempts) >= threshold:
                alerts.append(
                    SecurityAlert(
                        alert_type="SUSPICIOUS_SUCCESS",
                        severity="HIGH",
                        username=event.username,
                        ip_address=event.ip_address,
                        failed_attempts=len(recent_attempts),
                    )
                )

            failed_attempts[key] = []

    return alerts

def analyze(
    events: list[LogEvent],
    threshold: int = 3,
    window_seconds: int = 60,
) -> list[SecurityAlert]:
    alerts = []

    alerts.extend(
        detect_brute_force(
            events,
            threshold=threshold,
            window_seconds=window_seconds,
        )
    )

    alerts.extend(
        detect_password_spraying(
            events,
            threshold=threshold,
            window_seconds=window_seconds,
        )
    )

    alerts.extend(
        detect_account_enumeration(
            events,
            threshold=threshold,
            window_seconds=window_seconds,
        )
    )

    alerts.extend(
        detect_suspicious_success(
            events,
            threshold=threshold,
            window_seconds=window_seconds,
        )
    )

    return alerts