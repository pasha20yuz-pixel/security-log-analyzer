from dataclasses import dataclass

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
) -> list[SecurityAlert]:
    alerts = []

    failed_attempts: dict[tuple[str, str], int] = {}

    for event in events:
        key = (event.username, event.ip_address)

        if event.event_type == "LOGIN_FAILED":
            failed_attempts[key] = failed_attempts.get(key, 0) + 1

            if failed_attempts[key] == threshold:
                alerts.append(
                    SecurityAlert(
                        alert_type="BRUTE_FORCE",
                        severity="HIGH",
                        username=event.username,
                        ip_address=event.ip_address,
                        failed_attempts=failed_attempts[key],
                    )
                )

        elif event.event_type == "LOGIN_SUCCESS":
            failed_attempts[key] = 0

    return alerts