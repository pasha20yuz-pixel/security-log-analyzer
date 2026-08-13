import ipaddress

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime
    event_type: str
    username: str
    ip_address: str

def parse_log_line(line: str) -> LogEvent:
    parts = line.strip().split()

    if len(parts) != 5:
        raise ValueError(f"Invalid log format: {line.strip()}")

    date = parts[0]
    time = parts[1]
    event_type = parts[2]

    user_part = parts[3]
    ip_part = parts[4]

    if not user_part.startswith("user="):
        raise ValueError(f"Invalid user field: {user_part}")

    if not ip_part.startswith("ip="):
        raise ValueError(f"Invalid IP field: {ip_part}")

    username = user_part.removeprefix("user=")
    ip_address = ip_part.removeprefix("ip=")

    if not username:
        raise ValueError("Username cannot be empty")

    try:
        ipaddress.ip_address(ip_address)
    except ValueError as error:
        raise ValueError(f"Invalid IP address: {ip_address}") from error

    timestamp = datetime.strptime(
        f"{date} {time}",
        "%Y-%m-%d %H:%M:%S",
    )

    return LogEvent(
        timestamp=timestamp,
        event_type=event_type,
        username=username,
        ip_address=ip_address,
    )