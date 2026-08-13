import argparse
from pathlib import Path

from .analyzer import detect_brute_force
from .parser import parse_log_line


def load_events(log_file: Path):
    events = []

    with log_file.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                event = parse_log_line(line)
            except ValueError as error:
                print(f"Warning: line {line_number}: {error}")
                continue

            events.append(event)

    return events


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for suspicious activity."
    )

    parser.add_argument(
        "log_file",
        type=Path,
        help="Path to the authentication log file.",
    )

    args = parser.parse_args()

    events = load_events(args.log_file)
    alerts = detect_brute_force(events)

    print("Security Log Analyzer")
    print("=" * 30)
    print(f"Events analyzed: {len(events)}")
    print(f"Alerts detected: {len(alerts)}")

    for alert in alerts:
        print()
        print(f"[{alert.severity}] {alert.alert_type}")
        print(f"User: {alert.username}")
        print(f"IP: {alert.ip_address}")
        print(f"Failed attempts: {alert.failed_attempts}")


if __name__ == "__main__":
    main()