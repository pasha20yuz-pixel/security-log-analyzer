import argparse
import json
from pathlib import Path

from .analyzer import SecurityAlert, analyze
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


def alert_to_dict(alert: SecurityAlert) -> dict:
    return {
        "alert_type": alert.alert_type,
        "severity": alert.severity,
        "username": alert.username,
        "ip_address": alert.ip_address,
        "failed_attempts": alert.failed_attempts,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for suspicious activity."
    )

    parser.add_argument(
        "log_file",
        type=Path,
        help="Path to the authentication log file.",
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Number of failed attempts required to trigger an alert.",
    )

    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Time window in seconds for detection.",
    )

    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be greater than 0")

    if args.window < 1:
        parser.error("--window must be greater than 0")

    events = load_events(args.log_file)

    alerts = analyze(
        events,
        threshold=args.threshold,
        window_seconds=args.window,
    )

    if args.format == "json":
        output = {
            "events_analyzed": len(events),
            "alerts_detected": len(alerts),
            "alerts": [
                alert_to_dict(alert)
                for alert in alerts
            ],
        }

        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

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