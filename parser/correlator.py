
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote

from parser.log_parser import parse_scenario


# Detection patterns
FAILED_PATTERN = re.compile(r"Failed password", re.IGNORECASE)
SUCCESS_PATTERN = re.compile(
    r"Accepted (?:password|publickey)", re.IGNORECASE
)
SQLI_PATTERN = re.compile(
    r"(?:'\s*OR\s+1\s*=\s*1|UNION\s+SELECT|%27\s*OR)",
    re.IGNORECASE,
)
TRAVERSAL_PATTERN = re.compile(
    r"(?:\.\./|\.\.%2f|%2e%2e%2f)",
    re.IGNORECASE,
)
USER_PATTERN = re.compile(
    r"(?:Failed password for (?:invalid user )?|"
    r"Accepted (?:password|publickey) for )"
    r"([a-zA-Z0-9_.-]+)"
)


def parse_time(record):
    """Normalize authentication and Apache timestamps."""
    value = record.get("timestamp", "")

    formats = [
        "%b %d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
    ]

    for fmt in formats:
        try:
            parsed = datetime.strptime(value, fmt)

            if fmt == formats[0]:
                parsed = parsed.replace(year=2026)

            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(
                    timezone.utc
                ).replace(tzinfo=None)

            return parsed

        except ValueError:
            continue

    return None


def enrich(record):
    """Normalize fields used by the detection rules."""
    event = dict(record)
    event["event_time"] = parse_time(record)

    raw = record.get("raw", "")
    message = record.get("message", "")

    event["user"] = record.get("user")

    if not event["user"]:
        user_match = USER_PATTERN.search(raw)
        if user_match:
            event["user"] = user_match.group(1)

    if record["log_type"] == "auth":
        if FAILED_PATTERN.search(message):
            event["event_type"] = "failed_login"

        elif SUCCESS_PATTERN.search(message):
            event["event_type"] = "successful_login"

        elif re.search(r"\bsudo\b", message, re.IGNORECASE):
            event["event_type"] = "sudo_activity"

        if event["event_type"] == "sudo_activity":
            sudo_match = re.search(r"for user (\S+)", raw)
            if sudo_match:
                event["user"] = sudo_match.group(1)

    return event


def event_ref(event):
    """Qualify line IDs because separate files reuse IDs."""
    filename = (
        "auth.log"
        if event["log_type"] == "auth"
        else "access.log"
    )
    return f"{filename}:{event['line_id']}"


def make_finding(rule, records, explanation):
    """Create a finding with traceable evidence."""
    return {
        "rule": rule,
        "explanation": explanation,
        "evidence_ids": [event_ref(e) for e in records],
        "events": [
            {
                "line_id": event_ref(e),
                "timestamp": e.get("timestamp"),
                "event_type": e.get("event_type"),
                "ip": e.get("ip"),
                "user": e.get("user"),
                "message": e.get("message", e.get("path", "")),
                "status": e.get("status"),
                "size_bytes": e.get("size_bytes"),
            }
            for e in records
        ],
    }


def correlate(records):
    """Apply deterministic rules without using an LLM."""
    events = [enrich(record) for record in records]

    events.sort(
        key=lambda e: e["event_time"] or datetime.max
    )

    findings = []

    # Group events by IP.
    by_ip = defaultdict(list)

    for event in events:
        if event.get("ip"):
            by_ip[event["ip"]].append(event)

    # Rule 1: five or more failed logins within 60 seconds.
    for ip, group in by_ip.items():
        failures = [
            e for e in group
            if e.get("event_type") == "failed_login"
        ]

        for first in failures:
            if first["event_time"] is None:
                continue

            window = [
                e for e in failures
                if e["event_time"] is not None
                and timedelta(0)
                <= e["event_time"] - first["event_time"]
                <= timedelta(seconds=60)
            ]

            if len(window) >= 5:
                findings.append(
                    make_finding(
                        "ssh_brute_force",
                        window,
                        f"{len(window)} failed logins from {ip} "
                        "within 60 seconds.",
                    )
                )
                break

    # Rule 2: failed login followed by success from the same IP.
    for ip, group in by_ip.items():
        failures = [
            e for e in group
            if e.get("event_type") == "failed_login"
        ]

        for success in group:
            if success.get("event_type") != "successful_login":
                continue

            if success["event_time"] is None:
                continue

            prior = [
                e for e in failures
                if e["event_time"] is not None
                and timedelta(0)
                <= success["event_time"] - e["event_time"]
                <= timedelta(minutes=10)
            ]

            if prior:
                findings.append(
                    make_finding(
                        "failure_then_success",
                        prior + [success],
                        f"A successful login from {ip} followed "
                        "failed login attempts within 10 minutes.",
                    )
                )

    # Rule 3: sudo activity after a successful login by the same user.
    for event in events:
        if event.get("event_type") != "sudo_activity":
            continue

        if not event.get("user") or event["event_time"] is None:
            continue

        prior_logins = [
            e for e in events
            if e.get("event_type") == "successful_login"
            and e.get("user") == event["user"]
            and e["event_time"] is not None
            and timedelta(0)
            <= event["event_time"] - e["event_time"]
            <= timedelta(minutes=10)
        ]

        if prior_logins:
            findings.append(
                make_finding(
                    "login_then_sudo",
                    [prior_logins[-1], event],
                    f"User {event['user']} performed sudo activity "
                    "within 10 minutes of a successful login.",
                )
            )

    # Rule 4: SQL injection and path traversal indicators.
    for event in events:
        if event.get("log_type") != "apache":
            continue

        path = event.get("path", "")
        decoded_path = unquote(path)

        if (
            SQLI_PATTERN.search(path)
            or SQLI_PATTERN.search(decoded_path)
        ):
            findings.append(
                make_finding(
                    "sql_injection_indicator",
                    [event],
                    "The request contains a SQL injection pattern. "
                    "Successful exploitation is not established.",
                )
            )

        if (
            TRAVERSAL_PATTERN.search(path)
            or TRAVERSAL_PATTERN.search(decoded_path)
        ):
            findings.append(
                make_finding(
                    "path_traversal_indicator",
                    [event],
                    "The request contains a path traversal pattern. "
                    "The response status alone does not prove file access.",
                )
            )

    # Rule 5: successful login during an unusual hour (00:00-04:59).
    for event in events:
        if event.get("event_type") != "successful_login":
            continue

        event_time = event.get("event_time")

        if event_time is not None and event_time.hour < 5:
            findings.append(
                make_finding(
                    "unusual_hour_login",
                    [event],
                    "A successful login occurred before 05:00. "
                    "Timing alone does not establish malicious activity.",
                )
            )

    # Rule 6: HTTP 200 response with at least 10 MB of data.
    large_responses = []

    for event in events:
        if event.get("log_type") != "apache":
            continue

        if (
            event.get("status") == 200
            and event.get("size_bytes", 0) >= 10_000_000
        ):
            large_responses.append(event)

            findings.append(
                make_finding(
                    "large_data_transfer_indicator",
                    [event],
                    "A large HTTP response was observed. "
                    "This alone does not prove data exfiltration.",
                )
            )

    # Rule 7: correlate an unusual-hour login with a large response
    # from the same IP within 24 hours.
    for login in events:
        if login.get("event_type") != "successful_login":
            continue

        login_time = login.get("event_time")

        if login_time is None or login_time.hour >= 5:
            continue

        for response in large_responses:
            if response.get("ip") != login.get("ip"):
                continue

            response_time = response.get("event_time")

            if response_time is None:
                continue

            elapsed = response_time - login_time

            if timedelta(0) <= elapsed <= timedelta(hours=24):
                findings.append(
                    make_finding(
                        "login_then_large_transfer",
                        [login, response],
                        "An unusual-hour login and a large HTTP response "
                        "share the same IP within 24 hours. Investigate "
                        "whether the events are related; exfiltration "
                        "is not confirmed.",
                    )
                )

    # Deduplicate identical rules with identical evidence.
    unique = {}

    for finding in findings:
        key = (
            finding["rule"],
            tuple(finding["evidence_ids"]),
        )
        unique[key] = finding

    return list(unique.values())


def analyze_scenario(scenario_dir):
    """Parse one scenario and apply the detection rules."""
    records, errors = parse_scenario(scenario_dir)
    findings = correlate(records)

    return {
        "scenario": Path(scenario_dir).name,
        "parsed_records": len(records),
        "parse_errors": errors,
        "suspicious_groups": findings,
    }


if __name__ == "__main__":
    project_dir = Path(__file__).resolve().parent.parent
    data_dir = project_dir / "data"

    for scenario_dir in sorted(data_dir.glob("S*")):
        if not scenario_dir.is_dir():
            continue

        result = analyze_scenario(scenario_dir)

        print(f"\n{result['scenario']}")
        print(f"Parsed records: {result['parsed_records']}")
        print(f"Parse errors: {len(result['parse_errors'])}")
        print(
            f"Suspicious groups: "
            f"{len(result['suspicious_groups'])}"
        )

        for finding in result["suspicious_groups"]:
            print(
                f"  - {finding['rule']}: "
                f"{', '.join(finding['evidence_ids'])}"
            )
