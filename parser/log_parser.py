"""Parse synthetic auth.log and Apache access.log into structured records."""
import re
from datetime import datetime
from pathlib import Path

LOG_YEAR = 2026
LOG_FILES = ("auth.log", "access.log")

ID_RE = re.compile(r"^(L\d+)\s+(.*)$")
AUTH_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<process>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$")
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+(?P<protocol>[^"]*))?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?\s*$')
FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)")
SUDO_RE = re.compile(r"^\s*(?P<user>\S+)\s*:.*?COMMAND=(?P<command>.*)$")
LOCK_RE = re.compile(r"account (?:temporarily )?locked", re.I)
LOCK_USER_RE = re.compile(r"for user (\S+)")


def split_line_id(raw, line_number, filename):
    match = ID_RE.match(raw)
    if match:
        return match.group(1), match.group(2)
    offset = 5000 if filename == "access.log" else 0
    return f"L{line_number + offset:04d}", raw


def parse_auth_timestamp(text):
    return datetime.strptime(f"{LOG_YEAR} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")


def parse_access_timestamp(text):
    return datetime.strptime(text.split()[0], "%d/%b/%Y:%H:%M:%S")


def parse_auth_line(raw, line_number):
    raw = raw.rstrip("\n")
    line_id, body = split_line_id(raw, line_number, "auth.log")
    evidence_id = f"auth.log:{line_id}"
    match = AUTH_RE.match(body)
    if not match:
        return None, f"{evidence_id}: unrecognized auth format"
    try:
        when = parse_auth_timestamp(match["ts"])
    except ValueError:
        return None, f"{evidence_id}: bad timestamp"
    message, process = match["message"], match["process"]
    user = ip = command = None
    if (m := FAILED_RE.search(message)):
        event_type, user, ip = "failed_authentication", m["user"], m["ip"]
    elif (m := ACCEPTED_RE.search(message)):
        event_type, user, ip = "successful_authentication", m["user"], m["ip"]
    elif process == "sudo" and (m := SUDO_RE.search(message)):
        event_type, user, command = "privileged_activity", m["user"], m["command"]
    elif LOCK_RE.search(message):
        event_type = "account_locked"
        u = LOCK_USER_RE.search(message)
        user = u.group(1) if u else None
    else:
        event_type = "other_auth_event"
    return {
        "source_file": "auth.log", "line_id": line_id, "evidence_id": evidence_id,
        "timestamp": when, "timestamp_text": match["ts"], "host": match["host"],
        "process": process, "pid": match["pid"], "ip": ip, "user": user,
        "command": command, "event_type": event_type, "message": message, "raw": raw,
    }, None


def parse_access_line(raw, line_number):
    raw = raw.rstrip("\n")
    line_id, body = split_line_id(raw, line_number, "access.log")
    evidence_id = f"access.log:{line_id}"
    match = ACCESS_RE.match(body)
    if not match:
        return None, f"{evidence_id}: unrecognized access format"
    try:
        when = parse_access_timestamp(match["ts"])
    except ValueError:
        return None, f"{evidence_id}: bad timestamp"
    return {
        "source_file": "access.log", "line_id": line_id, "evidence_id": evidence_id,
        "timestamp": when, "timestamp_text": match["ts"], "ip": match["ip"],
        "method": match["method"], "path": match["path"], "protocol": match["protocol"],
        "status": int(match["status"]),
        "bytes": 0 if match["bytes"] == "-" else int(match["bytes"]),
        "agent": match["agent"], "event_type": "http_request", "raw": raw,
    }, None


def parse_file(path):
    path = Path(path)
    parse_line = parse_auth_line if path.name == "auth.log" else parse_access_line
    records, errors = [], []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            record, error = parse_line(line, number)
            if record:
                records.append(record)
            if error:
                errors.append(error)
    return records, errors


def parse_scenario(scenario_dir):
    scenario_dir = Path(scenario_dir)
    records, errors = [], []
    for filename in LOG_FILES:
        path = scenario_dir / filename
        if path.exists():
            parsed, parse_errors = parse_file(path)
            records.extend(parsed)
            errors.extend(parse_errors)
    records.sort(key=lambda r: r["timestamp"])
    return records, errors


def load_raw_lines(scenario_dir):
    """Map evidence_id -> raw line, for validation and display."""
    lines = {}
    for filename in LOG_FILES:
        path = Path(scenario_dir) / filename
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for number, raw in enumerate(handle, start=1):
                raw = raw.rstrip("\n")
                if raw.strip():
                    line_id, _ = split_line_id(raw, number, filename)
                    lines[f"{filename}:{line_id}"] = raw
    return lines


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1] / "data"
    for scenario_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        records, errors = parse_scenario(scenario_dir)
        print(f"{scenario_dir.name}: {len(records)} records, {len(errors)} parse errors")
        for error in errors[:5]:
            print("   ", error)