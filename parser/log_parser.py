"""Parse synthetic auth.log and Apache access.log into structured records."""
import re
from datetime import datetime, timedelta
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
SUDO_DENIED_RE = re.compile(r"user NOT in sudoers|command not allowed|\d+ incorrect password attempts?", re.I)
SUDO_RE = re.compile(r"^\s*(?P<user>\S+)\s*:.*?COMMAND=(?P<command>.*)$")
INVALID_USER_RE = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>[\d.]+)")
LOCK_RE = re.compile(r"account (?:temporarily )?locked", re.I)
LOCK_USER_RE = re.compile(r"for user (\S+)")
# Pre-authentication disconnects: the peer dropped the connection before logging in. Only lines marked
# [preauth] (or the OpenSSH idle-handshake messages) count; a normal post-login disconnect does not.
USER_PART = r"(?:(?:authenticating|invalid) user (?P<user>\S+) )?"
PREAUTH_RES = [
    re.compile(rf"Connection closed by {USER_PART}(?P<ip>[\d.]+)(?: port \d+)? \[preauth\]"),
    re.compile(rf"Disconnected from {USER_PART}(?P<ip>[\d.]+)(?: port \d+)? \[preauth\]"),
    re.compile(r"(?:error: )?Received disconnect from (?P<ip>[\d.]+)(?: port \d+)?:\s*\d+:.*\[preauth\]"),
    re.compile(rf"Connection reset by {USER_PART}(?P<ip>[\d.]+)(?: port \d+)? \[preauth\]"),
    re.compile(r"Did not receive identification string from (?P<ip>[\d.]+)"),
    re.compile(r"Timeout before authentication for (?:connection from )?(?P<ip>[\d.]+)"),
]
# Authentication attempt limit reached (OpenSSH MaxAuthTries). The IP is absent from the
# "Disconnecting: Too many authentication failures" variant, so it can be None.
MAX_AUTH_RES = [
    re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"),
    re.compile(r"Disconnecting(?: (?:authenticating|invalid) user (?P<user>\S+) (?P<ip>[\d.]+)(?: port \d+)?)?: "
               r"Too many authentication failures(?: for (?P<user2>\S+))?"),
]


def first_match(patterns, message):
    for pattern in patterns:
        if (m := pattern.search(message)):
            return m
    return None


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
        # A denied attempt ("user NOT in sudoers", "command not allowed", "N incorrect password attempts")
        # is not privileged activity: the command did not run.
        event_type = "sudo_denied" if SUDO_DENIED_RE.search(message) else "privileged_activity"
        user, command = m["user"], m["command"]
    elif LOCK_RE.search(message):
        event_type = "account_locked"
        u = LOCK_USER_RE.search(message)
        user = u.group(1) if u else None
    elif (m := INVALID_USER_RE.search(message)):
        # sshd logs this once per attempt for a non-existent account; the follow-up
        # "input_userauth_request: invalid user X [preauth]" line has no IP and stays other_auth_event
        # so one attempt is not counted twice.
        event_type, user, ip = "invalid_user", m["user"] or None, m["ip"]
    elif (m := first_match(MAX_AUTH_RES, message)):
        event_type = "max_auth_attempts"
        user, ip = m["user"] or m.groupdict().get("user2"), m.groupdict().get("ip")
    elif (m := first_match(PREAUTH_RES, message)):
        event_type, user, ip = "preauth_disconnect", m.groupdict().get("user"), m["ip"]
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
    if path.name == "auth.log":
        infer_missing_ips(records)
    return records, errors


PID_WINDOW = timedelta(minutes=5)


def infer_missing_ips(records):
    """Fill the IP of a max-auth / preauth event that has none, from the latest earlier line of the same
    sshd process (host + pid) within PID_WINDOW. Such records get ip_source="pid" so the inference is visible;
    IPs read straight from the line stay ip_source="line"."""
    last = {}
    for r in records:
        r["ip_source"] = "line" if r["ip"] else None
        key = (r["host"], r["pid"])
        if r["pid"] is None:
            continue
        if r["ip"] is None and r["event_type"] in ("max_auth_attempts", "preauth_disconnect"):
            seen = last.get(key)
            if seen and timedelta(0) <= r["timestamp"] - seen[1] <= PID_WINDOW:
                r["ip"], r["ip_source"] = seen[0], "pid"
        if r["ip"]:
            last[key] = (r["ip"], r["timestamp"])


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