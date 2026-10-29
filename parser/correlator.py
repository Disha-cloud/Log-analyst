"""Deterministic detection and correlation rules."""
import re
from collections import defaultdict
from datetime import timedelta
from urllib.parse import unquote

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(seconds=60)
FTS_MIN_FAILURES = 3
FTS_WINDOW = timedelta(minutes=10)
SUDO_WINDOW = timedelta(minutes=10)
UNUSUAL_HOURS = range(0, 5)
LARGE_TRANSFER_BYTES = 10_000_000
CORRELATION_WINDOW = timedelta(hours=1)

SQLI_RE = re.compile(
    r"union\s+(all\s+)?select|select\s.+\sfrom\s|or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"
    r"|information_schema", re.I)
TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|/etc/passwd|windows/win\.ini", re.I)


def make_finding(rule_id, title, description, evidence_ids, severity, ip=None, user=None):
    return {"rule_id": rule_id, "title": title, "description": description,
            "severity": severity, "ip": ip, "user": user,
            "evidence_ids": list(dict.fromkeys(evidence_ids))}


def dedupe(findings):
    seen, unique = set(), []
    for f in findings:
        key = (f["rule_id"], tuple(sorted(f["evidence_ids"])))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def detect_brute_force(auth):
    by_ip = defaultdict(list)
    for r in auth:
        if r["event_type"] == "failed_authentication" and r["ip"]:
            by_ip[r["ip"]].append(r)
    findings = []
    for ip, fails in by_ip.items():
        fails.sort(key=lambda r: r["timestamp"])
        best = []
        for i, first in enumerate(fails):
            window = [x for x in fails[i:]
                      if x["timestamp"] - first["timestamp"] <= BRUTE_FORCE_WINDOW]
            if len(window) > len(best):
                best = window
        if len(best) >= BRUTE_FORCE_THRESHOLD:
            findings.append(make_finding(
                "ssh_brute_force", "Repeated failed SSH logins",
                f"{len(best)} failed logins from {ip} within "
                f"{int(BRUTE_FORCE_WINDOW.total_seconds())} seconds.",
                [x["evidence_id"] for x in best], "high", ip=ip, user=best[0]["user"]))
    return findings


def detect_failure_then_success(auth):
    findings, suspicious_logins, flagged_ips = [], [], set()
    for success in auth:
        if (success["event_type"] != "successful_authentication" or not success["ip"]
                or success["ip"] in flagged_ips):
            continue
        prior = [r for r in auth
                 if r["event_type"] == "failed_authentication" and r["ip"] == success["ip"]
                 and timedelta(0) <= success["timestamp"] - r["timestamp"] <= FTS_WINDOW]
        if len(prior) >= FTS_MIN_FAILURES:
            flagged_ips.add(success["ip"])
            suspicious_logins.append(success)
            findings.append(make_finding(
                "failure_then_success", "Successful login after repeated failures",
                f"{len(prior)} failed logins from {success['ip']} were followed by a successful "
                f"login for {success['user']} within 10 minutes.",
                [r["evidence_id"] for r in prior] + [success["evidence_id"]],
                "high", ip=success["ip"], user=success["user"]))
    return findings, suspicious_logins


def detect_unusual_hour(auth):
    findings, suspicious_logins = [], []
    for r in auth:
        if r["event_type"] == "successful_authentication" and r["timestamp"].hour in UNUSUAL_HOURS:
            suspicious_logins.append(r)
            findings.append(make_finding(
                "unusual_hour_login", "Successful login at unusual hour",
                f"{r['user']} logged in from {r['ip']} at {r['timestamp']:%H:%M}. "
                f"Review indicator, not proof of compromise.",
                [r["evidence_id"]], "medium", ip=r["ip"], user=r["user"]))
    return findings, suspicious_logins


def detect_login_then_sudo(auth, suspicious_logins):
    findings = []
    for login in suspicious_logins:
        for sudo in auth:
            if (sudo["event_type"] == "privileged_activity" and sudo["user"] == login["user"]
                    and timedelta(0) <= sudo["timestamp"] - login["timestamp"] <= SUDO_WINDOW):
                findings.append(make_finding(
                    "login_then_sudo", "Sudo activity after suspicious login",
                    f"{sudo['user']} ran sudo ({sudo['command']}) shortly after a suspicious login. "
                    f"This shows sudo use, not confirmed privilege escalation.",
                    [login["evidence_id"], sudo["evidence_id"]], "high",
                    ip=login["ip"], user=login["user"]))
    return findings


def detect_web_attacks(access):
    findings = []
    for r in access:
        decoded = unquote(r["path"])
        if SQLI_RE.search(decoded):
            findings.append(make_finding(
                "sql_injection_indicator", "SQL injection indicator",
                f"Request from {r['ip']} contains a SQL-injection-like pattern (status "
                f"{r['status']}). Attempt indicator; success not established.",
                [r["evidence_id"]], "high", ip=r["ip"]))
        if TRAVERSAL_RE.search(decoded):
            findings.append(make_finding(
                "path_traversal_indicator", "Path traversal indicator",
                f"Request from {r['ip']} contains a path-traversal-like pattern (status "
                f"{r['status']}). Attempt indicator; success not established.",
                [r["evidence_id"]], "high", ip=r["ip"]))
    return findings


def detect_large_transfers(access):
    return [make_finding(
        "large_data_transfer", "Large HTTP 200 response",
        f"Server returned {r['bytes']:,} bytes to {r['ip']} for {r['path']}.",
        [r["evidence_id"]], "low", ip=r["ip"])
        for r in access if r["status"] == 200 and r["bytes"] >= LARGE_TRANSFER_BYTES]


def detect_correlated(suspicious_logins, access):
    findings = []
    for login in suspicious_logins:
        for r in access:
            if (r["ip"] == login["ip"] and r["status"] == 200
                    and r["bytes"] >= LARGE_TRANSFER_BYTES
                    and timedelta(0) <= r["timestamp"] - login["timestamp"] <= CORRELATION_WINDOW):
                findings.append(make_finding(
                    "correlated_events", "Suspicious login linked to large download",
                    f"Suspicious login by {login['user']} from {login['ip']} followed by a "
                    f"{r['bytes']:,}-byte download within 1 hour. Correlation alone does not "
                    f"prove exfiltration.",
                    [login["evidence_id"], r["evidence_id"]], "high",
                    ip=login["ip"], user=login["user"]))
    return findings


def correlate(records):
    auth = [r for r in records if r["source_file"] == "auth.log"]
    access = [r for r in records if r["source_file"] == "access.log"]
    findings = detect_brute_force(auth)
    fts_findings, fts_logins = detect_failure_then_success(auth)
    hour_findings, hour_logins = detect_unusual_hour(auth)
    suspicious_logins = fts_logins + hour_logins
    findings += fts_findings + hour_findings
    findings += detect_login_then_sudo(auth, suspicious_logins)
    findings += detect_web_attacks(access)
    findings += detect_large_transfers(access)
    findings += detect_correlated(suspicious_logins, access)
    return dedupe(findings)