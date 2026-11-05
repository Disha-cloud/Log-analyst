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
SPRAY_WINDOW = timedelta(minutes=10)
SPRAY_MIN_ATTEMPTS = 4
SPRAY_MIN_USERNAMES = 3
EXHAUSTED_HIGH_COUNT = 3     # this many max-auth events from one IP raises severity to high
PROBE_MIN_ATTEMPTS = 2
PROBE_MIN_USERNAMES = 2
ATTEMPT_TYPES = ("failed_authentication", "invalid_user")
SLOW_WINDOW = timedelta(hours=24)
SLOW_MIN_ATTEMPTS = 5
DENIED_SUDO_WINDOW = timedelta(hours=1)
DENIED_SUDO_HIGH_COUNT = 3
SENSITIVE_COMMAND_RE = re.compile(r"/etc/(?:shadow|sudoers|passwd)|\.ssh/|id_rsa|/root/|authorized_keys", re.I)

SQLI_RE = re.compile(
    r"union\s+(all\s+)?select|select\s.+\sfrom\s|or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"
    r"|information_schema", re.I)
TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|/etc/passwd|windows/win\.ini", re.I)
RULE_TO_MITRE = {
    "ssh_brute_force": "T1110",
    "failure_then_success": "T1078",
    "unusual_hour_login": "T1078",
    "login_then_sudo": "T1548.003",
    "sql_injection_indicator": "T1190",
    "path_traversal_indicator": "T1190",
    "large_data_transfer": "T1048",
    "correlated_events": "T1048",
    "username_spraying": "T1110.003",
    "auth_attempts_exhausted": "T1110",
    "probe_then_success": "T1078",
    "slow_brute_force": "T1110.001",
    "denied_sudo": "T1548.003",
}


def make_finding(rule_id, title, description, evidence_ids, severity, ip=None, user=None):
    return {"rule_id": rule_id, "title": title, "description": description,
            "severity": severity, "ip": ip, "user": user,
            "mitre_id": RULE_TO_MITRE.get(rule_id),
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


def maximal_windows(events, span):
    """Yield (i, j) for each start i: events[i:j] is every event within `span` of events[i] (events time-sorted).
    Linear time: the end pointer never moves back."""
    j = 0
    for i, first in enumerate(events):
        j = max(j, i)
        while j < len(events) and events[j]["timestamp"] - first["timestamp"] <= span:
            j += 1
        yield i, j


def detect_username_spraying(auth):
    """>= 4 failed/invalid-user attempts covering >= 3 distinct usernames from one IP within 10 minutes.
    Complements ssh_brute_force, which needs 5 failures in 60 seconds and so misses slow multi-account guessing."""
    by_ip = defaultdict(list)
    for r in auth:
        if r["event_type"] in ATTEMPT_TYPES and r["ip"] and r["user"]:
            by_ip[r["ip"]].append(r)
    findings = []
    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda r: r["timestamp"])
        best, best_key = [], (0, 0)
        counts, lo = defaultdict(int), 0
        hi = 0
        for i, j in maximal_windows(attempts, SPRAY_WINDOW):
            while hi < j:
                counts[attempts[hi]["user"]] += 1
                hi += 1
            while lo < i:
                counts[attempts[lo]["user"]] -= 1
                if not counts[attempts[lo]["user"]]:
                    del counts[attempts[lo]["user"]]
                lo += 1
            size, users = j - i, len(counts)
            if size >= SPRAY_MIN_ATTEMPTS and users >= SPRAY_MIN_USERNAMES and (users, size) > best_key:
                best, best_key = attempts[i:j], (users, size)
        if best:
            users = sorted({x["user"] for x in best})
            findings.append(make_finding(
                "username_spraying", "One IP tried many usernames",
                f"{len(best)} failed or invalid-user attempts from {ip} across {len(users)} usernames "
                f"({', '.join(users[:6])}) within 10 minutes.",
                [x["evidence_id"] for x in best], "high", ip=ip, user=best[0]["user"]))
    return findings


def detect_auth_attempts_exhausted(auth):
    """sshd gave up on a connection after the maximum number of authentication attempts (MaxAuthTries)."""
    by_ip = defaultdict(list)
    for r in auth:
        if r["event_type"] == "max_auth_attempts" and r["ip"]:
            by_ip[r["ip"]].append(r)
    findings = []
    for ip, events in by_ip.items():
        events.sort(key=lambda r: r["timestamp"])
        findings.append(make_finding(
            "auth_attempts_exhausted", "Authentication attempt limit reached",
            f"sshd stopped {len(events)} connection(s) from {ip} after too many authentication attempts. "
            f"Indicates repeated guessing; the individual failures may not all be in this log.",
            [e["evidence_id"] for e in events], "high" if len(events) >= EXHAUSTED_HIGH_COUNT else "medium",
            ip=ip, user=events[0]["user"]))
    return findings


def detect_probe_then_success(auth, already_flagged_ips):
    """Several attempts across >= 2 usernames, then a successful login, within 10 minutes. A single user mistyping
    a password is deliberately NOT flagged: it looks identical to legitimate typos."""
    findings, logins = [], []
    done = set(already_flagged_ips)
    for success in auth:
        if success["event_type"] != "successful_authentication" or not success["ip"] or success["ip"] in done:
            continue
        prior = [r for r in auth if r["event_type"] in ATTEMPT_TYPES and r["ip"] == success["ip"]
                 and timedelta(0) <= success["timestamp"] - r["timestamp"] <= FTS_WINDOW]
        users = {r["user"] for r in prior if r["user"]} | {success["user"]}
        if len(prior) >= PROBE_MIN_ATTEMPTS and len(users) >= PROBE_MIN_USERNAMES \
                and any(r["user"] != success["user"] for r in prior):
            done.add(success["ip"])
            logins.append(success)
            findings.append(make_finding(
                "probe_then_success", "Login after guessing several accounts",
                f"{len(prior)} failed attempts from {success['ip']} across {len(users)} usernames were followed "
                f"by a successful login for {success['user']} within 10 minutes.",
                [r["evidence_id"] for r in prior] + [success["evidence_id"]],
                "high", ip=success["ip"], user=success["user"]))
    return findings, logins


def detect_slow_brute_force(auth, skip_ips):
    """>= 5 failed/invalid-user attempts from one IP within 24 hours and no successful login from it in that
    span. Catches guessing too slow for ssh_brute_force. An IP that ever succeeded is left to the other rules,
    which keeps occasional typos by real users out. IPs already reported as brute force / spraying are skipped."""
    by_ip = defaultdict(list)
    for r in auth:
        if r["ip"] and r["ip"] not in skip_ips:
            by_ip[r["ip"]].append(r)
    findings = []
    for ip, events in by_ip.items():
        events.sort(key=lambda r: r["timestamp"])
        attempts = [r for r in events if r["event_type"] in ATTEMPT_TYPES]
        best = []
        for i, j in maximal_windows(attempts, SLOW_WINDOW):
            if j - i > len(best):
                best = attempts[i:j]
        if len(best) < SLOW_MIN_ATTEMPTS:
            continue
        start, end = best[0]["timestamp"], best[-1]["timestamp"]
        if any(r["event_type"] == "successful_authentication" and start <= r["timestamp"] <= end + SLOW_WINDOW
               for r in events):
            continue
        users = sorted({x["user"] for x in best if x["user"]})
        hours = (end - start).total_seconds() / 3600
        findings.append(make_finding(
            "slow_brute_force", "Slow password guessing",
            f"{len(best)} failed attempts from {ip} over {hours:.1f} hours "
            f"({', '.join(users[:5]) or 'unknown users'}), with no successful login.",
            [x["evidence_id"] for x in best], "medium", ip=ip, user=best[0]["user"]))
    return findings


def detect_denied_sudo(auth):
    """sudo refused a command (user not in sudoers, command not allowed, wrong password). Grouped per user within
    1 hour; high when sensitive files are targeted or the user retried 3+ times."""
    by_user = defaultdict(list)
    for r in auth:
        if r["event_type"] == "sudo_denied":
            by_user[r["user"]].append(r)
    findings = []
    for user, events in by_user.items():
        events.sort(key=lambda r: r["timestamp"])
        group = [events[0]]
        for r in events[1:] + [None]:
            if r is not None and r["timestamp"] - group[-1]["timestamp"] <= DENIED_SUDO_WINDOW:
                group.append(r)
                continue
            sensitive = [g for g in group if SENSITIVE_COMMAND_RE.search(g["command"] or "")]
            severity = "high" if sensitive or len(group) >= DENIED_SUDO_HIGH_COUNT else "medium"
            cmds = sorted({(g["command"] or "").strip() for g in group})
            findings.append(make_finding(
                "denied_sudo", "Denied sudo attempts",
                f"{len(group)} denied sudo attempt(s) by {user} ({'; '.join(cmds[:3])})"
                f"{' targeting sensitive files' if sensitive else ''}. The commands did not run.",
                [g["evidence_id"] for g in group], severity, user=user))
            if r is not None:
                group = [r]
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
    probe_findings, probe_logins = detect_probe_then_success(auth, {f["ip"] for f in fts_findings})
    suspicious_logins = fts_logins + hour_logins + probe_logins
    findings += fts_findings + hour_findings + probe_findings
    spray = detect_username_spraying(auth)
    findings += spray + detect_auth_attempts_exhausted(auth)
    findings += detect_slow_brute_force(auth, {f["ip"] for f in findings if f["rule_id"] in
                                               ("ssh_brute_force", "username_spraying")})
    findings += detect_denied_sudo(auth)
    findings += detect_login_then_sudo(auth, suspicious_logins)
    findings += detect_web_attacks(access)
    findings += detect_large_transfers(access)
    findings += detect_correlated(suspicious_logins, access)
    return dedupe(findings)