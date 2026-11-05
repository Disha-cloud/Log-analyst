"""Per-IP features and weak labels for raw sshd logs (Loghub OpenSSH format).

Separate from features/extract_features.py on purpose: the project parser gives most real sshd lines
(Invalid user, PAM failures, preauth disconnects, break-in warnings) no IP, so they are invisible there.

Features describe ONE chunk of the log (default 2000 lines, like REAL_SSH): what a defender sees at a
point in time. Labels come from the IP's behaviour over the WHOLE log (hindsight). So the task is
"from one chunk, is this IP a persistent attacker?" Labels are heuristic, not human ground truth.
"""
import re
from collections import defaultdict
from datetime import datetime

import pandas as pd

IP = r"(?:\d{1,3}\.){3}\d{1,3}"
TS_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d+)\s+(\d\d):(\d\d):(\d\d)")
RULES = [  # (name, regex with the IP as group 'ip')
    ("failed_pw", re.compile(rf"Failed (?:password|none) for .*? from (?P<ip>{IP})")),
    ("invalid_user", re.compile(rf"Invalid user \S* from (?P<ip>{IP})")),
    ("pam_fail", re.compile(rf"authentication failure;.*rhost=(?P<ip>{IP})")),
    ("preauth_disc", re.compile(rf"(?:Received disconnect from|Connection closed by) (?P<ip>{IP})")),
    ("breakin", re.compile(rf"POSSIBLE BREAK-IN.*\[(?P<ip>{IP})\]")),
    ("no_ident", re.compile(rf"Did not receive identification string from (?P<ip>{IP})")),
    ("accepted", re.compile(rf"Accepted (?:password|publickey) for .*? from (?P<ip>{IP})")),
]
USER_RES = [re.compile(r"Failed \w+ for (?:invalid user )?(\S+) from"), re.compile(r"Invalid user (\S*) from"),
            re.compile(r"authentication failure;.*\buser=(\S+)")]
COUNTS = [r[0] for r in RULES]
FEATURE_COLUMNS = COUNTS + ["distinct_users", "event_count", "duration_min", "events_per_min",
                            "bad_ratio", "first_hour"]
BAD = ("failed_pw", "invalid_user", "pam_fail")


def parse_line(line):
    """(ip, kind, user, minute_of_day_with_date_order) or None."""
    for kind, rx in RULES:
        m = rx.search(line)
        if m:
            user = next((u.group(1) for u in (r.search(line) for r in USER_RES) if u), None)
            t = TS_RE.search(line)
            ts = datetime.strptime(f"2000 {t[1]} {t[2]} {t[3]}:{t[4]}:{t[5]}", "%Y %b %d %H:%M:%S") if t else None
            return m["ip"], kind, user, ts
    return None


def read_events(path):
    out = []
    with open(path, errors="replace") as fh:
        for n, line in enumerate(fh):
            ev = parse_line(line)
            out.append((n,) + ev if ev else None)
    return out  # index = line number; None for lines with no IP-bearing signal


def global_labels(events, min_bad=10):
    """malicious / benign / ambiguous per IP from whole-log behaviour."""
    tot = defaultdict(lambda: defaultdict(int))
    for ev in events:
        if ev:
            tot[ev[1]][ev[2]] += 1
    labels = {}
    for ip, c in tot.items():
        bad = sum(c[k] for k in BAD)
        if c["accepted"] == 0 and bad >= min_bad:
            labels[ip] = "malicious"
        elif c["accepted"] >= 1 and bad == 0:
            labels[ip] = "benign"
        else:
            labels[ip] = "ambiguous"
    return labels, tot


def chunk_features(events, chunk_lines=2000):
    rows, groups = [], defaultdict(list)
    for ev in events:
        if ev:
            groups[(ev[0] // chunk_lines, ev[1])].append(ev)
    for (chunk, ip), all_evs in groups.items():
        # Successful-login lines are excluded from every feature: the benign label is defined by them, and
        # other logs (e.g. Loghub Linux) do not tie them to a source host. Rows with nothing else carry no
        # signal a detector could act on, so they are dropped.
        evs = [e for e in all_evs if e[2] != "accepted"]
        if not evs:
            continue
        c = defaultdict(int)
        for e in evs:
            c[e[2]] += 1
        times = [e[4] for e in evs if e[4]]
        dur = max(0.0, (max(times) - min(times)).total_seconds() / 60) if times else 0.0
        n = len(evs)
        rows.append({"chunk": chunk, "ip": ip, **{k: c[k] for k in COUNTS},
                     "distinct_users": len({e[3] for e in evs if e[3]}), "event_count": n,
                     "duration_min": dur, "events_per_min": n / max(dur, 1.0),
                     "bad_ratio": sum(c[k] for k in BAD) / n,
                     "first_hour": times[0].hour if times else -1})
    return pd.DataFrame(rows)
