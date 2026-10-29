"""Deterministic synthetic log generator for Log Analyst.

Writes data/<scenario>/auth.log, access.log, ground_truth.json.
All data is synthetic. All IPs are private 10.x addresses.
"""
import json
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"

BASE_DATE = datetime(2026, 10, 28)
HOST = "web01"
AUTH_ID_START = 1         # auth.log IDs: L0001, L0002, ...
ACCESS_ID_START = 5001    # access.log IDs: L5001, ... so bare IDs never collide
BENIGN_AUTH_COUNT = 250
BENIGN_ACCESS_COUNT = 250
STALE_OUTPUTS = ("llm_analysis.json", "claim_validation.json", "evaluation.json")

USERS = ["alice", "bob", "carol", "deploy"]
BENIGN_AUTH_IPS = [f"10.0.1.{i}" for i in range(10, 31)]
BENIGN_WEB_IPS = [f"10.0.2.{i}" for i in range(10, 61)]
BENIGN_PATHS = ["/", "/index.html", "/about", "/contact", "/products", "/products?id=12",
                "/static/app.js", "/static/style.css", "/images/logo.png", "/login",
                "/api/status", "/api/items?page=2", "/blog/security-tips", "/cart"]
AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5)",
          "Mozilla/5.0 (X11; Linux x86_64)", "curl/8.4.0"]


def at(hour, minute, second=0):
    return BASE_DATE.replace(hour=hour, minute=minute, second=second)


def daytime(rng):
    return BASE_DATE + timedelta(seconds=rng.randint(8 * 3600, 19 * 3600))


def auth_event(when, process, message, pid=None, malicious=False):
    proc = f"{process}[{pid}]" if pid else process
    text = f"{when.strftime('%b %d %H:%M:%S')} {HOST} {proc}: {message}"
    return {"time": when, "text": text, "malicious": malicious}


def access_event(when, ip, method, path, status, size, agent, malicious=False):
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0000")
    text = f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'
    return {"time": when, "text": text, "malicious": malicious}


def benign_auth(rng, count=BENIGN_AUTH_COUNT):
    events = []
    while len(events) < count:
        when = daytime(rng)
        user = rng.choice(USERS)
        uid = 1000 + USERS.index(user)
        ip = rng.choice(BENIGN_AUTH_IPS)
        pid = rng.randint(1000, 2999)
        method = rng.choice(["password", "publickey"])
        events.append(auth_event(when, "sshd",
            f"Accepted {method} for {user} from {ip} port {rng.randint(40000, 65000)} ssh2", pid))
        events.append(auth_event(when + timedelta(seconds=1), "sshd",
            f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)", pid))
        if rng.random() < 0.4:
            events.append(auth_event(when + timedelta(minutes=rng.randint(5, 50)), "sshd",
                f"pam_unix(sshd:session): session closed for user {user}", pid))
        if rng.random() < 0.3:
            events.append(auth_event(daytime(rng), "CRON",
                "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
                rng.randint(1000, 2999)))
    return events[:count]


def benign_access(rng, count=BENIGN_ACCESS_COUNT):
    events = []
    for _ in range(count):
        status = rng.choices([200, 304, 404], weights=[85, 10, 5])[0]
        size = rng.randint(300, 250_000) if status == 200 else rng.randint(0, 500)
        events.append(access_event(daytime(rng), rng.choice(BENIGN_WEB_IPS),
            rng.choice(["GET", "GET", "GET", "POST"]), rng.choice(BENIGN_PATHS),
            status, size, rng.choice(AGENTS)))
    return events


def build_s1(rng, mitigated=False):
    auth, access = benign_auth(rng), benign_access(rng)
    ip, user, start = "10.0.5.23", "admin", at(2, 14, 0)
    failures = 5 if mitigated else 6
    for i in range(failures):
        auth.append(auth_event(start + timedelta(seconds=5 * i), "sshd",
            f"Failed password for {user} from {ip} port {51100 + i} ssh2", 3100 + i, True))
    if mitigated:
        locked = start + timedelta(seconds=5 * failures)
        auth.append(auth_event(locked, "sshd",
            f"pam_faillock(sshd:auth): Consecutive login failures for user {user} "
            f"account temporarily locked", 3200))
        for i in range(3):
            auth.append(auth_event(locked + timedelta(seconds=5 * (i + 1)), "sshd",
                f"Failed password for {user} from {ip} port {51200 + i} ssh2", 3201 + i, True))
        return {"auth": auth, "access": access,
                "description": "S1 with mitigation: account lockout after 5 failures. "
                               "Brute force continues but never succeeds.",
                "expected_rules": ["ssh_brute_force"]}
    login = start + timedelta(seconds=45)
    auth.append(auth_event(login, "sshd",
        f"Accepted password for {user} from {ip} port 51130 ssh2", 3150, True))
    auth.append(auth_event(login + timedelta(minutes=2), "sudo",
        f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        malicious=True))
    return {"auth": auth, "access": access,
            "description": "SSH brute force, then successful login at 02:14, then sudo reading /etc/shadow.",
            "expected_rules": ["ssh_brute_force", "failure_then_success",
                               "unusual_hour_login", "login_then_sudo"]}


def build_s2(rng):
    auth, access = benign_auth(rng), benign_access(rng)
    ip, agent, start = "10.0.6.66", "sqlmap/1.7", at(11, 20, 0)
    payloads = [
        ("/products.php?id=1%27%20OR%20%271%27=%271", 500, 312),
        ("/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users", 200, 1840),
        ("/download?file=../../../../etc/passwd", 403, 199),
        ("/static/..%2f..%2f..%2fetc/passwd", 404, 196),
    ]
    for i, (path, status, size) in enumerate(payloads):
        access.append(access_event(start + timedelta(seconds=30 * i), ip, "GET",
                                   path, status, size, agent, True))
    return {"auth": auth, "access": access,
            "description": "Web attack attempts: 2 SQL injection and 2 path traversal requests.",
            "expected_rules": ["sql_injection_indicator", "path_traversal_indicator"]}


def build_s3(rng):
    auth, access = benign_auth(rng), benign_access(rng)
    ip, user, login = "10.0.7.77", "carol", at(3, 14, 0)
    auth.append(auth_event(login, "sshd",
        f"Accepted password for {user} from {ip} port 52211 ssh2", 3300, True))
    access.append(access_event(login + timedelta(minutes=6), ip, "GET",
        "/exports/customers_full.csv", 200, 52_428_800, "python-requests/2.31", True))
    return {"auth": auth, "access": access,
            "description": "Unusual-hour login (03:14) followed by a 50 MB download from the same IP.",
            "expected_rules": ["unusual_hour_login", "large_data_transfer", "correlated_events"]}


def build_s4(rng):
    return {"auth": benign_auth(rng), "access": benign_access(rng),
            "description": "Benign baseline only.", "expected_rules": []}


def build_s5(rng):
    auth, access = benign_auth(rng), benign_access(rng)
    t = at(10, 5, 0)
    # 1. One mistyped password, then success (normal user behaviour).
    auth.append(auth_event(t, "sshd",
        "Failed password for bob from 10.0.1.14 port 50001 ssh2", 3400))
    auth.append(auth_event(t + timedelta(seconds=8), "sshd",
        "Accepted password for bob from 10.0.1.14 port 50002 ssh2", 3401))
    # 2. Daytime admin sudo after a normal login.
    auth.append(auth_event(t + timedelta(minutes=2), "sudo",
        "bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"))
    # 3. Legitimate large backup download.
    access.append(access_event(at(14, 0, 0), "10.0.1.50", "GET",
        "/backups/nightly-2026-10-28.tar.gz", 200, 31_457_280, "rsync-backup/1.0"))
    # 4. Harmless URL that contains the word "select".
    access.append(access_event(at(15, 30, 0), "10.0.2.33", "GET",
        "/shop?sort=select-price", 200, 4200, AGENTS[0]))
    return {"auth": auth, "access": access,
            "description": "Hard negatives: typo then login, daytime sudo, backup download, "
                           "harmless 'select' URL. Ground truth: nothing malicious.",
            "expected_rules": []}


SCENARIOS = {
    "S1": (101, build_s1),
    "S1_mitigated": (101, lambda rng: build_s1(rng, mitigated=True)),
    "S2": (102, build_s2),
    "S3": (103, build_s3),
    "S4": (104, build_s4),
    "S5": (105, build_s5),
}


def write_scenario(name, scenario, out_root=DATA_DIR):
    out = Path(out_root) / name
    out.mkdir(parents=True, exist_ok=True)
    for stale in STALE_OUTPUTS:
        (out / stale).unlink(missing_ok=True)
    suspicious, all_ids = [], []
    for filename, events, start in (("auth.log", scenario["auth"], AUTH_ID_START),
                                    ("access.log", scenario["access"], ACCESS_ID_START)):
        lines = []
        for offset, event in enumerate(sorted(events, key=lambda e: e["time"])):
            line_id = f"L{start + offset:04d}"
            evidence_id = f"{filename}:{line_id}"
            lines.append(f"{line_id} {event['text']}")
            all_ids.append(evidence_id)
            if event["malicious"]:
                suspicious.append(evidence_id)
        (out / filename).write_text("\n".join(lines) + "\n", encoding="utf-8")
    truth = {"scenario": name, "description": scenario["description"],
             "expected_rules": scenario["expected_rules"],
             "suspicious_evidence_ids": suspicious, "all_evidence_ids": all_ids}
    (out / "ground_truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    return len(all_ids), len(suspicious)


def generate_all(out_root=DATA_DIR, names=None):
    for name in names or SCENARIOS:
        seed, builder = SCENARIOS[name]
        total, bad = write_scenario(name, builder(random.Random(seed)), out_root)
        print(f"{name}: {total} lines, {bad} labelled suspicious")


if __name__ == "__main__":
    generate_all(names=sys.argv[1:] or None)