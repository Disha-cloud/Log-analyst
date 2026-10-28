
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

random.seed(42)

HOST = "web01"
PRIVATE_IPS = [
    "10.0.1.12",
    "10.0.2.18",
    "10.0.3.25",
    "10.0.5.23",
    "10.0.8.41",
]

USERS = ["alice", "bob", "charlie", "david", "emma"]
NORMAL_PATHS = [
    "/",
    "/index.html",
    "/login",
    "/dashboard",
    "/products",
    "/about",
    "/contact",
    "/assets/style.css",
    "/favicon.ico",
]

BASE_TIME = datetime(2026, 10, 28, 10, 0, 0)


def timestamp(offset_minutes=0, offset_seconds=0):
    """Return a timestamp relative to the scenario's base time."""
    dt = BASE_TIME + timedelta(
        minutes=offset_minutes,
        seconds=offset_seconds,
    )
    return dt.strftime("%b %d %H:%M:%S")


def apache_timestamp(dt):
    """Return an Apache-style timestamp."""
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def make_auth(message, line_id, time_offset=0):
    """Create a Linux authentication log line."""
    return (
        f"L{line_id:04d} {timestamp(offset_seconds=time_offset)} "
        f"{HOST} {message}"
    )


def seconds_offset(value):
    """Keep time offsets explicit when creating auth entries."""
    return value


def make_apache(ip, method, path, status, size, line_id, seconds=0):
    """Create an Apache combined-format access log line."""
    dt = BASE_TIME + timedelta(seconds=seconds)
    return (
        f"L{line_id:04d} {ip} - - "
        f"[{apache_timestamp(dt)}] "
        f'"{method} {path} HTTP/1.1" '
        f'{status} {size} "-" '
        '"Mozilla/5.0 (compatible; LogAnalystTest/1.0)"'
    )


def normal_auth(line_id, seconds):
    """Generate a benign authentication event."""
    user = random.choice(USERS)
    ip = random.choice(PRIVATE_IPS)
    port = random.randint(40000, 60000)

    if random.random() < 0.75:
        message = (
            f"sshd[{random.randint(2000, 9000)}]: "
            f"Accepted publickey for {user} from {ip} "
            f"port {port} ssh2"
        )
    else:
        message = (
            f"CRON[{random.randint(1000, 9000)}]: "
            f"pam_unix(cron:session): session opened for user "
            f"{user}(uid={random.randint(1000, 1099)})"
        )

    return make_auth(message, line_id, seconds)


def normal_apache(line_id, seconds):
    """Generate a benign Apache request."""
    ip = random.choice(PRIVATE_IPS)
    path = random.choice(NORMAL_PATHS)
    method = random.choices(
        ["GET", "POST", "HEAD"],
        weights=[80, 18, 2],
    )[0]
    status = random.choices(
        [200, 301, 304, 404],
        weights=[85, 5, 7, 3],
    )[0]
    size = random.randint(200, 5000)

    return make_apache(
        ip, method, path, status, size, line_id, seconds
    )


def write_scenario(name, auth_lines, access_lines, labels):
    """Write log files and ground truth for one scenario."""
    output_dir = DATA_DIR / name
    output_dir.mkdir(parents=True, exist_ok=True)

    (output_dir / "auth.log").write_text(
        "\n".join(auth_lines) + "\n",
        encoding="utf-8",
    )

    (output_dir / "access.log").write_text(
        "\n".join(access_lines) + "\n",
        encoding="utf-8",
    )

    ground_truth = {
        "scenario": name,
        "description": SCENARIO_DESCRIPTIONS[name],
        "normal_line_count": 500,
        "malicious_line_ids": list(labels.keys()),
        "labels": [
            {
                "line_id": line_id,
                "attack_stage": stage,
            }
            for line_id, stage in labels.items()
        ],
    }

    (output_dir / "ground_truth.json").write_text(
        json.dumps(ground_truth, indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        f"{name}: "
        f"{len(auth_lines)} auth lines, "
        f"{len(access_lines)} access lines, "
        f"{len(labels)} labeled malicious lines"
    )


SCENARIO_DESCRIPTIONS = {
    "S1": "SSH brute force followed by successful login and sudo activity.",
    "S2": "Web requests containing SQL injection and path traversal patterns.",
    "S3": "Unusual-hour login followed by a large server response.",
    "S4": "Benign activity only; used to test false positives.",
}


def generate_s1():
    """SSH brute force, success, and privilege escalation."""
    auth, access, labels = [], [], {}
    line_id = 1

    # 500 normal authentication events.
    for i in range(500):
        auth.append(normal_auth(line_id, i * 11))
        line_id += 1

    # Repeated failed SSH attempts from one private IP.
    attacker_ip = "10.0.5.23"

    for i in range(6):
        auth.append(
            make_auth(
                f"sshd[{2211 + i}]: Failed password for root "
                f"from {attacker_ip} port {51122 + i} ssh2",
                line_id,
                6000 + i * 2,
            )
        )
        labels[f"L{line_id:04d}"] = "ssh_brute_force"
        line_id += 1

    # Successful login after repeated failures.
    auth.append(
        make_auth(
            f"sshd[2230]: Accepted password for root from "
            f"{attacker_ip} port 51130 ssh2",
            line_id,
            6015,
        )
    )
    labels[f"L{line_id:04d}"] = "successful_login_after_brute_force"
    line_id += 1

    # Suspicious privilege escalation.
    auth.append(
        make_auth(
            "sudo: pam_unix(sudo:session): session opened "
            "for user root by root(uid=0)",
            line_id,
            6020,
        )
    )
    labels[f"L{line_id:04d}"] = "privilege_escalation"
    line_id += 1

    write_scenario("S1", auth, access, labels)


def generate_s2():
    """SQL injection and path traversal requests."""
    auth, access, labels = [], [], {}
    line_id = 1

    # 500 normal Apache requests.
    for i in range(500):
        access.append(normal_apache(line_id, i * 3))
        line_id += 1

    attacks = [
        (
            "/login?username=admin%27%20OR%201%3D1--",
            400,
            "sql_injection",
        ),
        (
            "/products?id=1%20UNION%20SELECT%20NULL--",
            400,
            "sql_injection",
        ),
        (
            "/../../../../etc/passwd",
            400,
            "path_traversal",
        ),
        (
            "/download?file=..%2F..%2Fetc%2Fpasswd",
            200,
            "path_traversal_success_suspected",
        ),
    ]

    for i, (path, status, stage) in enumerate(attacks):
        access.append(
            make_apache(
                "10.0.5.23",
                "GET",
                path,
                status,
                1200 if status == 200 else 250,
                line_id,
                6000 + i * 3,
            )
        )
        labels[f"L{line_id:04d}"] = stage
        line_id += 1

    write_scenario("S2", auth, access, labels)


def generate_s3():
    """Odd-hour login followed by a large response."""
    auth, access, labels = [], [], {}
    line_id = 1

   
    for i in range(250):
        auth.append(normal_auth(line_id, i * 15))
        line_id += 1

    for i in range(250):
        access.append(normal_apache(line_id, i * 15))
        line_id += 1

    unusual_ip = "10.0.8.41"
    auth.append(
        "L%04d %s %s sshd[7712]: Accepted password for alice "
        "from %s port 52000 ssh2"
        % (
            line_id,
            "Oct 28 03:14:07",
            HOST,
            unusual_ip,
        )
    )
    labels[f"L{line_id:04d}"] = "unusual_hour_login"
    line_id += 1

   
    access.append(
        make_apache(
            unusual_ip,
            "GET",
            "/exports/archive.zip",
            200,
            50000000,
            line_id,
            6020,
        )
    )
    labels[f"L{line_id:04d}"] = "large_data_transfer_suspected"

    write_scenario("S3", auth, access, labels)


def generate_s4():
    """Benign-only scenario for false-positive testing."""
    auth, access, labels = [], [], {}
    line_id = 1

    for i in range(250):
        auth.append(normal_auth(line_id, i * 13))
        line_id += 1

    for i in range(250):
        access.append(normal_apache(line_id, i * 5))
        line_id += 1

   
    write_scenario("S4", auth, access, labels)


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    generate_s1()
    generate_s2()
    generate_s3()
    generate_s4()

    print(f"\nAll scenarios saved to: {DATA_DIR}")


if __name__ == "__main__":
    main()
