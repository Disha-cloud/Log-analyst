import unittest
from datetime import datetime, timedelta

from parser.correlator import correlate
from parser.log_parser import parse_auth_line

T0 = datetime(2026, 11, 5, 0, 0, 0)


def rec(n, secs, msg, proc="sshd"):
    ts = (T0 + timedelta(seconds=secs)).strftime("%b %e %H:%M:%S")
    r, err = parse_auth_line(f"{ts} h {proc}[{n}]: {msg}" if proc == "sshd" else f"{ts} h {proc}: {msg}", n)
    assert err is None, err
    return r


def failed(n, secs, ip, user="alice"):
    return rec(n, secs, f"Failed password for {user} from {ip} port 1 ssh2")


def rules(records):
    out = {}
    for f in correlate(records):
        out.setdefault(f["rule_id"], []).append(f)
    return out


class SlowBruteForce(unittest.TestCase):
    def test_hourly_guessing_flagged(self):
        rs = [failed(i, i * 3600, "7.7.7.7", f"u{i}") for i in range(1, 6)]   # one per hour, 5 users
        f = rules(rs)["slow_brute_force"][0]
        self.assertEqual((f["ip"], f["severity"], f["mitre_id"], len(f["evidence_ids"])), ("7.7.7.7", "medium", "T1110.001", 5))

    def test_four_attempts_not_enough(self):
        self.assertNotIn("slow_brute_force", rules([failed(i, i * 3600, "7.7.7.7") for i in range(1, 5)]))

    def test_spread_over_more_than_24h_not_flagged(self):
        self.assertNotIn("slow_brute_force", rules([failed(i, i * 8 * 3600, "7.7.7.7") for i in range(1, 6)]))

    def test_ip_that_logged_in_is_left_alone(self):
        rs = [failed(i, i * 3600, "7.7.7.7") for i in range(1, 6)]
        rs.append(rec(9, 6 * 3600, "Accepted password for alice from 7.7.7.7 port 1 ssh2"))
        self.assertNotIn("slow_brute_force", rules(rs))

    def test_burst_already_reported_as_brute_force_not_duplicated(self):
        rs = [failed(i, i, "7.7.7.7") for i in range(1, 8)]
        r = rules(rs)
        self.assertIn("ssh_brute_force", r)
        self.assertNotIn("slow_brute_force", r)

    def test_occasional_typos_over_a_week_not_flagged(self):
        self.assertNotIn("slow_brute_force", rules([failed(i, i * 2 * 86400, "7.7.7.7") for i in range(1, 4)]))


class DeniedSudo(unittest.TestCase):
    DENIED = "{u} : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND={c}"

    def test_denied_is_not_privileged_activity(self):
        r = rec(1, 0, self.DENIED.format(u="mallory", c="/bin/ls"), proc="sudo")
        self.assertEqual((r["event_type"], r["user"], r["command"]), ("sudo_denied", "mallory", "/bin/ls"))

    def test_successful_sudo_unchanged(self):
        r = rec(1, 0, "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update", proc="sudo")
        self.assertEqual(r["event_type"], "privileged_activity")

    def test_other_denial_forms(self):
        for msg in ("bob : command not allowed ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/su",
                    "bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"):
            self.assertEqual(rec(1, 0, msg, proc="sudo")["event_type"], "sudo_denied", msg)

    def test_sensitive_file_is_high_plain_command_is_medium(self):
        hi = rules([rec(1, 0, self.DENIED.format(u="m", c="/usr/bin/cat /etc/shadow"), proc="sudo")])["denied_sudo"][0]
        self.assertEqual((hi["severity"], hi["mitre_id"], hi["user"]), ("high", "T1548.003", "m"))
        lo = rules([rec(1, 0, self.DENIED.format(u="m", c="/bin/ls /tmp"), proc="sudo")])["denied_sudo"][0]
        self.assertEqual(lo["severity"], "medium")

    def test_three_retries_in_an_hour_is_high_and_one_finding(self):
        rs = [rec(i, i * 60, self.DENIED.format(u="m", c="/bin/ls"), proc="sudo") for i in range(1, 4)]
        f = rules(rs)["denied_sudo"]
        self.assertEqual((len(f), f[0]["severity"], len(f[0]["evidence_ids"])), (1, "high", 3))

    def test_separate_days_are_separate_findings(self):
        rs = [rec(1, 0, self.DENIED.format(u="m", c="/bin/ls"), proc="sudo"),
              rec(2, 86400, self.DENIED.format(u="m", c="/bin/ls"), proc="sudo")]
        self.assertEqual(len(rules(rs)["denied_sudo"]), 2)

    def test_denied_sudo_does_not_trigger_login_then_sudo(self):
        rs = [rec(1, 3 * 3600, "Accepted password for mallory from 1.1.1.1 port 1 ssh2"),
              rec(2, 3 * 3600 + 30, self.DENIED.format(u="mallory", c="/bin/ls"), proc="sudo")]
        self.assertNotIn("login_then_sudo", rules(rs))


if __name__ == "__main__":
    unittest.main()
