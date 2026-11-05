import unittest
from datetime import datetime, timedelta

from parser.correlator import correlate
from parser.log_parser import parse_auth_line

T0 = datetime(2026, 11, 5, 10, 0, 0)


def rec(n, secs, msg, pid=100):
    ts = (T0 + timedelta(seconds=secs)).strftime("%b %e %H:%M:%S")
    r, err = parse_auth_line(f"{ts} h sshd[{pid}]: {msg}", n)
    assert err is None, err
    return r


def failed(n, secs, user, ip, invalid=False):
    return rec(n, secs, f"Failed password for {'invalid user ' if invalid else ''}{user} from {ip} port 1 ssh2", pid=n)


def rules(records):
    return {f["rule_id"]: f for f in correlate(records)}


class InvalidUserParsing(unittest.TestCase):
    def test_parsed_with_ip_and_user(self):
        r = rec(1, 0, "Invalid user oracle from 203.0.113.77 port 60110")
        self.assertEqual((r["event_type"], r["ip"], r["user"]), ("invalid_user", "203.0.113.77", "oracle"))

    def test_followup_line_not_counted_twice(self):
        r = rec(1, 0, "input_userauth_request: invalid user oracle [preauth]")
        self.assertEqual(r["event_type"], "other_auth_event")


class UsernameSpraying(unittest.TestCase):
    def test_fires_on_slow_multi_account_guessing(self):
        rs = [failed(1, 0, "guest", "9.9.9.9", True), failed(2, 4, "guest", "9.9.9.9", True),
              failed(3, 8, "admin", "9.9.9.9", True), failed(4, 12, "root", "9.9.9.9")]
        f = rules(rs)["username_spraying"]
        self.assertEqual((f["mitre_id"], f["ip"], len(f["evidence_ids"])), ("T1110.003", "9.9.9.9", 4))
        self.assertNotIn("ssh_brute_force", rules(rs))   # only 4 failures: below the brute-force threshold

    def test_single_user_not_spraying(self):
        rs = [failed(i, i * 5, "alice", "9.9.9.9") for i in range(1, 5)]
        self.assertNotIn("username_spraying", rules(rs))

    def test_spread_over_more_than_ten_minutes_not_spraying(self):
        rs = [failed(1, 0, "a", "9.9.9.9"), failed(2, 400, "b", "9.9.9.9"),
              failed(3, 800, "c", "9.9.9.9"), failed(4, 1200, "d", "9.9.9.9")]
        self.assertNotIn("username_spraying", rules(rs))

    def test_counts_invalid_user_lines(self):
        rs = [rec(i, i, f"Invalid user u{i} from 8.8.8.8 port 1", pid=i) for i in range(1, 5)]
        self.assertIn("username_spraying", rules(rs))


class AuthAttemptsExhausted(unittest.TestCase):
    def test_fires_and_severity_grows(self):
        one = [rec(1, 0, "error: maximum authentication attempts exceeded for root from 7.7.7.7 port 1 ssh2 [preauth]")]
        self.assertEqual(rules(one)["auth_attempts_exhausted"]["severity"], "medium")
        three = [rec(i, i * 60, "error: maximum authentication attempts exceeded for root from 7.7.7.7 port 1 ssh2 [preauth]")
                 for i in range(1, 4)]
        self.assertEqual(rules(three)["auth_attempts_exhausted"]["severity"], "high")

    def test_no_ip_no_finding(self):
        self.assertEqual(rules([rec(1, 0, "Disconnecting: Too many authentication failures for root [preauth]", pid=1)]), {})


class ProbeThenSuccess(unittest.TestCase):
    def accepted(self, n, secs, user, ip):
        return rec(n, secs, f"Accepted password for {user} from {ip} port 1 ssh2", pid=n)

    def test_two_accounts_guessed_then_success(self):
        rs = [failed(1, 0, "guest", "6.6.6.6", True), failed(2, 5, "admin", "6.6.6.6", True), self.accepted(3, 20, "deploy", "6.6.6.6")]
        f = rules(rs)["probe_then_success"]
        self.assertEqual((f["ip"], f["user"], f["mitre_id"]), ("6.6.6.6", "deploy", "T1078"))

    def test_single_user_typo_is_not_flagged(self):
        rs = [failed(1, 0, "alice", "6.6.6.6"), failed(2, 5, "alice", "6.6.6.6"), self.accepted(3, 20, "alice", "6.6.6.6")]
        self.assertEqual(rules(rs), {})

    def test_three_or_more_failures_left_to_existing_rule(self):
        rs = [failed(i, i, "guest", "6.6.6.6", True) for i in range(1, 4)] + [self.accepted(4, 20, "deploy", "6.6.6.6")]
        self.assertIn("failure_then_success", rules(rs))
        self.assertNotIn("probe_then_success", rules(rs))


if __name__ == "__main__":
    unittest.main()
