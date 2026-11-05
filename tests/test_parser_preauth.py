import tempfile
import unittest
from pathlib import Path

from parser.log_parser import parse_auth_line, parse_file


def parse(msg, pid=2000, ts="Nov  5 10:04:32"):
    rec, err = parse_auth_line(f"{ts} h sshd[{pid}]: {msg}", 1)
    assert err is None, err
    return rec


class PreauthParsingTests(unittest.TestCase):
    def check(self, msg, event, ip, user):
        r = parse(msg)
        self.assertEqual((r["event_type"], r["ip"], r["user"]), (event, ip, user), msg)

    def test_connection_closed_variants(self):
        self.check("Connection closed by 203.0.113.99 port 39001 [preauth]", "preauth_disconnect", "203.0.113.99", None)
        self.check("Connection closed by authenticating user root 198.51.100.23 port 40223 [preauth]",
                   "preauth_disconnect", "198.51.100.23", "root")
        self.check("Connection closed by invalid user bob 10.0.0.5 port 22 [preauth]", "preauth_disconnect", "10.0.0.5", "bob")
        self.check("Disconnected from authenticating user root 1.2.3.4 port 5 [preauth]", "preauth_disconnect", "1.2.3.4", "root")
        self.check("Connection reset by 1.2.3.4 port 5 [preauth]", "preauth_disconnect", "1.2.3.4", None)

    def test_received_disconnect_preauth(self):
        self.check("Received disconnect from 5.6.7.8: 11: Bye Bye [preauth]", "preauth_disconnect", "5.6.7.8", None)
        self.check("error: Received disconnect from 5.6.7.8 port 99:14: No more user authentication methods "
                   "available. [preauth]", "preauth_disconnect", "5.6.7.8", None)

    def test_idle_handshake(self):
        self.check("Did not receive identification string from 9.9.9.9", "preauth_disconnect", "9.9.9.9", None)

    def test_post_login_disconnect_is_not_preauth(self):
        self.check("Received disconnect from 192.0.2.10 port 51120:11: disconnected by user",
                   "other_auth_event", None, None)

    def test_max_auth_attempts(self):
        self.check("error: maximum authentication attempts exceeded for root from 203.0.113.99 port 39005 ssh2 [preauth]",
                   "max_auth_attempts", "203.0.113.99", "root")
        self.check("error: maximum authentication attempts exceeded for invalid user admin from 1.1.1.1 port 7 ssh2 [preauth]",
                   "max_auth_attempts", "1.1.1.1", "admin")
        self.check("Disconnecting: Too many authentication failures for root [preauth]", "max_auth_attempts", None, "root")
        self.check("Disconnecting authenticating user root 1.2.3.4 port 5: Too many authentication failures [preauth]",
                   "max_auth_attempts", "1.2.3.4", "root")

    def test_existing_event_types_unchanged(self):
        self.check("Failed password for invalid user guest from 1.2.3.4 port 5 ssh2", "failed_authentication", "1.2.3.4", "guest")
        self.check("Accepted password for deploy from 1.2.3.4 port 5 ssh2", "successful_authentication", "1.2.3.4", "deploy")

    def test_missing_ip_inferred_from_same_pid_and_flagged(self):
        lines = ["Nov  5 10:00:00 h sshd[77]: Failed password for root from 4.4.4.4 port 1 ssh2",
                 "Nov  5 10:00:03 h sshd[77]: Disconnecting: Too many authentication failures for root [preauth]",
                 "Nov  5 10:00:04 h sshd[88]: Disconnecting: Too many authentication failures for root [preauth]",
                 "Nov  5 11:00:04 h sshd[77]: Disconnecting: Too many authentication failures for root [preauth]"]
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "auth.log"
            f.write_text("\n".join(lines))
            recs, _ = parse_file(f)
        self.assertEqual([(r["ip"], r["ip_source"]) for r in recs],
                         [("4.4.4.4", "line"), ("4.4.4.4", "pid"), (None, None), (None, None)])


if __name__ == "__main__":
    unittest.main()
