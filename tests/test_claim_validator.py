import unittest

from validator.claim_validator import check_summary, identify_claim_type, verify_claim

LOGS = {
    "auth.log:L0001": "L0001 Oct 28 02:14:00 web01 sshd[3100]: Failed password for admin from 10.0.5.23 port 51100 ssh2",
    "auth.log:L0002": "L0002 Oct 28 02:14:45 web01 sshd[3150]: Accepted password for admin from 10.0.5.23 port 51130 ssh2",
    "auth.log:L0003": "L0003 Oct 28 02:16:45 web01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
    "access.log:L5001": 'L5001 10.0.5.23 - - [28/Oct/2026:02:20:00 +0000] "GET /exports/customers_full.csv HTTP/1.1" 200 52428800 "-" "python-requests/2.31"',
    "access.log:L5002": 'L5002 10.0.6.66 - - [28/Oct/2026:11:20:00 +0000] "GET /products.php?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 500 312 "-" "sqlmap/1.7"',
}


def claim(stage, ids, explanation="x"):
    return {"stage": stage, "explanation": explanation, "evidence_ids": ids}


class ClaimValidatorTests(unittest.TestCase):
    def status(self, c, logs=LOGS):
        return verify_claim(c, logs)["status"]

    def test_valid_brute_force_verified(self):
        self.assertEqual(self.status(claim("authentication_attempt", ["auth.log:L0001"])), "verified")

    def test_nonexistent_id_unverified(self):
        self.assertEqual(self.status(claim("authentication_attempt", ["auth.log:L9999"])), "unverified")

    def test_wrong_line_type_unverified(self):
        self.assertEqual(self.status(claim("authentication_attempt", ["auth.log:L0002"])), "unverified")

    def test_empty_evidence_unverified(self):
        self.assertEqual(self.status(claim("successful_authentication", [])), "unverified")

    def test_unknown_stage_unverified(self):
        self.assertEqual(self.status(claim("cosmic_event", ["auth.log:L0001"], "reality changed")), "unverified")

    def test_privileged_stage_beats_login_wording(self):
        c = claim("privileged_activity", ["auth.log:L0003"], "Sudo after the successful login.")
        self.assertEqual(identify_claim_type(c), "privileged_activity")
        self.assertEqual(self.status(c), "verified")

    def test_bare_id_resolves(self):
        self.assertEqual(self.status(claim("authentication_attempt", ["L0001"])), "verified")

    def test_unpadded_id_resolves(self):
        self.assertEqual(self.status(claim("authentication_attempt", ["auth.log:L1"])), "verified")

    def test_ambiguous_bare_id_unverified(self):
        logs = {"auth.log:L0001": LOGS["auth.log:L0001"],
                "access.log:L0001": LOGS["access.log:L5001"]}
        self.assertEqual(self.status(claim("authentication_attempt", ["L0001"]), logs), "unverified")

    def test_mixed_valid_invalid_unverified(self):
        self.assertEqual(self.status(claim("authentication_attempt",
                                           ["auth.log:L0001", "auth.log:L9999"])), "unverified")

    def test_correlation_both_sides_verified(self):
        self.assertEqual(self.status(claim("correlated_events",
                                           ["auth.log:L0002", "access.log:L5001"])), "verified")

    def test_correlation_one_side_unverified(self):
        self.assertEqual(self.status(claim("correlated_events", ["auth.log:L0002"])), "unverified")

    def test_sql_injection_verified(self):
        self.assertEqual(self.status(claim("exploitation_attempt", ["access.log:L5002"])), "verified")

    def test_success_claim_with_failures_and_success_verified(self):
        self.assertEqual(self.status(claim("successful_authentication",
                                           ["auth.log:L0001", "auth.log:L0002"])), "verified")

    def test_success_claim_with_only_failures_unverified(self):
        self.assertEqual(self.status(claim("successful_authentication", ["auth.log:L0001"])), "unverified")

    def test_privileged_claim_with_login_and_sudo_verified(self):
        self.assertEqual(self.status(claim("privileged_activity",
                                           ["auth.log:L0002", "auth.log:L0003"])), "verified")

    def test_summary_fake_id_flagged(self):
        results = check_summary("Attack seen at auth.log:L0001 and L9999.", LOGS)
        self.assertEqual([r["status"] for r in results], ["pass", "fail"])


if __name__ == "__main__":
    unittest.main()
