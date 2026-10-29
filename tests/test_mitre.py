import unittest

from validator.claim_validator import check_mitre, verify_claim

FAIL = "L0001 Oct 28 02:14:00 web01 sshd[3100]: Failed password for admin from 10.0.5.23 port 51100 ssh2"
LOGIN = "L0002 Oct 28 03:14:00 web01 sshd[3300]: Accepted password for carol from 10.0.7.77 port 52211 ssh2"
LOGS = {"auth.log:L0001": FAIL, "auth.log:L0002": LOGIN}


class MitreTests(unittest.TestCase):
    def test_exact_match(self):
        self.assertEqual(check_mitre("authentication_attempt", "T1110")["status"], "match")

    def test_subtechnique_of_expected_parent_lowercase(self):
        self.assertEqual(check_mitre("authentication_attempt", "t1110.004")["status"], "match")

    def test_parent_of_expected_subtechnique(self):
        self.assertEqual(check_mitre("privileged_activity", "T1548")["status"], "match")

    def test_wrong_technique(self):
        self.assertEqual(check_mitre("authentication_attempt", "T1190")["status"], "mismatch")

    def test_malformed(self):
        self.assertEqual(check_mitre("exploitation_attempt", "SQL injection")["status"], "malformed")

    def test_missing(self):
        self.assertEqual(check_mitre("exploitation_attempt", "unknown")["status"], "missing")
        self.assertEqual(check_mitre("exploitation_attempt", None)["status"], "missing")

    def test_mitre_does_not_change_evidence_status(self):
        result = verify_claim({"stage": "authentication_attempt", "explanation": "x",
                               "evidence_ids": ["auth.log:L0001"], "mitre_id": "T1190"}, LOGS)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["mitre_check"]["status"], "mismatch")

    def test_brute_force_id_rejected_for_login_without_failures(self):
        result = verify_claim({"stage": "successful_authentication", "explanation": "x",
                               "evidence_ids": ["auth.log:L0002"], "mitre_id": "T1110"}, LOGS)
        self.assertEqual(result["mitre_check"]["status"], "mismatch")

    def test_brute_force_id_accepted_for_login_after_failures(self):
        result = verify_claim({"stage": "successful_authentication", "explanation": "x",
                               "evidence_ids": ["auth.log:L0001", "auth.log:L0002"], "mitre_id": "T1110"}, LOGS)
        self.assertEqual(result["mitre_check"]["status"], "match")


if __name__ == "__main__":
    unittest.main()
