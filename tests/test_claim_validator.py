
import unittest

from validator.claim_validator import verify_claim


class TestClaimValidator(unittest.TestCase):

    def test_valid_brute_force_evidence_passes(self):
        claim = {
            "stage": "authentication_attempt",
            "explanation": "Repeated failed SSH password attempts indicate brute force.",
            "evidence_ids": ["auth.log:L0501"],
        }

        logs = {
            "auth.log:L0501":
                "L0501 Oct 28 11:40:00 web01 sshd[2211]: "
                "Failed password for root from 10.0.5.23 port 51122 ssh2"
        }

        result = verify_claim(claim, logs)

        self.assertEqual(result["status"], "verified")

    def test_nonexistent_evidence_id_is_flagged(self):
        claim = {
            "stage": "authentication_attempt",
            "explanation": "Repeated failed SSH password attempts indicate brute force.",
            "evidence_ids": ["auth.log:L9999"],
        }

        logs = {
            "auth.log:L0501":
                "L0501 Oct 28 11:40:00 web01 sshd[2211]: "
                "Failed password for root from 10.0.5.23 port 51122 ssh2"
        }

        result = verify_claim(claim, logs)

        self.assertEqual(result["status"], "unverified")
        self.assertIn(
            "does not exist",
            result["evidence_checks"][0]["reason"],
        )

    def test_wrong_event_line_is_flagged(self):
        claim = {
            "stage": "authentication_attempt",
            "explanation": "This line proves a brute-force attempt.",
            "evidence_ids": ["auth.log:L0507"],
        }

        logs = {
            "auth.log:L0507":
                "L0507 Oct 28 11:40:15 web01 sshd[2230]: "
                "Accepted password for root from 10.0.5.23 port 51130 ssh2"
        }

        result = verify_claim(claim, logs)

        self.assertEqual(result["status"], "unverified")

    def test_missing_evidence_is_flagged(self):
        claim = {
            "stage": "authentication_attempt",
            "explanation": "Brute-force attempt.",
            "evidence_ids": [],
        }

        result = verify_claim(claim, {})

        self.assertEqual(result["status"], "unverified")
        self.assertIn("No evidence IDs", result["reason"])

    def test_unsupported_claim_type_is_flagged(self):
        claim = {
            "stage": "unknown_event",
            "explanation": "An unexplained event happened.",
            "evidence_ids": ["auth.log:L0501"],
        }

        logs = {
            "auth.log:L0501": "Some log text"
        }

        result = verify_claim(claim, logs)

        self.assertEqual(result["status"], "unverified")


if __name__ == "__main__":
    unittest.main()
