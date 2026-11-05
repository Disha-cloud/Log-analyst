import unittest

from validator.claim_validator import (check_contradiction, check_stage_coverage,
                                       check_summary_contradiction, find_dismissals)


def f(rule_id):
    return {"rule_id": rule_id}


class ContradictionTests(unittest.TestCase):
    def test_phrases_found(self):
        self.assertEqual(find_dismissals("This was marked as a False Positive; do not flag it."),
                         ["false positive", "do not flag"])
        self.assertIn("not malicious", find_dismissals("The login is not malicious."))
        self.assertIn("authorized", find_dismissals("The sudo use is authorized."))

    def test_unauthorized_and_plain_text_not_flagged(self):
        self.assertEqual(find_dismissals("Unauthorized access via brute force succeeded."), [])
        self.assertEqual(find_dismissals("Six failed logins then a success at 02:30."), [])
        self.assertEqual(find_dismissals(None), [])

    def test_claim_contradicts_fired_rule(self):
        r = check_contradiction("privileged_activity", "Sudo use is authorized.", {"login_then_sudo"})
        self.assertEqual(r["rules_fired"], ["login_then_sudo"])

    def test_no_flag_when_rule_did_not_fire_for_that_stage(self):
        self.assertIsNone(check_contradiction("privileged_activity", "Sudo use is authorized.",
                                              {"ssh_brute_force"}))

    def test_summary_contradiction(self):
        self.assertIsNotNone(check_summary_contradiction("marked as a false positive", {"ssh_brute_force"}))
        self.assertIsNone(check_summary_contradiction("marked as a false positive", set()))
        self.assertIsNone(check_summary_contradiction("brute force attack", {"ssh_brute_force"}))


class CoverageTests(unittest.TestCase):
    RULES = [f("ssh_brute_force"), f("failure_then_success"), f("unusual_hour_login"), f("login_then_sudo")]

    def test_distinct_stages_not_findings(self):
        r = check_stage_coverage(self.RULES, [])
        self.assertEqual(r["rule_stage_count"], 3)   # two rules share successful_authentication

    def test_under_reported(self):
        claims = [{"claim_type": "authentication_attempt"}, {"claim_type": "successful_authentication"}]
        r = check_stage_coverage(self.RULES, claims)
        self.assertEqual(r["status"], "UNDER-REPORTED")
        self.assertEqual(r["missing_stages"], ["privileged_activity"])
        self.assertEqual((r["claim_stages_covered"], r["rule_stage_count"]), (2, 3))

    def test_full_coverage_ok(self):
        claims = [{"claim_type": t} for t in
                  ("authentication_attempt", "successful_authentication", "privileged_activity")]
        self.assertEqual(check_stage_coverage(self.RULES, claims)["status"], "ok")

    def test_no_rules_no_gap(self):
        self.assertEqual(check_stage_coverage([], [])["status"], "ok")

    def test_empty_attack_chain_is_caught(self):
        self.assertEqual(check_stage_coverage(self.RULES, [])["status"], "UNDER-REPORTED")


if __name__ == "__main__":
    unittest.main()
