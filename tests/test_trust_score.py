import unittest

from scoring.trust_score import WEIGHTS, band, compute_trust


def finding(rule_id):
    return {"rule_id": rule_id}


def validation(total, verified, mitre):
    return {"total_claims": total, "verified_claims": verified, "mitre_match": mitre}


class TrustScoreTests(unittest.TestCase):
    def test_weights_sum_to_one(self):
        self.assertAlmostEqual(sum(WEIGHTS.values()), 1.0)

    def test_known_value_s1_like(self):
        # rules: .90 .85 .60 .80 -> mean .7875 ; verified 3/3 ; mitre 2/3
        rules = ["ssh_brute_force", "failure_then_success", "unusual_hour_login", "login_then_sudo"]
        t = compute_trust([finding(r) for r in rules], validation(3, 3, 2))
        self.assertEqual(t["score"], 85)           # 31.5 + 40 + 13.33 = 84.83
        self.assertEqual(t["band"], "high")
        self.assertEqual([c["key"] for c in t["components"]],
                         ["rule_confidence", "claims_verified", "mitre_match"])
        self.assertAlmostEqual(sum(c["points"] for c in t["components"]), 84.83, places=1)

    def test_perfect_and_worst(self):
        best = compute_trust([finding("ssh_brute_force")], validation(2, 2, 2))
        self.assertEqual(best["score"], 96)        # .9*40 + 40 + 20
        worst = compute_trust([finding("large_data_transfer")], validation(2, 0, 0))
        self.assertEqual(worst["score"], 20)       # only rule confidence .5 * 40
        self.assertEqual(worst["band"], "low")

    def test_distinct_rules_not_findings(self):
        one = compute_trust([finding("ssh_brute_force")], validation(1, 1, 1))["score"]
        many = compute_trust([finding("ssh_brute_force")] * 9, validation(1, 1, 1))["score"]
        self.assertEqual(one, many)

    def test_unknown_rule_gets_default(self):
        t = compute_trust([finding("brand_new_rule")], validation(1, 1, 1))
        self.assertEqual(t["score"], 80)           # .5*40 + 40 + 20

    def test_not_computable_cases_return_none_with_reason(self):
        for rf, val in (([], validation(1, 1, 1)),                 # no findings
                        ([finding("ssh_brute_force")], None),      # validator not run
                        ([finding("ssh_brute_force")], validation(0, 0, 0))):  # no claims
            t = compute_trust(rf, val)
            self.assertIsNone(t["score"])
            self.assertTrue(t["reason"])

    def test_bands(self):
        self.assertEqual([band(s) for s in (100, 80, 79, 60, 59, 0)],
                         ["high", "high", "moderate", "moderate", "low", "low"])


if __name__ == "__main__":
    unittest.main()
