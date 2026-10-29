import tempfile
import unittest
from pathlib import Path

from generator.generate_logs import generate_all
from parser.correlator import correlate
from parser.log_parser import LOG_YEAR, parse_scenario


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        generate_all(Path(cls.tmp.name))
        cls.results = {}
        for d in sorted(Path(cls.tmp.name).iterdir()):
            records, errors = parse_scenario(d)
            cls.results[d.name] = (records, errors, correlate(records))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def rules(self, name):
        return [f["rule_id"] for f in self.results[name][2]]

    def test_no_parse_errors(self):
        for name, (_, errors, _) in self.results.items():
            self.assertEqual(errors, [], name)

    def test_timestamps_use_log_year(self):
        for records, _, _ in self.results.values():
            self.assertTrue(all(r["timestamp"].year == LOG_YEAR for r in records))

    def test_s1_full_chain(self):
        for rule in ("ssh_brute_force", "failure_then_success", "login_then_sudo"):
            self.assertIn(rule, self.rules("S1"))

    def test_s1_no_duplicate_failure_then_success(self):
        self.assertEqual(self.rules("S1").count("failure_then_success"), 1)

    def test_s2_web_indicators(self):
        self.assertEqual(self.rules("S2").count("sql_injection_indicator"), 2)
        self.assertEqual(self.rules("S2").count("path_traversal_indicator"), 2)

    def test_s3_correlation_fires(self):
        self.assertIn("correlated_events", self.rules("S3"))

    def test_s4_benign_has_no_findings(self):
        self.assertEqual(self.rules("S4"), [])

    def test_s5_hard_negatives_no_high_severity(self):
        self.assertTrue(all(f["severity"] != "high" for f in self.results["S5"][2]))

    def test_mitigation_breaks_chain(self):
        rules = self.rules("S1_mitigated")
        self.assertIn("ssh_brute_force", rules)
        self.assertNotIn("failure_then_success", rules)
        self.assertNotIn("login_then_sudo", rules)


if __name__ == "__main__":
    unittest.main()