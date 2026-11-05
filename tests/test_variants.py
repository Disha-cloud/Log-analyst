import json
import tempfile
import unittest
from pathlib import Path

from generator.generate_logs import generate_variants
from parser.correlator import correlate
from parser.log_parser import parse_scenario

N = 12


class VariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        generate_variants(N, cls.root)
        cls.dirs = sorted(p for p in cls.root.iterdir() if p.is_dir())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def truth(self, d):
        return json.loads((d / "ground_truth.json").read_text())

    def test_counts(self):
        self.assertEqual(len(self.dirs), 3 * N)

    def test_same_ground_truth_format_as_fixed_scenarios(self):
        for d in self.dirs:
            t = self.truth(d)
            for key in ("scenario", "description", "expected_rules",
                        "suspicious_evidence_ids", "all_evidence_ids"):
                self.assertIn(key, t, d.name)
            self.assertEqual(t["scenario"], d.name)
            self.assertTrue(set(t["suspicious_evidence_ids"]) <= set(t["all_evidence_ids"]), d.name)
            self.assertTrue(t["suspicious_evidence_ids"], d.name)

    def test_rules_match_labels(self):
        """Every variant is a valid instance: expected rules fire, and the lines the rules
        cite are exactly the labelled suspicious lines."""
        for d in self.dirs:
            records, errors = parse_scenario(d)
            self.assertEqual(errors, [], d.name)
            findings = correlate(records)
            t = self.truth(d)
            self.assertEqual({f["rule_id"] for f in findings}, set(t["expected_rules"]), d.name)
            self.assertEqual({e for f in findings for e in f["evidence_ids"]},
                             set(t["suspicious_evidence_ids"]), d.name)

    def test_reproducible(self):
        with tempfile.TemporaryDirectory() as other:
            generate_variants(N, other)
            for d in self.dirs:
                for fname in ("auth.log", "access.log", "ground_truth.json"):
                    self.assertEqual((d / fname).read_text(), (Path(other) / d.name / fname).read_text(),
                                     f"{d.name}/{fname}")

    def test_parameters_actually_vary(self):
        manifest = json.loads((self.root / "manifest.json").read_text())
        for base in ("S1", "S2", "S3"):
            rows = [m for m in manifest if m["variant_of"] == base]
            self.assertEqual(len({m["seed"] for m in rows}), N)
            self.assertGreater(len({m["params"]["attacker_ip"] for m in rows}), N // 2)
        s1 = [m["params"] for m in manifest if m["variant_of"] == "S1"]
        self.assertGreater(len({p["failures"] for p in s1}), 3)
        self.assertGreater(len({p["target_user"] for p in s1}), 2)
        self.assertGreater(len({p["login_time"] for p in s1}), N // 2)


if __name__ == "__main__":
    unittest.main()
