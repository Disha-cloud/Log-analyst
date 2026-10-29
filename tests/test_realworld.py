import tempfile
import unittest
from pathlib import Path

from generator.import_real import import_scenario
from llm.analyzer import MAX_EVIDENCE_PER_FINDING, MAX_FINDINGS_FOR_LLM, findings_for_llm
from parser.log_parser import load_raw_lines, parse_scenario

SAMPLE = """Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186
Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2
Dec 10 06:55:50 LabSZ sshd[24201]: Failed password for root from 10.0.0.9 port 4000 ssh2
"""


class RealWorldImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_public_ips_masked_private_kept(self):
        truth = import_scenario("REAL", auth_text=SAMPLE, out_root=self.root)
        text = (self.root / "REAL" / "auth.log").read_text()
        self.assertNotIn("173.234.31.186", text)
        self.assertEqual(text.count("10.200.0.2"), 2)
        self.assertIn("10.0.0.9", text)
        self.assertFalse(truth["labels_available"])
        self.assertEqual(truth["masked_ip_count"], 1)

    def test_no_mask_keeps_original(self):
        import_scenario("REAL", auth_text=SAMPLE, mask=False, out_root=self.root)
        self.assertIn("173.234.31.186", (self.root / "REAL" / "auth.log").read_text())

    def test_ids_added_and_parsed(self):
        import_scenario("REAL", auth_text=SAMPLE, out_root=self.root)
        records, errors = parse_scenario(self.root / "REAL")
        self.assertEqual(errors, [])
        self.assertEqual(len(records), 3)
        self.assertIn("auth.log:L0001", load_raw_lines(self.root / "REAL"))

    def test_findings_capped_for_llm(self):
        ids = [f"auth.log:L{i:04d}" for i in range(1, 50)]
        findings = [{"rule_id": "ssh_brute_force", "severity": "high", "evidence_ids": ids}] * 30
        out = findings_for_llm(findings)
        self.assertEqual(len(out), MAX_FINDINGS_FOR_LLM)
        self.assertTrue(all(len(f["evidence_ids"]) == MAX_EVIDENCE_PER_FINDING for f in out))
        self.assertEqual(out[0]["total_evidence"], 49)


if __name__ == "__main__":
    unittest.main()
