import tempfile
import unittest
from pathlib import Path

from feed.live_feed import alert_key, stream
from generator.generate_logs import generate_all
from parser.correlator import correlate
from parser.log_parser import parse_scenario


class LiveFeedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        generate_all(Path(cls.tmp.name), names=["S1", "S2", "S3", "S4", "S5"])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_stream(self, name):
        records, _ = parse_scenario(Path(self.tmp.name) / name)
        steps = list(stream(records))
        return records, steps

    def test_every_record_streamed_in_order(self):
        records, steps = self.run_stream("S1")
        self.assertEqual([s[0] for s in steps], list(range(1, len(records) + 1)))
        self.assertEqual([s[1]["evidence_id"] for s in steps], [r["evidence_id"] for r in records])

    def test_live_alerts_match_final_rule_findings(self):
        for name in ("S1", "S2", "S3", "S4", "S5"):
            records, steps = self.run_stream(name)
            live = {alert_key(f) for _, _, new in steps for f in new}
            final = {alert_key(f) for f in correlate(records)}
            self.assertEqual(live, final, name)

    def test_no_alert_reported_twice(self):
        _, steps = self.run_stream("S1")
        keys = [alert_key(f) for _, _, new in steps for f in new]
        self.assertEqual(len(keys), len(set(keys)))

    def test_alert_fires_only_after_its_evidence_has_arrived(self):
        records, steps = self.run_stream("S1")
        arrived = set()
        for _, record, new in steps:
            arrived.add(record["evidence_id"])
            for f in new:
                self.assertTrue(set(f["evidence_ids"]) <= arrived, f["rule_id"])

    def test_benign_scenario_raises_no_alerts(self):
        _, steps = self.run_stream("S4")
        self.assertEqual([f for _, _, new in steps for f in new], [])

    def test_brute_force_alerts_once_per_ip(self):
        _, steps = self.run_stream("S1")
        bf = [f for _, _, new in steps for f in new if f["rule_id"] == "ssh_brute_force"]
        self.assertEqual(len(bf), 1)


if __name__ == "__main__":
    unittest.main()
