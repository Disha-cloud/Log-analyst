import unittest

import numpy as np
import pandas as pd

from anomaly.baseline import ALL_COLUMNS, fit_baseline, score


def frame(n, seed=0, **over):
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({c: rng.poisson(3, n).astype(float) for c in ALL_COLUMNS})
    for c in ("ratio_2xx", "ratio_3xx", "ratio_4xx", "ratio_5xx", "off_hours_ratio", "pct_encoded_ratio"):
        df[c] = rng.uniform(0, 0.2, n)
    df["first_hour"] = df["mean_hour"] = rng.uniform(9, 17, n)
    df["ip"] = [f"10.0.0.{i}" for i in range(n)]
    for k, v in over.items():
        df[k] = v
    return df


class AnomalyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = fit_baseline([frame(600)], quantile=0.99)

    def test_refuses_tiny_baseline(self):
        with self.assertRaises(ValueError):
            fit_baseline([frame(5)])

    def test_warns_on_small_baseline(self):
        self.assertIsNotNone(fit_baseline([frame(50)])["warning"])
        self.assertIsNone(self.bundle["warning"])

    def test_baseline_like_data_flag_rate_is_low(self):
        rate = score(frame(600, seed=7), self.bundle).flagged.mean()
        self.assertLess(rate, 0.05)

    def test_extreme_row_flagged_with_reason(self):
        row = frame(3, seed=3, failed_login_count=400.0, distinct_usernames=60.0, off_hours_ratio=1.0)
        out = score(row, self.bundle)
        self.assertTrue(out.flagged.all())
        self.assertTrue(any("failed_login_count" in r for r in out.reasons.iloc[0]))

    def test_lower_than_normal_is_not_suspicious(self):
        out = score(frame(3, seed=4, request_count=0.0, event_count=0.0), self.bundle)
        self.assertFalse(any("request_count" in r for rs in out.reasons for r in rs))

    def test_attack_inside_baseline_is_learned_as_normal(self):
        # documented limitation: contaminate the baseline with the same extreme rows
        dirty = pd.concat([frame(600), frame(60, seed=9, failed_login_count=400.0, distinct_usernames=60.0)])
        b = fit_baseline([dirty], quantile=0.99)
        row = frame(3, seed=3, failed_login_count=400.0, distinct_usernames=60.0)
        self.assertLessEqual(score(row, b).flagged.mean(), score(row, self.bundle).flagged.mean())


if __name__ == "__main__":
    unittest.main()
