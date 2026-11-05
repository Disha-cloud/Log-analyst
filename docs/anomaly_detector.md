# Per-environment anomaly detector

Code: `anomaly/baseline.py`, `anomaly/__main__.py` (CLI), `anomaly/evaluate.py`; tests `tests/test_anomaly.py`.
Raw numbers: `docs/anomaly_results.json`.

## Idea
Learn what NORMAL looks like in one environment from baseline logs, then flag IPs that deviate. No attack labels are
needed to fit, so it can run on log content nobody labeled. It is not a general attack classifier: it only knows the
environment it was fitted on.

## How it works
- Per-IP, per-calendar-day features (a log that fits in one day gives one row per IP; multi-day logs give one row per
  IP per day, so a 7-day baseline and a 1-day log are comparable). The features are: the 16 existing ones (failed logins, distinct usernames, request rate, endpoints, status
  mix, bytes, hours) plus request-shape features (longest path, special characters in a path, share of percent-encoded
  requests). Counts are log-scaled; hour of day is encoded as sin/cos.
- Two detectors: an IsolationForest, and the largest single-feature deviation from the baseline (robust z-score, only
  "higher than normal" counts). Each threshold is set on the baseline's own scores so the overall flag rate on
  baseline-like data is about `1 - quantile`.
- Each flag lists the features that deviate most ("failed_login_count=46 (baseline median 0, p99 0)").

## Use
```
python -m anomaly fit --baseline S4 --baseline /path/to/normal_logs_dir -o my_baseline.joblib
python -m anomaly score /path/to/new_logs_dir --model my_baseline.joblib
```
A directory holds `auth.log` and/or `access.log`. Fitting refuses fewer than 20 IP rows and warns under 200.

## Evaluation (synthetic S1-S5 + variants)
Fit on the benign IPs of the training scenarios only (7,128 rows, zero attack rows). Test: the same 26 held-out
scenarios as the supervised model (1,879 IPs, 24 attack IPs).

| Quantile | Precision | Recall | F1 | FPR | Recall S1 / S2 / S3 |
|---|---|---|---|---|---|
| 0.95 | 0.293 | 1.000 | 0.453 | 3.1% | 1.00 / 1.00 / 1.00 |
| 0.99 | 0.611 | 0.917 | 0.733 | 0.8% | 1.00 / 0.75 / 1.00 |
| 0.999 | 0.944 | 0.708 | 0.810 | 0.1% | 1.00 / 0.125 / 1.00 |

The supervised RandomForest scores 1.00 on the same split, but it needs labeled attacks and transferred poorly to
unseen attack families. The anomaly detector never saw an attack label. Attacks are only 1.3% of IPs, so even a 1% flag
rate costs precision. A first version without the single-feature detector and request-shape features missed S3 entirely
(recall 0.67 overall at 0.99).

## Limits
- **Only as good as the baseline.** On REAL_SSH with a baseline fitted on synthetic S4/S5, 21 of 24 IPs are flagged,
  because that real server is under constant attack and the synthetic baseline never was. A baseline must come from the
  environment being monitored.
- **Contaminated baseline.** Attacks present in the baseline are learned as normal. Review baseline logs first.
- **Small baselines give noisy thresholds** (S4+S5 alone is 143 rows; the CLI warns).
- **It says "unusual", not "attack".** A legitimate large backup is flagged too (S5's backup shows up with bytes_total far
  above baseline); the reasons let an analyst decide.
- Synthetic benign data from the same generator is easy; these numbers are not evidence about real servers.
- Not wired into the Streamlit app yet.

## Real-file check (user-supplied synthetic logs)
Baseline fitted on `server_auth.log` (356 lines, 7 days, 52 IPs, mostly routine; 92 IP-day rows, small so thresholds are
noisy). Scored against two other files: `auth_7days.log` flags the slow guesser 203.0.113.77 (which the rule engine
misses) and the spraying IP on both days, but also a regular user (`deploy`, 3 days); `auth.log` flags the spraying and
brute-force IPs and misses the attempt-limit IP (203.0.113.99, no failed-login features). A first version that used
whole-log rows scaled features with log length and flagged nothing useful on the 1-day file; the per-day rows fixed it.
