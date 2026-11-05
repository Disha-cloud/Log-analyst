# Real-log ML detector (Loghub OpenSSH, 655,147 lines)

Code: `features/real_ssh.py`, `model/train_real.py`, `model/linux_transfer.py`. Model: `model/detector_real.joblib`.
Raw numbers: `docs/real_detector_results.json`, `docs/linux_transfer_results.json`.
Data (downloaded outside the repo): Loghub `SSH.tar.gz` and `Linux.tar.gz`, Zenodo record 8196385.

## Method
- Features: one IP in one 2,000-line chunk. Counts of failed passwords, invalid users, PAM failures, preauth
  disconnects, break-in warnings, missing-identification probes; distinct usernames, events/min, bad ratio.
  **Successful-login lines are excluded from every feature, and rows that contain only successful logins are dropped.**
- Labels (weak, from whole-log behaviour): malicious = 10+ failed-auth events and no successful login (367 IPs);
  benign = successful login and zero failures, or a reviewed hard negative; the rest is ambiguous and excluded.
- Reviewed hard negatives (`docs/real_label_review_mixed_ips.csv`): 6 IPs that fail and then succeed with one stable
  username. 3 were marked "candidate hard negative" by the reviewer; 3 "unknown" show the identical pattern and I
  labeled them benign. The 2 reviewer-marked "suspicious" IPs are left out of training (unresolved).
- Evaluation: stratified 5-fold cross-validation grouped by IP (an IP is never in train and test), repeated 5 times.

## Results (main labeling: 367 malicious IPs / 2,480 rows; 15 benign IPs / 37 rows)
| | Precision | Recall | F1 | False-positive rate on benign |
|---|---|---|---|---|
| RandomForest | 0.998 | 0.990 | 0.994 | 16.2% (hard negatives: 28.7%) |
| Threshold >=3 failures in chunk | 1.000 | 0.916 | 0.956 | 2.7% (1 of 37 rows) |
| Threshold >=5 failures in chunk | 1.000 | 0.744 | 0.853 | 0% |

Sensitivity to the 2 unresolved IPs: labeled benign gives FP rate 17.8% (F1 0.994); labeled malicious gives 23.2%
(F1 0.993). Conclusions do not change.

## Linux transfer (different machine, PAM-only lines, no true labels)
| Host bucket (total PAM failures) | Rows | ML flagged | Threshold >=5 flagged |
|---|---|---|---|
| 10+ failures (214 hosts) | 221 | 100% | 100% |
| 3-9 failures | 75 | 96% | 71% |
| 1-2 failures | 57 | **3.5%** | 0% |

## What changed and what to believe
- An earlier version flagged every host with any failure (100% of the 1-2 failure bucket). Cause found: `bad_ratio`
  and `event_count` included successful-login lines, so the model learned "login lines present => benign", which
  does not exist in the Linux log. Removing them fixed transfer: 1-2 failure hosts dropped from 100% to 3.5% flagged.
  The same fix shrank the benign set from 122 to 37 rows, because most benign IPs had nothing but successful logins.
- The ML model is **not** better than a plain ">=3 failures" rule on this data: slightly higher recall (0.990 vs 0.916),
  but a much higher false-positive rate on benign (16% vs 3%). It is only better at catching slower attackers.
- Benign evidence is still tiny: 15 IPs, 37 rows. False-positive rates are rough (one more error moves them by ~3 points).
- Labels are heuristic and overlap with the features; there is still a single lab server, so no independent real test.
- Linux has no labels, so that table shows behavior, not accuracy.
