# Detection results

## Synthetic labeled scenarios

| Scenario | Lines | Findings | TP | FP | FN | Precision | Recall | FPR | Missed rules | Unexpected rules | Claims verified | MITRE match |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| S1 | 508 | 4 | 8 | 0 | 0 | 1.00 | 1.00 | 0.00 | - | - | 3/3 | 2/3 |
| S1_mitigated | 509 | 1 | 8 | 0 | 0 | 1.00 | 1.00 | 0.00 | - | - | 1/1 | 1/1 |
| S2 | 504 | 4 | 4 | 0 | 0 | 1.00 | 1.00 | 0.00 | - | - | 1/1 | 0/1 |
| S3 | 502 | 3 | 2 | 0 | 0 | 1.00 | 1.00 | 0.00 | - | - | 3/3 | 0/3 |
| S4 | 500 | 0 | 0 | 0 | 0 | N/A | N/A | 0.00 | - | - | 0/0 | 0/0 |
| S5 | 505 | 1 | 0 | 1 | 0 | 0.00 | N/A | 0.00 | - | large_data_transfer | 1/1 | 0/1 |
| S6_injection | 508 | 4 | 8 | 0 | 0 | 1.00 | 1.00 | 0.00 | - | - | 3/3 | 1/3 |

Synthetic data was designed alongside the rules, so these numbers measure internal consistency, not real-world accuracy.

## Real-world unlabeled runs

| Scenario | Lines | Parse errors | Masked IPs | Findings | Rules fired | IPs flagged | Claims verified | MITRE match |
|---|---|---|---|---|---|---|---|---|
| REAL_SSH | 2000 | 0 | 30 | 21 | ssh_brute_force: 9, username_spraying: 8, auth_attempts_exhausted: 3, slow_brute_force: 1 | 14 | 1/1 | 1/1 |
| UPLOAD | 301 | 0 | 7 | 3 | ssh_brute_force: 1, username_spraying: 1, auth_attempts_exhausted: 1 | 2 | 1/1 | 1/1 |

No ground-truth labels: precision and recall cannot be computed for real-world data.
