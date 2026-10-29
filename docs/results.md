# Detection results

| Scenario | Lines | Findings | TP | FP | FN | Precision | Recall | FPR | Missed rules | Unexpected rules | Claims verified |
|---|---|---|---|---|---|---|---|---|---|---|---|
| S1 | 508 | 4 | 8 | 0 | 0 | 1.00 | 1.00 | 0.00 | - | - | 3/3 |
| S1_mitigated | 509 | 1 | 8 | 0 | 0 | 1.00 | 1.00 | 0.00 | - | - | 1/1 |
| S2 | 504 | 4 | 4 | 0 | 0 | 1.00 | 1.00 | 0.00 | - | - | 1/1 |
| S3 | 502 | 3 | 2 | 0 | 0 | 1.00 | 1.00 | 0.00 | - | - | 3/3 |
| S4 | 500 | 0 | 0 | 0 | 0 | N/A | N/A | 0.00 | - | - | 0/0 |
| S5 | 505 | 1 | 0 | 1 | 0 | 0.00 | N/A | 0.00 | - | large_data_transfer | 1/1 |

Synthetic data was designed alongside the rules, so these numbers measure internal consistency, not real-world accuracy.
