# ML detector results (RandomForest)

Model: saved model detector.joblib, trained on 100 scenarios, evaluated on held-out scenarios

## Held-out summary: ML detector vs rule engine (same scenarios)

| Group | Scenarios | ML TP | ML FP | ML FN | ML Precision | ML Recall | ML FPR | Rules TP | Rules FP | Rules FN | Rules Precision | Rules Recall | Rules FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| S1 | 8 | 112 | 0 | 8 | 1.00 | 0.93 | 0.00 | 120 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S2 | 8 | 39 | 0 | 0 | 1.00 | 1.00 | 0.00 | 39 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S3 | 8 | 25 | 0 | 0 | 1.00 | 1.00 | 0.00 | 25 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| benign (S4/S5) | 2 | 0 | 0 | 0 | N/A | N/A | 0.00 | 0 | 1 | 0 | 0.00 | N/A | 0.00 |
| ALL | 26 | 176 | 0 | 8 | 1.00 | 0.96 | 0.00 | 184 | 1 | 0 | 0.99 | 1.00 | 0.00 |

Counts are per log line, pooled across scenarios (same scoring as docs/results.md). Both detectors are scored on identical, held-out scenarios from the same synthetic generator the rules were designed alongside.

## Transfer to an unseen attack type (leave one family out)

| Held-out family | Scenarios | ML TP | ML FP | ML FN | ML Precision | ML Recall | ML FPR | Rules TP | Rules FP | Rules FN | Rules Precision | Rules Recall | Rules FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| S1 | 42 | 0 | 0 | 607 | N/A | 0.00 | 0.00 | 607 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S2 | 41 | 7 | 0 | 183 | 1.00 | 0.04 | 0.00 | 190 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S3 | 41 | 0 | 0 | 127 | N/A | 0.00 | 0.00 | 127 | 0 | 0 | 1.00 | 1.00 | 0.00 |

The model was trained with that family's fixed scenario and all its variants removed (for S1 this includes S1_mitigated).

## Per-scenario (ML detector)

| Scenario | Lines | Findings | TP | FP | FN | Precision | Recall | FPR |
|---|---|---|---|---|---|---|---|---|
| S1_v004 | 518 | 1 | 17 | 0 | 1 | 1.00 | 0.94 | 0.00 |
| S1_v010 | 508 | 1 | 7 | 0 | 1 | 1.00 | 0.88 | 0.00 |
| S1_v011 | 522 | 1 | 21 | 0 | 1 | 1.00 | 0.95 | 0.00 |
| S1_v012 | 520 | 1 | 19 | 0 | 1 | 1.00 | 0.95 | 0.00 |
| S1_v025 | 514 | 1 | 13 | 0 | 1 | 1.00 | 0.93 | 0.00 |
| S1_v026 | 518 | 1 | 17 | 0 | 1 | 1.00 | 0.94 | 0.00 |
| S1_v031 | 509 | 1 | 8 | 0 | 1 | 1.00 | 0.89 | 0.00 |
| S1_v037 | 511 | 1 | 10 | 0 | 1 | 1.00 | 0.91 | 0.00 |
| S2_v001 | 503 | 1 | 3 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S2_v009 | 505 | 1 | 5 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S2_v013 | 506 | 1 | 6 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S2_v014 | 507 | 1 | 7 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S2_v015 | 503 | 1 | 3 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S2_v016 | 505 | 1 | 5 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S2_v028 | 505 | 1 | 5 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S2_v033 | 505 | 1 | 5 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S3_v001 | 502 | 1 | 2 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S3_v006 | 503 | 1 | 3 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S3_v010 | 503 | 1 | 3 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S3_v014 | 504 | 1 | 4 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S3_v020 | 504 | 1 | 4 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S3_v029 | 503 | 1 | 3 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S3_v031 | 503 | 1 | 3 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S3_v040 | 503 | 1 | 3 | 0 | 0 | 1.00 | 1.00 | 0.00 |
| S4 | 500 | 0 | 0 | 0 | 0 | N/A | N/A | 0.00 |
| S5 | 505 | 0 | 0 | 0 | 0 | N/A | N/A | 0.00 |

Findings = flagged IPs; TP/FP/FN/TN are per log line.

## Real-world unlabeled runs

| Scenario | Lines | Parse errors | Masked IPs | Findings | IPs flagged | Rule-engine IPs | Agree | Model only | Rules only |
|---|---|---|---|---|---|---|---|---|---|
| REAL_SSH | 2000 | 0 | 30 | 5 | 5 | 9 | 2 | 3 | 7 |

No ground-truth labels: precision and recall cannot be computed for real-world data.
