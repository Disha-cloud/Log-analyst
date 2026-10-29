# Ablation: grounded vs ungrounded

Model qwen2.5:3b, temperature 0.2, seeds [1, 2], scenarios ['S1', 'S2', 'S3']. Ungrounded mode sees all attack lines plus 120 random benign lines, no rule findings.

| Mode | Runs | Claims | Verified rate | Invalid IDs | Benign lines cited | Attack coverage | Errors |
|---|---|---|---|---|---|---|---|
| grounded | 6 | 12 | 83.3% | 0 | 0 | 100.0% | 0 |
| ungrounded | 6 | 4 | 100.0% | 0 | 0 | 14.3% | 0 |
