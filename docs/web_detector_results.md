# Web-request ML detector (CSIC 2010)

Code: `features/http_requests.py`, `model/train_web.py` (model: `model/detector_web.joblib`).
Data: https://github.com/Monkey-D-Groot/Machine-Learning-on-CSIC-2010 (`normalTrafficTraining.txt`,
`anomalousTrafficTest.txt`), downloaded outside the repo. Raw numbers: `docs/web_detector_results.json`.
36,000 normal and 25,065 anomalous requests, labeled per request. CSIC 2010 is a synthetic e-commerce app
(simulated users and attackers), not production traffic.

Split: 80/20 by unique request signature (no identical request on both sides): 13,453 test rows, 5,937 anomalous.

## Results
| Model | Precision | Recall | F1 |
|---|---|---|---|
| RandomForest (path/query/body features) | 0.612 | 0.892 | 0.726 |
| Project regex rules (SQLI_RE / TRAVERSAL_RE) | 1.000 | 0.012 | 0.024 |
| Header-only RandomForest (artifact check) | 0.573 | 0.367 | 0.447 |

ROC AUC of the forest: 0.775. Raising the threshold does not help (0.9: precision 0.54, recall 0.60).

## What this shows
- **Obvious injection payloads are easy.** Of the 945 test attacks containing SQLi/XSS/traversal keywords, the forest
  catches 100%. The regexes miss almost everything here because they were written for SSH-era S2/S3 patterns.
- **Most CSIC "anomalies" are not payloads.** 4,992 of 5,937 test anomalies have no attack keyword: they are
  tampered parameter names (`nombreA`, `loginA`, `B2A`), odd paths, etc. The forest catches 87% of those, but only
  by learning this one shop's request grammar, which will not transfer to other sites.
- **False-positive rate is too high to use: 44.6% of normal test requests are flagged.** This is a weak model,
  not a deployable one.
- **Artifact risk:** a header-only model reaches F1 0.45 without seeing any payload, so the dataset has some
  generation artifacts. Payload features deliberately exclude headers.
- Normal test rows repeat: 7,516 rows but only 1,929 unique requests, so a few repeated mistakes weigh heavily.

## Takeaway
Useful as evidence that ML can learn a labeled benign baseline, but not evidence of real-world web detection.
It is not wired into the app.
