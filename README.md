# Log Analyst

LLM-based security log analysis with evidence-linked, machine-verified claims.
CS3405 Ethical Hacking and Penetration Testing hackathon.

**Problem statement:** LLM-Based Security Log Analysis and Threat Explanation

## Problem
Analysts drown in logs. LLMs summarize fast, but hallucinate events, cite wrong lines,
mislabel techniques, and can silently miss attacks. Log Analyst lets a local LLM explain
attacks, then automatically verifies every claim against the raw log lines it cites.

## Architecture
```
synthetic generator / real log importer
        |
parser      -> structured records with evidence IDs (auth.log:L0007)
        |
correlator  -> deterministic rule findings + MITRE ATT&CK technique
        |
LLM (Ollama, local) -> JSON attack chain, every claim cites evidence IDs
        |
validator   -> VERIFIED / UNVERIFIED per claim + ATT&CK check
        |
Streamlit UI + evaluation (ground truth, adversarial set, ablation, real data)
```
Rules detect. LLM explains. Validator checks. The LLM never sees full logs, only rule
findings and the lines they cite.

Alongside the rule pipeline there are optional, experimental ML paths that are **not** the primary
detector: supervised RandomForests and a per-environment anomaly detector fitted on your own normal logs.

## Project structure
```
generator/generate_logs.py   synthetic scenarios + ground truth (fixed seeds); N randomized S1-S3 variants
generator/import_real.py     import real/uploaded logs, mask public IPs
parser/log_parser.py         auth.log + Apache access.log parsing (incl. preauth, max-attempts, invalid user, denied sudo)
parser/correlator.py         13 detection rules, ATT&CK mapping
llm/analyzer.py              local LLM analysis (Ollama, JSON schema)
llm/ablation.py              grounded vs ungrounded experiment
validator/claim_validator.py evidence + ATT&CK verification, contradiction and stage-coverage checks
validator/evaluate.py        metrics vs ground truth
validator/adversarial_eval.py 22-case validator test set
scoring/trust_score.py       0-100 trust score (rule confidence, claims verified, ATT&CK match)
feed/live_feed.py            simulated live feed (replay, alerts fire as trigger lines arrive)
features/, model/            per-IP features and the RandomForest detectors (synthetic, real SSH, CSIC web)
anomaly/                     per-environment anomaly detector (python -m anomaly fit / score)
tests/                       109 unit tests
app.py                       Streamlit UI
data/                        scenarios and saved results (data_variants/ is generated, not committed)
docs/                        results, adversarial, ablation, case study, injection demo, ML and anomaly results
```

## Requirements
- macOS or Linux, Python 3.10+
- Ollama (https://ollama.com) with model qwen2.5:3b (about 2 GB)

## Setup
```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
ollama pull qwen2.5:3b
```
Open the Ollama app before running LLM steps.

## Run
Demo (works from saved results, even with Ollama off):
```
streamlit run app.py
```
Full pipeline:
```
python -m generator.generate_logs
python -m unittest discover -s tests -v
python -m llm.analyzer
python -m validator.claim_validator
python -m validator.evaluate
python -m validator.adversarial_eval
python -m llm.ablation            # optional, 10 to 20 min
```
Variants, ML and anomaly detection (all optional):
```
python -m generator.generate_logs --variants 40          # data_variants/ (not committed)
python -m model.train_detector && python -m model.evaluate_detector
python -m model.train_real /path/to/Loghub_SSH.log       # Loghub OpenSSH, from Zenodo 8196385
python -m anomaly fit --baseline /path/to/normal_logs -o my_baseline.joblib
python -m anomaly score /path/to/new_logs --model my_baseline.joblib
```
A log folder holds `auth.log` and/or `access.log` (OpenSSH syslog; Apache combined).
The CSIC web model (`model/train_web.py`) writes a 77 MB file that is git-ignored.

Real-world test (download OpenSSH_2k.log from Loghub first):
```
python -m generator.import_real ~/Downloads/OpenSSH_2k.log --name REAL_SSH
python -m llm.analyzer REAL_SSH
python -m validator.claim_validator REAL_SSH
python -m validator.evaluate
```

## Scenarios
| ID | Content | Expected |
|---|---|---|
| S1 | SSH brute force, login at 02:14, sudo reading /etc/shadow | full attack chain |
| S1_mitigated | Same baseline, account lockout after 5 failures | brute force only, chain broken |
| S2 | 2 SQL injection + 2 path traversal requests | web attack indicators |
| S3 | 03:14 login then 50 MB download from same IP | correlated events |
| S4 | Benign only | no findings |
| S5 | Hard negatives: typo then login, daytime sudo, backup, harmless "select" URL | ideally none |
| S6_injection | S1-style attack plus a crafted sudo COMMAND aimed at the LLM (see docs/injection_demo.md) | rules unaffected; LLM and validator tested |
| REAL_SSH | 2,000 real OpenSSH lines (Loghub), public IPs masked | unlabeled |

## Detection rules (13)
SSH: `ssh_brute_force` (5 failures in 60 s), `slow_brute_force` (5 in 24 h, never succeeded), `username_spraying`
(4 attempts over 3+ usernames in 10 min), `auth_attempts_exhausted` (sshd attempt limit hit), `failure_then_success`,
`probe_then_success` (several accounts guessed, then a success), `unusual_hour_login`, `login_then_sudo`.
Sudo: `denied_sudo`. Web: `sql_injection_indicator`, `path_traversal_indicator`. Transfers: `large_data_transfer`,
`correlated_events`. A single user mistyping a password then succeeding is deliberately not flagged. Details: docs/new_rules.md.

## Results
| Metric | Value |
|---|---|
| Unit tests | 109 passing |
| Rule detection (S1 to S3) | precision 1.00, recall 1.00; S4 0 findings; S5 1 documented FP |
| LLM claims evidence-verified | 12/12 (temperature 0, original S1-S5 run) |
| Validator adversarial test | 15/15 fabricated caught, 5/5 valid accepted, 2 blind spots documented |
| Ablation attack coverage | grounded 100% vs ungrounded 14.3% (ungrounded missed attack in 5/6 runs) |
| LLM-suggested ATT&CK IDs correct | 4/10, so techniques are assigned by rules |
| Real-world (REAL_SSH, 2,000 lines) | 0 parse errors, 30 IPs masked, 21 findings on 14 IPs (brute force 9, spraying 8, attempt limit 3, slow 1). Saved LLM analysis predates the newer rules. |
| Real-world (full Loghub SSH, 655k lines) | rules flag 356 of 367 heuristically-labeled attacker IPs; 6 of 40 benign IPs flagged, all by `unusual_hour_login`. Labels are heuristic. Correlation took about 48 min (old rules are quadratic). |
| Mitigation | S1: 4 rules, 3 stages; S1_mitigated: 1 rule, 1 stage |

Details: docs/results.md, docs/adversarial.md, docs/ablation.md, docs/case_study_ordering_bug.md

## Added after the first hackathon version
- **Prompt injection (S6_injection):** the validator catches fabricated evidence IDs but not persuasive prose. A
  contradiction check (claims or summary dismissing a fired rule: "false positive", "authorized") and a stage-coverage
  check (UNDER-REPORTED) now catch two of three tested injection-influenced runs. One run that merely echoes the injected
  text is still missed. No control run. See docs/injection_demo.md.
- **Trust score (Overview tab):** how well the analysis is supported by evidence. It is not a maliciousness score. Weights are judgment.
- **Live feed tab:** replays a scenario; each alert appears when its trigger line arrives. Simulation only, no model call.
- **ML detectors (honest status):** the synthetic RandomForest is perfect in-distribution and near zero on unseen attack
  families (docs/detector_results.md). The real-SSH RandomForest (Loghub, weak labels, 6 reviewed hard negatives) has
  F1 0.994 but a 16% false-positive rate on benign IPs and does not beat a "3+ failures" rule (docs/real_detector_results.md).
  The CSIC web model reaches F1 0.73 with 44.6% false positives (docs/web_detector_results.md). None is a reliable detector yet.
- **Per-environment anomaly detector:** learns normal from your logs (no attack labels), flags deviations with reasons.
  Synthetic held-out F1 0.73 at its default setting; only as good as the baseline (docs/anomaly_detector.md).

## Mitigation
Account lockout (pam_faillock) after 5 failures. Re-running the pipeline on S1_mitigated
shows brute force still detected, but no successful login and no sudo: attack chain broken.

## Limitations
- Synthetic data was designed alongside the rules: metrics show consistency, not real-world accuracy.
- Only OpenSSH/sudo syslog and Apache-style access logs are parsed. Windows, firewall, cloud, JSON and other formats are not supported. "No findings" does not mean "no attack".
- The app caps the auth log at 5,000 lines. The rule engine is slow on very large logs (quadratic scans in the older rules).
- `unusual_hour_login` uses a fixed 00:00-05:00 window and is noisy on servers used around the clock.
- Verified means cited lines support the event type, not that activity is malicious.
- Numbers and IPs in the free-text summary are not verified, only cited IDs. Contradiction checks are a phrase list and miss paraphrases.
- Indicators are not proof of success; correlation is not proof of exfiltration.
- ATT&CK stage mapping is the team's judgment.
- One small local model (3B).
- IP masking does not hide hostnames or usernames in the real dataset.
- The ML models are trained on little real labeled data; real-data labels are heuristic. The anomaly detector learns attacks that are present in its baseline as normal.
- Log injection against the LLM is only partly mitigated (see above).

## Ethics
Synthetic data (private 10.x IPs) and one public research dataset only. No systems scanned
or attacked. LLM runs locally; no data leaves the machine. No credentials in the repository.
LLM output treated as untrusted until verified.

## AI tool disclosure
AI assistants were used for code review, debugging, and drafting parts of the code and
documentation. All code was run, tested, and reviewed by the team; all reported numbers
come from our own runs.

## References
- J. Zhu, S. He, P. He, J. Liu, M. R. Lyu, "Loghub: A Large Collection of System Log Datasets
  for AI-driven Log Analytics," ISSRE 2023. https://github.com/logpai/loghub
- HTTP dataset CSIC 2010 (Spanish National Research Council, CSIC), used through the copy at
  https://github.com/Monkey-D-Groot/Machine-Learning-on-CSIC-2010. Check the original source for the authoritative citation.
- MITRE ATT&CK. https://attack.mitre.org
- OWASP Top 10 for LLM Applications.
- Qwen Team, "Qwen2.5 Technical Report," arXiv:2412.15115, 2024.
