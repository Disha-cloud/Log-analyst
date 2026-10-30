# Log Analyst

LLM-based security log analysis with evidence-linked, machine-verified claims.
CS3405 Ethical Hacking and Penetration Testing hackathon.

**Team:** NAME 1 (USN), NAME 2 (USN), NAME 3 (USN)
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

## Project structure
```
generator/generate_logs.py   synthetic scenarios + ground truth (fixed seeds)
generator/import_real.py     import real/uploaded logs, mask public IPs
parser/log_parser.py         auth.log + Apache access.log parsing
parser/correlator.py         8 detection rules, ATT&CK mapping
llm/analyzer.py              local LLM analysis (Ollama, JSON schema)
llm/ablation.py              grounded vs ungrounded experiment
validator/claim_validator.py evidence + ATT&CK verification
validator/evaluate.py        metrics vs ground truth
validator/adversarial_eval.py 22-case validator test set
tests/                       44 unit tests
app.py                       Streamlit UI
data/                        scenarios and saved results
docs/                        results, adversarial, ablation, case study
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
| REAL_SSH | 2,000 real OpenSSH lines (Loghub), public IPs masked | unlabeled |

## Results
| Metric | Value |
|---|---|
| Unit tests | 44 passing |
| Rule detection (S1 to S3) | precision 1.00, recall 1.00; S4 0 findings; S5 1 documented FP |
| LLM claims evidence-verified | 12/12 (temperature 0) |
| Validator adversarial test | 15/15 fabricated caught, 5/5 valid accepted, 2 blind spots documented |
| Ablation attack coverage | grounded 100% vs ungrounded 14.3% (ungrounded missed attack in 5/6 runs) |
| LLM-suggested ATT&CK IDs correct | 4/10, so techniques are assigned by rules |
| Real-world | 2,000 lines, 0 parse errors, 30 IPs masked, 9 brute-force IPs flagged |
| Mitigation | S1: 4 rules, 3 stages; S1_mitigated: 1 rule, 1 stage |

Details: docs/results.md, docs/adversarial.md, docs/ablation.md, docs/case_study_ordering_bug.md

## Mitigation
Account lockout (pam_faillock) after 5 failures. Re-running the pipeline on S1_mitigated
shows brute force still detected, but no successful login and no sudo: attack chain broken.

## Limitations
- Synthetic data was designed alongside the rules: metrics show consistency, not real-world accuracy.
- Verified means cited lines support the event type, not that activity is malicious.
- Numbers and IPs in the free-text summary are not verified, only cited IDs.
- Indicators are not proof of success; correlation is not proof of exfiltration.
- ATT&CK stage mapping is the team's judgment.
- One small local model (3B).
- IP masking does not hide hostnames or usernames in the real dataset.
- Log injection against the LLM not evaluated (future work).

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
- MITRE ATT&CK. https://attack.mitre.org
- OWASP Top 10 for LLM Applications.
- Qwen Team, "Qwen2.5 Technical Report," arXiv:2412.15115, 2024.
