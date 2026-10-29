# Log Analyst

LLM-based security log analysis with evidence-linked, machine-verified claims.
CS3405 Ethical Hacking and Penetration Testing hackathon.

Team: NAME 1 (USN), NAME 2 (USN), NAME 3 (USN)

## Problem
Analysts drown in logs. LLMs can summarize them, but LLMs hallucinate events and evidence.
This tool lets a local LLM explain attacks, then verifies every claim against the raw log lines it cites.

## Architecture
    synthetic logs (generator)
            |
    parser  ->  structured records with evidence IDs (auth.log:L0007)
            |
    correlator  ->  deterministic rule findings (brute force, SQLi, odd-hour login, exfil...)
            |
    LLM (Ollama, local)  ->  JSON attack chain, every claim cites evidence IDs
            |
    claim validator  ->  VERIFIED / UNVERIFIED per claim, against raw lines
            |
    Streamlit UI + metrics (ground truth, adversarial set, ablation)

Design choice: rules detect, LLM explains, validator checks. The LLM never sees full logs,
only rule findings and cited lines, which keeps it grounded and within context limits.

## Setup (macOS)
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    # install Ollama from ollama.com, open the app, then:
    ollama pull qwen2.5:3b

## Run
    ./run_all.sh                 # generate, parse, test, analyze, validate, evaluate
    python -m llm.ablation       # optional, 10-20 min
    streamlit run app.py         # demo UI (works with Ollama off, using saved results)

## Scenarios
| ID | Content | Expected |
|---|---|---|
| S1 | SSH brute force, login at 02:14, sudo reading /etc/shadow | full attack chain |
| S1_mitigated | Same baseline, account lockout after 5 failures | brute force only, chain broken |
| S2 | 2 SQL injection + 2 path traversal requests | web attack indicators |
| S3 | 03:14 login then 50 MB download from same IP | correlated events |
| S4 | Benign only | no findings |
| S5 | Hard negatives: typo then login, daytime sudo, backup download, harmless "select" URL | ideally no findings |

## Evaluation
- docs/results.md: rule detection vs ground truth per scenario
- docs/adversarial.md: 22 handcrafted claims (valid, fabricated, blind spots) against the validator
- docs/ablation.md: grounded vs ungrounded LLM, same model and seeds
- 31 unit tests: python -m unittest discover -s tests -v

## Mitigation
S1 vs S1_mitigated: account lockout (pam_faillock) after 5 failures. Re-running the pipeline
shows the brute force still detected but no successful login, no sudo, attack chain broken.

## Limitations
- Synthetic data, designed alongside the rules. Metrics show internal consistency, not real-world accuracy.
- Validator uses pattern matching. Verified means cited lines support the event type, not that the activity is malicious (see blind spots B1, B2).
- Indicators are not proof of success. Correlation is not proof of exfiltration. Sudo use is not proof of privilege escalation.
- S5 backup download is flagged as a low-severity large transfer: a documented false positive.
- Small local model (3B); larger models may give different claim quality.

## Ethics
Synthetic data only, private 10.x IPs, no real systems scanned or attacked. LLM runs locally,
no data leaves the machine. LLM output treated as untrusted until verified.

## AI tool disclosure
AI assistants were used for code review, debugging, and drafting parts of the code and docs.
All code was run, tested, and reviewed by the team.