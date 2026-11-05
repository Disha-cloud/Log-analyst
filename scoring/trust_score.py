"""Combine rule confidence, LLM-claim verification and MITRE match rate into one 0-100 trust score.

What it measures: how well the analysis is supported by deterministic evidence. It is NOT a
measure of how malicious the activity is, and it does not detect prompt injection (see
docs/injection_demo.md). Weights and per-rule confidences are team judgment, not fitted values.

Components (each 0..1):
  rule_confidence  mean confidence of the DISTINCT rules that fired (nine identical brute-force
                   findings are not nine times the evidence)
  claims_verified  verified LLM claims / total LLM claims   (validator/claim_validator.py)
  mitre_match      LLM ATT&CK IDs that match the stage / total claims (same validator output)

Score = 100 * sum(weight * component). Returns None (shown as N/A) when it cannot be computed
honestly: no rule findings, validation not run, or the LLM produced no claims. Missing
components are never silently dropped or re-weighted.
"""

WEIGHTS = {"rule_confidence": 0.40, "claims_verified": 0.40, "mitre_match": 0.20}

# Confidence that a firing of the rule reflects a real attack indicator. Team judgment, informed
# by docs/results.md (e.g. large_data_transfer is the only rule with a documented false positive:
# a legitimate backup download in S5). Indicators are not proof of success.
RULE_CONFIDENCE = {
    "ssh_brute_force": 0.90,          # >=5 failures from one IP within 60 s
    "failure_then_success": 0.85,
    "probe_then_success": 0.80,       # several accounts guessed, then a success from the same IP
    "slow_brute_force": 0.65,         # >=5 failures in 24 h, never succeeded; slow scans vs a forgetful user
    "denied_sudo": 0.75,              # privilege attempt refused; intent unclear for a single event
    "username_spraying": 0.80,        # >=4 attempts over >=3 usernames in 10 min
    "auth_attempts_exhausted": 0.70,  # sshd hit MaxAuthTries; failures may be only partly logged     # >=3 failures then a success within 10 min
    "login_then_sudo": 0.80,          # sudo within 10 min of a suspicious login
    "sql_injection_indicator": 0.80,  # pattern match; attempt, success not established
    "path_traversal_indicator": 0.80,
    "correlated_events": 0.75,        # correlation is not proof of exfiltration
    "unusual_hour_login": 0.60,       # review indicator only
    "large_data_transfer": 0.50,      # size alone; legitimate backups look identical
}
DEFAULT_RULE_CONFIDENCE = 0.50
BANDS = [(80, "high"), (60, "moderate"), (0, "low")]


def band(score):
    return next(name for floor, name in BANDS if score >= floor)


def rule_confidence(findings):
    """Mean confidence over distinct rules that fired, or None if none fired."""
    rules = sorted({f["rule_id"] for f in findings})
    if not rules:
        return None, []
    values = [RULE_CONFIDENCE.get(r, DEFAULT_RULE_CONFIDENCE) for r in rules]
    return sum(values) / len(values), rules


def compute_trust(rule_findings, validation):
    """Return {"score": int|None, "band": str|None, "reason": str|None, "components": [...]}."""
    rc, rules = rule_confidence(rule_findings or [])
    if rc is None:
        return {"score": None, "band": None, "components": [],
                "reason": "No rule findings, so there is nothing to score."}
    if not validation:
        return {"score": None, "band": None, "components": [],
                "reason": "Validator has not run. Run live analysis to produce a score."}
    total = validation.get("total_claims") or 0
    if total == 0:
        return {"score": None, "band": None, "components": [],
                "reason": "The LLM produced no claims to verify."}
    verified = validation.get("verified_claims", 0)
    matched = validation.get("mitre_match", 0)
    values = {"rule_confidence": rc, "claims_verified": verified / total, "mitre_match": matched / total}
    details = {
        "rule_confidence": f"mean over {len(rules)} rule(s): {', '.join(rules)}",
        "claims_verified": f"{verified}/{total} LLM claims backed by the lines they cite",
        "mitre_match": f"{matched}/{total} LLM ATT&CK IDs fit the claim stage",
    }
    labels = {"rule_confidence": "Rule confidence", "claims_verified": "LLM claims verified",
              "mitre_match": "LLM ATT&CK ID match"}
    components = [{"key": k, "label": labels[k], "value": values[k], "weight": WEIGHTS[k],
                   "points": 100 * WEIGHTS[k] * values[k], "detail": details[k]} for k in WEIGHTS]
    score = int(sum(c["points"] for c in components) + 0.5)
    return {"score": score, "band": band(score), "reason": None, "components": components}
