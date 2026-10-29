"""Check each LLM attack_chain claim against the raw log lines it cites."""
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote

from parser.correlator import LARGE_TRANSFER_BYTES, SQLI_RE, TRAVERSAL_RE
from parser.log_parser import load_raw_lines

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"

STAGES = ["authentication_attempt", "successful_authentication", "privileged_activity",
          "exploitation_attempt", "large_data_transfer", "correlated_events"]

PATTERNS = {
    "authentication_attempt": re.compile(r"Failed password|authentication failure", re.I),
    "successful_authentication": re.compile(r"Accepted (?:password|publickey)", re.I),
    "privileged_activity": re.compile(r"\bsudo:.*COMMAND=", re.I),
}

# stage: (required kinds: each must appear at least once across cited lines,
#         allowed kinds: every cited line must show at least one of these)
STAGE_EVIDENCE = {
    "authentication_attempt": ({"failed"}, {"failed"}),
    "successful_authentication": ({"accepted"}, {"accepted", "failed"}),
    "privileged_activity": ({"sudo"}, {"sudo", "accepted"}),
    "exploitation_attempt": ({"web_attack"}, {"web_attack"}),
    "large_data_transfer": ({"large"}, {"large"}),
    "correlated_events": ({"accepted", "large"}, {"accepted", "large"}),
}

# Used only when stage is not an exact known stage. Order matters.
FALLBACK_KEYWORDS = [
    ("correlated_events", ("correlat", "exfiltration")),
    ("exploitation_attempt", ("sql", "injection", "traversal", "exploit")),
    ("privileged_activity", ("sudo", "privilege")),
    ("large_data_transfer", ("large", "transfer", "download")),
    ("authentication_attempt", ("brute", "failed login", "failed password")),
    ("successful_authentication", ("successful login", "login success", "accepted")),
]

ID_RE = re.compile(r"^(?:(auth\.log|access\.log)\s*:\s*)?L0*(\d+)$", re.I)
SUMMARY_ID_RE = re.compile(r"\b(?:(?:auth|access)\.log:)?L\d{3,5}\b")
LARGE_RE = re.compile(r'"\s+(\d{3})\s+(\d+|-)')


def identify_claim_type(claim):
    stage = str(claim.get("stage", "")).strip().lower()
    if stage in STAGES:
        return stage
    text = f"{stage} {str(claim.get('explanation', '')).lower()}"
    for claim_type, words in FALLBACK_KEYWORDS:
        if any(w in text for w in words):
            return claim_type
    return None


def normalize_evidence_id(raw_id, log_lines):
    """Return (resolved_id, None) or (None, reason)."""
    eid = str(raw_id).strip()
    if eid in log_lines:
        return eid, None
    match = ID_RE.match(eid)
    if not match:
        return None, "Malformed evidence ID."
    filename, line_id = match.group(1), f"L{int(match.group(2)):04d}"
    if filename:
        candidate = f"{filename.lower()}:{line_id}"
        if candidate in log_lines:
            return candidate, None
        return None, "Evidence ID does not exist in the source logs."
    matches = [k for k in log_lines if k.endswith(f":{line_id}")]
    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        return None, "Ambiguous evidence ID (exists in more than one file)."
    return None, "Evidence ID does not exist in the source logs."


def is_large_response(raw):
    match = LARGE_RE.search(raw)
    if not match:
        return False
    status, size = match.groups()
    return status == "200" and size != "-" and int(size) >= LARGE_TRANSFER_BYTES


def line_kinds(raw):
    kinds, decoded = set(), unquote(raw)
    if PATTERNS["authentication_attempt"].search(raw):
        kinds.add("failed")
    if PATTERNS["successful_authentication"].search(raw):
        kinds.add("accepted")
    if PATTERNS["privileged_activity"].search(raw):
        kinds.add("sudo")
    if SQLI_RE.search(decoded) or TRAVERSAL_RE.search(decoded):
        kinds.add("web_attack")
    if is_large_response(raw):
        kinds.add("large")
    return kinds


def verify_claim(claim, log_lines):
    claim_type = identify_claim_type(claim)
    evidence_ids = claim.get("evidence_ids") or []
    if claim_type is None:
        return {"status": "unverified", "claim_type": None,
                "reason": "Unrecognized claim type.", "evidence_checks": []}
    if not evidence_ids:
        return {"status": "unverified", "claim_type": claim_type,
                "reason": "No evidence IDs supplied.", "evidence_checks": []}
    required, allowed = STAGE_EVIDENCE[claim_type]
    checks, seen_kinds = [], set()
    for raw_id in evidence_ids:
        eid, problem = normalize_evidence_id(raw_id, log_lines)
        if eid is None:
            checks.append({"evidence_id": raw_id, "status": "fail", "reason": problem})
            continue
        kinds = line_kinds(log_lines[eid])
        seen_kinds |= kinds
        note = "" if eid == str(raw_id).strip() else f" (normalized from {raw_id})"
        if kinds & allowed:
            checks.append({"evidence_id": eid, "status": "pass",
                           "reason": f"Line shows {', '.join(sorted(kinds & allowed))}." + note})
        else:
            checks.append({"evidence_id": eid, "status": "fail",
                           "reason": f"Line does not support a {claim_type} claim." + note})
    missing = required - seen_kinds
    if missing:
        checks.append({"evidence_id": "(required)", "status": "fail",
                       "reason": f"Claim needs at least one line showing: {', '.join(sorted(missing))}."})
    verified = all(c["status"] == "pass" for c in checks)
    return {"status": "verified" if verified else "unverified", "claim_type": claim_type,
            "reason": "All cited lines passed." if verified else "One or more checks failed.",
            "evidence_checks": checks}


def check_summary(summary, log_lines):
    results = []
    for mention in dict.fromkeys(SUMMARY_ID_RE.findall(summary or "")):
        eid, problem = normalize_evidence_id(mention, log_lines)
        results.append({"mention": mention, "status": "pass" if eid else "fail",
                        "reason": "Exists in source logs." if eid else problem})
    return results


def validate_scenario(scenario_name, data_dir=DATA_DIR, save=True):
    scenario_dir = Path(data_dir) / scenario_name
    analysis_path = scenario_dir / "llm_analysis.json"
    if not analysis_path.exists():
        raise FileNotFoundError(f"Missing {analysis_path}. Run: python -m llm.analyzer {scenario_name}")
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    log_lines = load_raw_lines(scenario_dir)
    claims = []
    for number, claim in enumerate(analysis.get("attack_chain", []), start=1):
        claims.append({"claim_number": number, "stage": claim.get("stage"),
                       "explanation": claim.get("explanation"),
                       "evidence_ids": claim.get("evidence_ids", []),
                       **verify_claim(claim, log_lines)})
    total = len(claims)
    verified = sum(c["status"] == "verified" for c in claims)
    report = {
        "scenario": scenario_name, "total_claims": total, "verified_claims": verified,
        "unverified_claims": total - verified,
        "verification_rate_percent": round(100 * verified / total, 2) if total else None,
        "summary_checks": check_summary(analysis.get("summary", ""), log_lines),
        "claims": claims,
        "limitations": [
            "Checks use heuristic text patterns, not semantic proof.",
            "Verified means the cited lines support the claim, not that the activity is malicious.",
            "Unverified means unsupported by the cited lines, not automatically false.",
            "Summary is checked only for cited IDs, not for every statement.",
            "A matching indicator does not prove an attack succeeded.",
        ],
    }
    if save:
        (scenario_dir / "claim_validation.json").write_text(json.dumps(report, indent=2),
                                                            encoding="utf-8")
    rate = report["verification_rate_percent"]
    print(f"{scenario_name}: {total} claims, {verified} verified, {total - verified} unverified, "
          f"rate={'N/A' if rate is None else str(rate) + '%'}")
    return report


if __name__ == "__main__":
    names = sys.argv[1:] or sorted(p.name for p in DATA_DIR.iterdir()
                                   if (p / "llm_analysis.json").exists())
    for name in names:
        validate_scenario(name)