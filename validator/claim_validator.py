
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"

PATTERNS = {
    "brute_force": re.compile(
        r"failed password|authentication failure|failed login",
        re.IGNORECASE,
    ),
    "successful_authentication": re.compile(
        r"accepted password|accepted publickey|login successful|"
        r"successful login",
        re.IGNORECASE,
    ),
    "privileged_activity": re.compile(
        r"\bsudo\b|\bsu\b|user.*(?:added|modified)",
        re.IGNORECASE,
    ),
    "sql_injection": re.compile(
        r"union\s+(?:all\s+)?select|select.+from|"
        r"or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|"
        r"information_schema|%27|%22",
        re.IGNORECASE,
    ),
    "path_traversal": re.compile(
        r"\.\./|\.\.\\|%2e%2e|/etc/passwd|windows/win\.ini",
        re.IGNORECASE,
    ),
}


def load_log_lines(scenario_dir):
    """Load log lines using their embedded IDs where available."""
    log_lines = {}

    for filename in ("auth.log", "access.log"):
        path = scenario_dir / filename

        if not path.exists():
            continue

        with path.open("r", encoding="utf-8", errors="replace") as file:
            for line_number, raw_line in enumerate(file, start=1):
                raw_line = raw_line.rstrip("\n")
                match = re.match(r"^(L\d+)\s+", raw_line)
                line_id = (
                    match.group(1)
                    if match
                    else f"L{line_number:04d}"
                )

                evidence_id = f"{filename}:{line_id}"
                log_lines[evidence_id] = raw_line

    return log_lines


def identify_claim_type(claim):
    """Map a claim to a supported verification category."""
    stage = str(claim.get("stage", "")).lower()
    explanation = str(claim.get("explanation", "")).lower()
    text = f"{stage} {explanation}"

    # Check combined claims before individual event types.
    if any(term in text for term in (
        "correlated_events",
        "correlated events",
        "login followed by transfer",
        "login_then_large_transfer",
        "correlated login",
    )):
        return "correlated_events"

    if any(term in text for term in (
        "authentication_attempt",
        "authentication attempt",
        "brute force",
        "brute_force",
        "failed login attack",
        "ssh brute",
        "failed password",
    )):
        return "brute_force"

    if any(term in text for term in (
        "sql injection",
        "sql_injection",
        "path traversal",
        "path_traversal",
        "exploitation attempt",
    )):
        return "exploitation_attempt"

    if any(term in text for term in (
        "successful authentication",
        "successful_authentication",
        "successful login",
        "login success",
    )):
        return "successful_authentication"

    if any(term in text for term in (
        "privileged activity",
        "privileged_activity",
        "privilege escalation",
    )):
        return "privileged_activity"

    if any(term in text for term in (
        "large data transfer",
        "large_data_transfer",
        "data exfiltration",
    )):
        return "large_data_transfer"

    return None


def line_supports(claim_type, raw_line):
    """Check whether a log line contains indicators for the claim."""
    decoded_line = unquote(raw_line)

    if claim_type == "exploitation_attempt":
        return any(
            PATTERNS[pattern].search(decoded_line)
            for pattern in ("sql_injection", "path_traversal")
        )

    if claim_type == "large_data_transfer":
        # Apache combined logs can contain additional fields after bytes.
        match = re.search(
            r'"\s+(\d{3})\s+(\d+|-)(?:\s|$)',
            decoded_line,
        )

        if match and match.group(2) != "-":
            return (
                match.group(1) == "200"
                and int(match.group(2)) >= 10_000_000
            )

        return bool(re.search(
            r"large response|large transfer|bytes sent",
            decoded_line,
            re.IGNORECASE,
        ))

    pattern = PATTERNS.get(claim_type)
    return bool(pattern and pattern.search(decoded_line))


def verify_claim(claim, log_lines):
    """Verify cited evidence and return a structured result."""
    evidence_ids = claim.get("evidence_ids", [])

    if not isinstance(evidence_ids, list) or not evidence_ids:
        return {
            "status": "unverified",
            "claim_type": None,
            "reason": "No evidence IDs were cited.",
            "evidence_checks": [],
        }

    claim_type = identify_claim_type(claim)

    if claim_type is None:
        return {
            "status": "unverified",
            "claim_type": None,
            "reason": "No verification rule exists for this claim type.",
            "evidence_checks": [],
        }

    evidence_checks = []

    for evidence_id in evidence_ids:
        if not isinstance(evidence_id, str) or evidence_id not in log_lines:
            evidence_checks.append({
                "evidence_id": evidence_id,
                "status": "fail",
                "reason": "Evidence ID does not exist in the loaded logs.",
            })
            continue

        raw_line = log_lines[evidence_id]

        if claim_type == "correlated_events":
            evidence_checks.append({
                "evidence_id": evidence_id,
                "status": "review_required",
                "reason": "This claim requires multiple supporting events.",
            })
            continue

        supported = line_supports(claim_type, raw_line)

        evidence_checks.append({
            "evidence_id": evidence_id,
            "status": "pass" if supported else "fail",
            "reason": (
                "The line contains a matching event indicator."
                if supported
                else "The line does not contain the expected event indicator."
            ),
        })

    # Combined claims must cite existing lines supporting both events.
    if claim_type == "correlated_events":
        all_ids_exist = all(
            isinstance(evidence_id, str) and evidence_id in log_lines
            for evidence_id in evidence_ids
        )

        existing_lines = [
            log_lines[evidence_id]
            for evidence_id in evidence_ids
            if isinstance(evidence_id, str)
            and evidence_id in log_lines
        ]

        has_auth = any(
            PATTERNS["successful_authentication"].search(line)
            for line in existing_lines
        )

        has_transfer = any(
            line_supports("large_data_transfer", line)
            for line in existing_lines
        )

        passed = all_ids_exist and has_auth and has_transfer

        reason = (
            "Existing cited lines contain both authentication and "
            "large-transfer indicators."
            if passed
            else "The cited lines do not establish both required events "
            "or one or more evidence IDs are missing."
        )

    else:
        passed = (
            len(evidence_checks) == len(evidence_ids)
            and all(
                check["status"] == "pass"
                for check in evidence_checks
            )
        )

        reason = (
            "All cited lines support the claimed event."
            if passed
            else "One or more cited lines failed verification."
        )

    return {
        "status": "verified" if passed else "unverified",
        "claim_type": claim_type,
        "reason": reason,
        "evidence_checks": evidence_checks,
    }


def validate_scenario(scenario_name):
    """Validate one scenario and save its claim-verification report."""
    scenario_dir = DATA_DIR / scenario_name
    report_path = scenario_dir / "llm_analysis.json"

    if not report_path.exists():
        raise FileNotFoundError(f"Missing report: {report_path}")

    with report_path.open("r", encoding="utf-8") as file:
        report = json.load(file)

    log_lines = load_log_lines(scenario_dir)
    claims = report.get("attack_chain", [])
    results = []

    for index, claim in enumerate(claims, start=1):
        result = verify_claim(claim, log_lines)

        results.append({
            "claim_number": index,
            "stage": claim.get("stage", "unknown"),
            "explanation": claim.get("explanation", ""),
            "evidence_ids": claim.get("evidence_ids", []),
            **result,
        })

    # Count each claim once, even when multiple evidence IDs fail.
    verified_count = sum(
        result["status"] == "verified"
        for result in results
    )
    unverified_count = sum(
        result["status"] == "unverified"
        for result in results
    )
    total_claims = len(results)

    # Percentages are undefined when there are no claims.
    verification_rate = (
        verified_count / total_claims * 100
        if total_claims else None
    )
    unverified_rate = (
        unverified_count / total_claims * 100
        if total_claims else None
    )

    output = {
        "scenario": scenario_name,
        "total_claims": total_claims,
        "verified_claims": verified_count,
        "unverified_claims": unverified_count,
        "verification_rate_percent": (
            round(verification_rate, 2)
            if verification_rate is not None else None
        ),
        "unverified_rate_percent": (
            round(unverified_rate, 2)
            if unverified_rate is not None else None
        ),
        "claims": results,
        "limitations": [
            "Pattern matching is heuristic and does not prove intent.",
            "Unverified claims are not automatically confirmed hallucinations.",
            "Summary and mitigation statements are not individually checked.",
            "A matching log indicator does not prove an attack succeeded.",
        ],
    }

    output_path = scenario_dir / "claim_validation.json"

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(output, file, indent=2)

    print(f"\nScenario: {scenario_name}")
    print(f"Claims checked: {total_claims}")
    print(f"Verified: {verified_count}")
    print(f"Unverified: {unverified_count}")

    if total_claims:
        print(f"Verification rate: {verification_rate:.2f}%")
        print(f"Unverified rate: {unverified_rate:.2f}%")
    else:
        print("Verification rate: N/A (no claims to evaluate)")
        print("Unverified rate: N/A (no claims to evaluate)")

    for result in results:
        print(
            f"\nClaim {result['claim_number']}: "
            f"{result['stage']} -> {result['status']}"
        )
        print(f"Reason: {result['reason']}")

    print(f"\nDetailed results saved to: {output_path}")
    return output


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "S1"
    validate_scenario(scenario)
