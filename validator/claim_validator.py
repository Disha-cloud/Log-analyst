
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"

# Patterns used to check whether log lines support a claim.
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
        r"\bsudo\b|\bsu\b|user.*(added|modified)",
        re.IGNORECASE,
    ),
    "sql_injection": re.compile(
        r"union\s+(all\s+)?select|select.+from|"
        r"or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|"
        r"information_schema|%27|%22",
        re.IGNORECASE,
    ),
    "path_traversal": re.compile(
        r"\.\./|\.\.\\|%2e%2e|/etc/passwd|"
        r"windows/win\.ini",
        re.IGNORECASE,
    ),
}



def load_log_lines(scenario_dir):
    """Map IDs embedded in log lines to their original log text."""
    log_lines = {}

    for filename in ("auth.log", "access.log"):
        path = scenario_dir / filename

        if not path.exists():
            continue

        with path.open("r", encoding="utf-8", errors="replace") as file:
            for line_number, raw_line in enumerate(file, start=1):
                raw_line = raw_line.rstrip("\n")

                # The generator may embed IDs such as L0501 in the line.
                match = re.match(r"^(L\d+)\s+", raw_line)
                line_id = match.group(1) if match else f"L{line_number:04d}"

                evidence_id = f"{filename}:{line_id}"
                log_lines[evidence_id] = raw_line

    return log_lines



def identify_claim_type(claim):
    text = " ".join([
        str(claim.get("stage", "")),
        str(claim.get("explanation", "")),
    ]).lower()

    if any(term in text for term in (
        "authentication_attempt", "authentication attempt",
        "brute force", "brute_force", "failed login attack",
        "ssh brute", "failed password",
    )):
        return "brute_force"

    if any(term in text for term in (
        "sql injection", "sql_injection", "path traversal",
        "path_traversal", "exploitation attempt",
    )):
        return "exploitation_attempt"

    if any(term in text for term in (
        "successful authentication", "successful login",
        "successful_authentication", "login success",
    )):
        return "successful_authentication"

    if any(term in text for term in (
        "privileged activity", "privileged_activity",
        "privilege escalation",
    )):
        return "privileged_activity"

    if any(term in text for term in (
        "large data transfer", "large_data_transfer",
        "data exfiltration",
    )):
        return "large_data_transfer"

    if any(term in text for term in (
        "correlated events", "correlated_events",
        "login followed by transfer", "attack chain",
    )):
        return "correlated_events"

    return None




def line_supports(claim_type, raw_line):
    decoded_line = unquote(raw_line)

    if claim_type == "brute_force":
        return bool(re.search(
            r"failed password|authentication failure|failed login",
            decoded_line,
            re.IGNORECASE,
        ))

    if claim_type == "exploitation_attempt":
        return any(
            PATTERNS[pattern].search(decoded_line)
            for pattern in ("sql_injection", "path_traversal")
        )

    if claim_type == "successful_authentication":
        return bool(re.search(
            r"accepted password|accepted publickey|login successful|"
            r"successful login",
            decoded_line,
            re.IGNORECASE,
        ))

    if claim_type == "privileged_activity":
        return bool(re.search(
            r"sudo:|pam_unix\(sudo:session\)|"
            r"session opened for user",
            decoded_line,
            re.IGNORECASE,
        ))

    if claim_type == "large_data_transfer":
        # Match the status code and response size, even if more fields follow.
        match = re.search(r'"\s+(\d{3})\s+(\d+|-)', decoded_line)

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

    if claim_type == "correlated_events":
        # This requires validation across multiple cited lines.
        return False

    return False


    pattern = PATTERNS.get(claim_type)
    return bool(pattern and pattern.search(decoded_line))


def verify_claim(claim, log_lines):
    evidence_ids = claim.get("evidence_ids", [])

    if not isinstance(evidence_ids, list) or not evidence_ids:
        return {
            "status": "unverified",
            "reason": "No evidence IDs were cited.",
            "evidence_checks": [],
        }

    claim_type = identify_claim_type(claim)

    if claim_type is None:
        return {
            "status": "unverified",
            "reason": "No verification rule exists for this claim type.",
            "evidence_checks": [],
        }

    evidence_checks = []

    for evidence_id in evidence_ids:
        if evidence_id not in log_lines:
            evidence_checks.append({
                "evidence_id": evidence_id,
                "status": "fail",
                "reason": "Evidence ID does not exist in the loaded logs.",
            })
            continue

        raw_line = log_lines[evidence_id]

        if claim_type == "correlated_events":
            # The combined claim is checked after reviewing all its lines.
            evidence_checks.append({
                "evidence_id": evidence_id,
                "status": "review_required",
                "reason": "Correlation requires multiple supporting events.",
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

    if claim_type == "correlated_events":
        existing_lines = [
            log_lines[evidence_id]
            for evidence_id in evidence_ids
            if evidence_id in log_lines
        ]

        has_auth = any(
            re.search(
                r"accepted password|accepted publickey|login successful",
                line,
                re.IGNORECASE,
            )
            for line in existing_lines
        )

        has_transfer = any(
            line_supports("large_data_transfer", line)
            for line in existing_lines
        )

        passed = has_auth and has_transfer
        reason = (
            "Both authentication and large-transfer indicators were found."
            if passed
            else "The cited lines do not establish both required events."
        )
    else:
        passed = (
            len(evidence_checks) == len(evidence_ids)
            and all(check["status"] == "pass" for check in evidence_checks)
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

    # A claim is counted once, even if several evidence IDs fail.
    hallucination_count = sum(
        result["status"] == "unverified"
        for result in results
    )

    output = {
        "scenario": scenario_name,
        "total_claims": len(results),
        "verified_claims": len(results) - hallucination_count,
        "unverified_claims": hallucination_count,
        "claims": results,
        "limitations": [
            "Pattern matches are heuristic evidence checks, not proof of intent.",
            "Unsupported claims are flagged as unverified, not automatically proven false.",
            "Summary and mitigation statements are not individually checked.",
        ],
    }

    output_path = scenario_dir / "claim_validation.json"

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(output, file, indent=2)

    print(f"\nScenario: {scenario_name}")
    print(f"Claims checked: {output['total_claims']}")
    print(f"Verified: {output['verified_claims']}")
    print(f"Unverified: {output['unverified_claims']}")

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
