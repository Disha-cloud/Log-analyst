"""Adversarial evaluation: can the validator catch fabricated or wrong claims?"""
import json
import re
from pathlib import Path

from parser.log_parser import load_raw_lines
from validator.claim_validator import verify_claim

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DOCS_DIR = PROJECT_ROOT / "docs"


def find(lines, pattern, n=1):
    rx = re.compile(pattern)
    ids = [eid for eid, raw in lines.items() if rx.search(raw)]
    if len(ids) < n:
        raise ValueError(f"Pattern not found enough times: {pattern}. Regenerate data.")
    return ids[:n]


def c(stage, ids, explanation):
    return {"stage": stage, "explanation": explanation, "evidence_ids": ids}


def build_cases():
    s1, s2, s3, s5 = (load_raw_lines(DATA_DIR / s) for s in ("S1", "S2", "S3", "S5"))
    fails = find(s1, r"Failed password for admin from 10\.0\.5\.23", 3)
    acc = find(s1, r"Accepted password for admin from 10\.0\.5\.23")
    sudo = find(s1, r"sudo: admin :")
    benign_login = find(s1, r"Accepted \w+ for alice")
    cron = find(s1, r"CRON")
    benign_web = find(s1, r'" 200 \d+ ')
    sql = find(s2, r"UNION|%27")
    trav = find(s2, r"etc/passwd")
    s3_login = find(s3, r"Accepted password for carol from 10\.0\.7\.77")
    s3_big = find(s3, r"customers_full")
    s5_typo = find(s5, r"Failed password for bob")
    s5_backup = find(s5, r"nightly")
    wrong_file = ["access.log:" + fails[0].split(":")[1]]

    V, F, B = "valid_control", "fabricated", "known_blind_spot"
    return [
        ("V1", V, "Real brute-force lines", "S1", c("authentication_attempt", fails, "Repeated failures"), "verified"),
        ("V2", V, "Failures then success", "S1", c("successful_authentication", fails[:2] + acc, "Login after failures"), "verified"),
        ("V3", V, "Login then sudo", "S1", c("privileged_activity", acc + sudo, "Sudo after login"), "verified"),
        ("V4", V, "SQLi and traversal requests", "S2", c("exploitation_attempt", sql + trav, "Web attack attempts"), "verified"),
        ("V5", V, "Login linked to large download", "S3", c("correlated_events", s3_login + s3_big, "Login then download"), "verified"),
        ("F1", F, "Nonexistent ID", "S1", c("authentication_attempt", ["auth.log:L9999"], "Brute force"), "unverified"),
        ("F2", F, "Malformed ID", "S1", c("authentication_attempt", ["line 42"], "Brute force"), "unverified"),
        ("F3", F, "No evidence at all", "S1", c("privileged_activity", [], "Root obtained"), "unverified"),
        ("F4", F, "Invented stage and event", "S1", c("ransomware_deployment", fails[:1], "Attacker encrypted all files"), "unverified"),
        ("F5", F, "Benign login cited as brute force", "S1", c("authentication_attempt", benign_login, "Brute force"), "unverified"),
        ("F6", F, "Benign request cited as exploit", "S1", c("exploitation_attempt", benign_web, "SQL injection"), "unverified"),
        ("F7", F, "Small response cited as large transfer", "S1", c("large_data_transfer", benign_web, "Data exfiltration"), "unverified"),
        ("F8", F, "Correlation with login only", "S3", c("correlated_events", s3_login, "Login then exfil"), "unverified"),
        ("F9", F, "Correlation with transfer only", "S3", c("correlated_events", s3_big, "Login then exfil"), "unverified"),
        ("F10", F, "Privilege claim without sudo line", "S1", c("privileged_activity", acc, "Became root"), "unverified"),
        ("F11", F, "Success claim with only failures", "S1", c("successful_authentication", fails[:2], "Attacker got in"), "unverified"),
        ("F12", F, "Mixed real and fake IDs", "S1", c("authentication_attempt", fails[:1] + ["auth.log:L9998"], "Brute force"), "unverified"),
        ("F13", F, "Right number, wrong file", "S1", c("authentication_attempt", wrong_file, "Brute force"), "unverified"),
        ("F14", F, "Cron job cited as sudo", "S1", c("privileged_activity", cron, "Privilege escalation"), "unverified"),
        ("F15", F, "Auth failure cited as web exploit", "S1", c("exploitation_attempt", fails[:1], "SQL injection"), "unverified"),
        ("B1", B, "Single typo cited as brute force", "S5", c("authentication_attempt", s5_typo, "Brute force attack"), "verified"),
        ("B2", B, "Backup cited as exfiltration", "S5", c("large_data_transfer", s5_backup, "Data exfiltration"), "verified"),
    ]


def run():
    lines_cache, rows = {}, []
    for case_id, category, description, scenario, claim, expected in build_cases():
        lines = lines_cache.setdefault(scenario, load_raw_lines(DATA_DIR / scenario))
        result = verify_claim(claim, lines)
        reasons = [ch["reason"] for ch in result["evidence_checks"] if ch["status"] == "fail"]
        rows.append({"id": case_id, "category": category, "description": description,
                     "scenario": scenario, "stage": claim["stage"],
                     "evidence_ids": claim["evidence_ids"], "expected": expected,
                     "actual": result["status"], "as_expected": result["status"] == expected,
                     "reason": "; ".join(reasons) or result["reason"]})
    fabricated = [r for r in rows if r["category"] == "fabricated"]
    valid = [r for r in rows if r["category"] == "valid_control"]
    blind = [r for r in rows if r["category"] == "known_blind_spot"]
    summary = {
        "total_cases": len(rows),
        "fabricated_caught": sum(r["actual"] == "unverified" for r in fabricated),
        "fabricated_total": len(fabricated),
        "valid_accepted": sum(r["actual"] == "verified" for r in valid),
        "valid_total": len(valid),
        "blind_spots_passed_through": sum(r["actual"] == "verified" for r in blind),
        "blind_spots_total": len(blind),
        "all_as_expected": all(r["as_expected"] for r in rows),
    }
    DOCS_DIR.mkdir(exist_ok=True)
    (DOCS_DIR / "adversarial.json").write_text(json.dumps({"summary": summary, "cases": rows}, indent=2), encoding="utf-8")
    md = ["# Adversarial validator evaluation", "",
          f"- Fabricated claims caught: **{summary['fabricated_caught']}/{summary['fabricated_total']}**",
          f"- Valid claims accepted: **{summary['valid_accepted']}/{summary['valid_total']}**",
          f"- Known blind spots (true lines, wrong interpretation) passed through: "
          f"**{summary['blind_spots_passed_through']}/{summary['blind_spots_total']}**", "",
          "| ID | Category | Case | Expected | Actual | OK | Reason |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['id']} | {r['category']} | {r['description']} | {r['expected']} | "
                  f"{r['actual']} | {'yes' if r['as_expected'] else 'NO'} | {r['reason']} |")
    md += ["", "Blind spots show the validator checks whether cited lines support the event type, "
               "not whether the interpretation (malicious vs benign) is correct."]
    (DOCS_DIR / "adversarial.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md[:6]))
    return summary


if __name__ == "__main__":
    run()