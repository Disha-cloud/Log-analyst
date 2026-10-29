"""Evaluate rule detections against synthetic ground truth."""
import json
import sys
from pathlib import Path

from parser.correlator import correlate
from parser.log_parser import parse_scenario

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DOCS_DIR = PROJECT_ROOT / "docs"


def ratio(a, b):
    return round(a / b, 4) if b else None


def evaluate_scenario(scenario_name, data_dir=DATA_DIR, save=True):
    scenario_dir = Path(data_dir) / scenario_name
    truth = json.loads((scenario_dir / "ground_truth.json").read_text(encoding="utf-8"))
    records, errors = parse_scenario(scenario_dir)
    findings = correlate(records)
    truth_ids = set(truth["suspicious_evidence_ids"])
    all_ids = set(truth["all_evidence_ids"])
    predicted = {eid for f in findings for eid in f["evidence_ids"]}
    tp, fp, fn = len(truth_ids & predicted), len(predicted - truth_ids), len(truth_ids - predicted)
    tn = len(all_ids - truth_ids - predicted)
    expected, fired = set(truth.get("expected_rules", [])), {f["rule_id"] for f in findings}
    result = {
        "scenario": scenario_name, "description": truth.get("description"),
        "lines": len(all_ids), "parse_errors": len(errors), "findings": len(findings),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "rules_expected": sorted(expected), "rules_fired": sorted(fired),
        "rules_missed": sorted(expected - fired), "rules_unexpected": sorted(fired - expected),
    }
    claims_path = scenario_dir / "claim_validation.json"
    if claims_path.exists():
        claims = json.loads(claims_path.read_text(encoding="utf-8"))
        result["claims_total"] = claims["total_claims"]
        result["claims_verified"] = claims["verified_claims"]
    if save:
        (scenario_dir / "evaluation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def fmt(value):
    return "N/A" if value is None else f"{value:.2f}"


def write_results(results):
    DOCS_DIR.mkdir(exist_ok=True)
    (DOCS_DIR / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    rows = ["| Scenario | Lines | Findings | TP | FP | FN | Precision | Recall | FPR | "
            "Missed rules | Unexpected rules | Claims verified |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in results:
        claims = (f"{r['claims_verified']}/{r['claims_total']}" if "claims_total" in r else "not run")
        rows.append(f"| {r['scenario']} | {r['lines']} | {r['findings']} | {r['tp']} | {r['fp']} | "
                    f"{r['fn']} | {fmt(r['precision'])} | {fmt(r['recall'])} | "
                    f"{fmt(r['false_positive_rate'])} | {', '.join(r['rules_missed']) or '-'} | "
                    f"{', '.join(r['rules_unexpected']) or '-'} | {claims} |")
    note = ("\n\nSynthetic data was designed alongside the rules, so these numbers measure "
            "internal consistency, not real-world accuracy.\n")
    (DOCS_DIR / "results.md").write_text("# Detection results\n\n" + "\n".join(rows) + note,
                                         encoding="utf-8")
    print("\n".join(rows))


if __name__ == "__main__":
    names = sys.argv[1:] or sorted(p.name for p in DATA_DIR.iterdir()
                                   if (p / "ground_truth.json").exists())
    write_results([evaluate_scenario(n) for n in names])