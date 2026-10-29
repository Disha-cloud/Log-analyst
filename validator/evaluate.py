"""Evaluate rule detections against ground truth; describe unlabeled (real-world) runs."""
import json
import sys
from collections import Counter
from pathlib import Path

from parser.correlator import correlate
from parser.log_parser import parse_scenario

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DOCS_DIR = PROJECT_ROOT / "docs"


def ratio(a, b):
    return round(a / b, 4) if b else None


def load_truth(scenario_dir):
    return json.loads((scenario_dir / "ground_truth.json").read_text(encoding="utf-8"))


def claim_stats(scenario_dir):
    path = scenario_dir / "claim_validation.json"
    if not path.exists():
        return {}
    c = json.loads(path.read_text(encoding="utf-8"))
    return {"claims_total": c["total_claims"], "claims_verified": c["verified_claims"],
            "mitre_match": c.get("mitre_match")}


def evaluate_scenario(scenario_name, data_dir=DATA_DIR, save=True):
    scenario_dir = Path(data_dir) / scenario_name
    truth = load_truth(scenario_dir)
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
        **claim_stats(scenario_dir),
    }
    if save:
        (scenario_dir / "evaluation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def describe_unlabeled(scenario_name, data_dir=DATA_DIR):
    scenario_dir = Path(data_dir) / scenario_name
    truth = load_truth(scenario_dir)
    records, errors = parse_scenario(scenario_dir)
    findings = correlate(records)
    return {"scenario": scenario_name, "source": truth.get("source"),
            "lines": len(truth["all_evidence_ids"]), "parse_errors": len(errors),
            "masked_ips": truth.get("masked_ip_count"), "findings": len(findings),
            "rules_fired": dict(Counter(f["rule_id"] for f in findings)),
            "distinct_ips_flagged": len({f["ip"] for f in findings if f.get("ip")}),
            **claim_stats(scenario_dir)}


def fmt(value):
    return "N/A" if value is None else f"{value:.2f}"


def frac(r, key):
    return f"{r[key]}/{r['claims_total']}" if r.get(key) is not None and "claims_total" in r else "not run"


def write_results(labeled, unlabeled):
    DOCS_DIR.mkdir(exist_ok=True)
    (DOCS_DIR / "results.json").write_text(json.dumps(labeled, indent=2), encoding="utf-8")
    (DOCS_DIR / "realworld.json").write_text(json.dumps(unlabeled, indent=2), encoding="utf-8")
    rows = ["| Scenario | Lines | Findings | TP | FP | FN | Precision | Recall | FPR | "
            "Missed rules | Unexpected rules | Claims verified | MITRE match |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in labeled:
        rows.append(f"| {r['scenario']} | {r['lines']} | {r['findings']} | {r['tp']} | {r['fp']} | "
                    f"{r['fn']} | {fmt(r['precision'])} | {fmt(r['recall'])} | "
                    f"{fmt(r['false_positive_rate'])} | {', '.join(r['rules_missed']) or '-'} | "
                    f"{', '.join(r['rules_unexpected']) or '-'} | {frac(r, 'claims_verified')} | "
                    f"{frac(r, 'mitre_match')} |")
    md = ["# Detection results", "", "## Synthetic labeled scenarios", ""] + rows + [
        "", "Synthetic data was designed alongside the rules, so these numbers measure "
            "internal consistency, not real-world accuracy."]
    if unlabeled:
        md += ["", "## Real-world unlabeled runs", "",
               "| Scenario | Lines | Parse errors | Masked IPs | Findings | Rules fired | IPs flagged | "
               "Claims verified | MITRE match |", "|---|---|---|---|---|---|---|---|---|"]
        for r in unlabeled:
            rules = ", ".join(f"{k}: {v}" for k, v in r["rules_fired"].items()) or "-"
            md.append(f"| {r['scenario']} | {r['lines']} | {r['parse_errors']} | {r['masked_ips']} | "
                      f"{r['findings']} | {rules} | {r['distinct_ips_flagged']} | "
                      f"{frac(r, 'claims_verified')} | {frac(r, 'mitre_match')} |")
        md += ["", "No ground-truth labels: precision and recall cannot be computed for real-world data."]
    (DOCS_DIR / "results.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))


if __name__ == "__main__":
    names = sys.argv[1:] or sorted(p.name for p in DATA_DIR.iterdir()
                                   if (p / "ground_truth.json").exists())
    labeled, unlabeled = [], []
    for n in names:
        if load_truth(DATA_DIR / n).get("labels_available", True):
            labeled.append(evaluate_scenario(n))
        else:
            unlabeled.append(describe_unlabeled(n))
    write_results(labeled, unlabeled)