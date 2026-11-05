"""Evaluate the trained RandomForest detector in the same format as validator/evaluate.py.

The model predicts per IP. To compare with the rule engine, every log line belonging to a
flagged IP is counted as "predicted suspicious", then TP/FP/FN/TN, precision, recall and
FPR are computed over evidence IDs exactly as the rule engine is scored. Lines with no IP
(e.g. a sudo line) can never be flagged by this model.

Default run scores:
  * the held-out test scenarios stored in the saved model (never trained on), alongside
    the rule engine on the SAME scenarios (validator.evaluate.evaluate_scenario, save=False);
  * REAL_SSH (unlabeled): described, and compared with the IPs the rule engine flagged.

--transfer additionally trains on everything EXCEPT one attack family (S1 / S2 / S3,
fixed scenario + all its variants) and tests on that family: can the model detect an attack
type it has never seen? Rules are scored on the same scenarios.

Usage:
    python -m model.evaluate_detector
    python -m model.evaluate_detector --transfer
    python -m model.evaluate_detector S2_v003 S5 REAL_SSH      # explicit scenarios
Writes docs/detector_results.{json,md}; does not touch rule-engine outputs.
"""
import argparse
import json
from pathlib import Path

import joblib

from features.extract_features import FEATURE_COLUMNS, extract_features, records_to_frame, scenario_dir
from model.train_detector import DEFAULT_OUT, build_dataset, family, labeled_scenarios, new_forest
from parser.correlator import correlate
from parser.log_parser import parse_scenario
from validator.evaluate import evaluate_scenario, fmt, load_truth, ratio

DOCS_DIR = Path(__file__).resolve().parents[1] / "docs"


def predict_flagged(clf, features, records, window_minutes):
    """Return (flagged_groups_df, set of evidence IDs belonging to flagged groups)."""
    feats = extract_features(records, window_minutes)
    if feats.empty:
        return feats, set()
    flagged = feats[clf.predict(feats[features]) == 1]
    keys = ["ip"] + (["window_start"] if window_minutes else [])
    lines = records_to_frame(records)
    if window_minutes:
        lines["window_start"] = lines["timestamp"].dt.floor(f"{int(window_minutes)}min")
    hit = lines.merge(flagged[keys], on=keys, how="inner")
    return flagged, set(hit["evidence_id"])


def evaluate_labeled(name, clf, features, window_minutes):
    sdir = scenario_dir(name)
    truth = load_truth(sdir)
    records, errors = parse_scenario(sdir)
    flagged, predicted = predict_flagged(clf, features, records, window_minutes)
    truth_ids, all_ids = set(truth["suspicious_evidence_ids"]), set(truth["all_evidence_ids"])
    tp, fp, fn = len(truth_ids & predicted), len(predicted - truth_ids), len(truth_ids - predicted)
    tn = len(all_ids - truth_ids - predicted)
    rules = evaluate_scenario(name, data_dir=sdir.parent, save=False)
    return {
        "scenario": name, "family": family(name), "description": truth.get("description"),
        "lines": len(all_ids), "parse_errors": len(errors), "findings": len(flagged),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
        "flagged_ips": sorted(flagged["ip"].unique()) if len(flagged) else [],
        "rules": {k: rules[k] for k in ("findings", "tp", "fp", "fn", "tn", "precision", "recall",
                                        "false_positive_rate")},
    }


def describe_unlabeled(name, clf, features, window_minutes):
    sdir = scenario_dir(name)
    truth = load_truth(sdir)
    records, errors = parse_scenario(sdir)
    flagged, _ = predict_flagged(clf, features, records, window_minutes)
    model_ips = set(flagged["ip"]) if len(flagged) else set()
    rule_ips = {f["ip"] for f in correlate(records) if f.get("ip")}
    return {
        "scenario": name, "source": truth.get("source"),
        "lines": len(truth["all_evidence_ids"]), "parse_errors": len(errors),
        "masked_ips": truth.get("masked_ip_count"), "findings": len(flagged),
        "distinct_ips_flagged": len(model_ips),
        "rule_engine_ips_flagged": len(rule_ips),
        "agree_with_rules": len(model_ips & rule_ips),
        "model_only": len(model_ips - rule_ips), "rules_only": len(rule_ips - model_ips),
    }


def pool(rows, who):
    """Micro-average line-level counts across scenarios. who: None for ML, 'rules' for rules."""
    get = (lambda r, k: r[k]) if who is None else (lambda r, k: r["rules"][k])
    tp, fp, fn, tn = (sum(get(r, k) for r in rows) for k in ("tp", "fp", "fn", "tn"))
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": ratio(tp, tp + fp),
            "recall": ratio(tp, tp + fn), "false_positive_rate": ratio(fp, fp + tn)}


def summarize(rows):
    groups = {}
    for r in rows:
        key = r["family"] if r["family"] in ("S1", "S2", "S3") else "benign (S4/S5)"
        groups.setdefault(key, []).append(r)
    out = [{"group": g, "scenarios": len(rs), "ml": pool(rs, None), "rules": pool(rs, "rules")}
           for g, rs in sorted(groups.items())]
    out.append({"group": "ALL", "scenarios": len(rows), "ml": pool(rows, None), "rules": pool(rows, "rules")})
    return out


def transfer(window_minutes, seed):
    """Leave one attack family out entirely, train on the rest, test on the family."""
    names = labeled_scenarios()
    df = build_dataset(window_minutes, names)
    results = []
    for fam in ("S1", "S2", "S3"):
        held = [n for n in names if family(n) in ((fam, "S1_mitigated") if fam == "S1" else (fam,))]
        train = df[~df["scenario"].isin(held)]
        clf = new_forest(seed).fit(train[FEATURE_COLUMNS], train["is_suspicious"])
        rows = [evaluate_labeled(n, clf, FEATURE_COLUMNS, window_minutes) for n in held]
        results.append({"held_out_family": fam, "scenarios": len(held), "train_positives":
                        int(train.is_suspicious.sum()), "ml": pool(rows, None), "rules": pool(rows, "rules")})
    return results


def metric_cells(m):
    return f"{m['tp']} | {m['fp']} | {m['fn']} | {fmt(m['precision'])} | {fmt(m['recall'])} | {fmt(m['false_positive_rate'])}"


def write_results(labeled, unlabeled, mode, transfer_rows):
    DOCS_DIR.mkdir(exist_ok=True)
    summary = summarize(labeled) if labeled else []
    (DOCS_DIR / "detector_results.json").write_text(json.dumps(
        {"mode": mode, "summary": summary, "labeled": labeled, "unlabeled": unlabeled,
         "transfer": transfer_rows}, indent=2), encoding="utf-8")
    md = ["# ML detector results (RandomForest)", "", f"Model: {mode}", ""]
    if summary:
        md += ["## Held-out summary: ML detector vs rule engine (same scenarios)", "",
               "| Group | Scenarios | ML TP | ML FP | ML FN | ML Precision | ML Recall | ML FPR | "
               "Rules TP | Rules FP | Rules FN | Rules Precision | Rules Recall | Rules FPR |",
               "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for g in summary:
            md.append(f"| {g['group']} | {g['scenarios']} | {metric_cells(g['ml'])} | {metric_cells(g['rules'])} |")
        md += ["", "Counts are per log line, pooled across scenarios (same scoring as docs/results.md). "
                   "Both detectors are scored on identical, held-out scenarios from the same synthetic "
                   "generator the rules were designed alongside."]
    if transfer_rows:
        md += ["", "## Transfer to an unseen attack type (leave one family out)", "",
               "| Held-out family | Scenarios | ML TP | ML FP | ML FN | ML Precision | ML Recall | ML FPR | "
               "Rules TP | Rules FP | Rules FN | Rules Precision | Rules Recall | Rules FPR |",
               "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for t in transfer_rows:
            md.append(f"| {t['held_out_family']} | {t['scenarios']} | {metric_cells(t['ml'])} | "
                      f"{metric_cells(t['rules'])} |")
        md += ["", "The model was trained with that family's fixed scenario and all its variants removed "
                   "(for S1 this includes S1_mitigated)."]
    if labeled:
        md += ["", "## Per-scenario (ML detector)", "",
               "| Scenario | Lines | Findings | TP | FP | FN | Precision | Recall | FPR |",
               "|---|---|---|---|---|---|---|---|---|"]
        for r in labeled:
            md.append(f"| {r['scenario']} | {r['lines']} | {r['findings']} | {r['tp']} | {r['fp']} | "
                      f"{r['fn']} | {fmt(r['precision'])} | {fmt(r['recall'])} | "
                      f"{fmt(r['false_positive_rate'])} |")
        md += ["", "Findings = flagged IPs; TP/FP/FN/TN are per log line."]
    if unlabeled:
        md += ["", "## Real-world unlabeled runs", "",
               "| Scenario | Lines | Parse errors | Masked IPs | Findings | IPs flagged | "
               "Rule-engine IPs | Agree | Model only | Rules only |",
               "|---|---|---|---|---|---|---|---|---|---|"]
        for r in unlabeled:
            md.append(f"| {r['scenario']} | {r['lines']} | {r['parse_errors']} | {r['masked_ips']} | "
                      f"{r['findings']} | {r['distinct_ips_flagged']} | {r['rule_engine_ips_flagged']} | "
                      f"{r['agree_with_rules']} | {r['model_only']} | {r['rules_only']} |")
        md += ["", "No ground-truth labels: precision and recall cannot be computed for real-world data."]
    (DOCS_DIR / "detector_results.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenarios", nargs="*", help="default: the model's held-out scenarios + REAL_SSH")
    ap.add_argument("--model", default=str(DEFAULT_OUT))
    ap.add_argument("--transfer", action="store_true", help="also run leave-one-attack-family-out")
    args = ap.parse_args()

    bundle = joblib.load(args.model)
    features, window, clf = bundle["features"], bundle["window_minutes"], bundle["model"]
    trained_on = set(bundle.get("train_scenarios", []))
    names = args.scenarios or (bundle.get("test_scenarios", []) + ["REAL_SSH"])
    mode = (f"saved model {Path(args.model).name}, trained on {len(trained_on)} scenarios, "
            f"evaluated on held-out scenarios")

    labeled, unlabeled = [], []
    for name in names:
        if name in trained_on:
            print(f"note: {name} was in the training data; its score is not held-out")
        if load_truth(scenario_dir(name)).get("labels_available", True):
            labeled.append(evaluate_labeled(name, clf, features, window))
        else:
            unlabeled.append(describe_unlabeled(name, clf, features, window))
    write_results(labeled, unlabeled, mode, transfer(window, bundle.get("seed", 42)) if args.transfer else None)


if __name__ == "__main__":
    main()
