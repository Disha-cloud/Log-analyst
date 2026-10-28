
import json
from pathlib import Path

from parser.correlator import analyze_scenario
from parser.log_parser import parse_scenario


PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_DIR / "data"


def evaluate_scenario(scenario_dir):
    """Compare rule-based detections against ground truth."""

    ground_truth_path = scenario_dir / "ground_truth.json"

    with open(ground_truth_path, "r", encoding="utf-8") as file:
        ground_truth = json.load(file)

    records, parse_errors = parse_scenario(scenario_dir)

    if parse_errors:
        raise ValueError(
            f"{scenario_dir.name} has {len(parse_errors)} parsing errors. "
            "Fix them before evaluating detection accuracy."
        )

    analysis = analyze_scenario(scenario_dir)
    findings = analysis["suspicious_groups"]

    # Map each line ID to its parsed record.
    records_by_line_id = {}

    for record in records:
        line_id = record["line_id"]
        records_by_line_id.setdefault(line_id, []).append(record)

    # Convert ground-truth line IDs to file-qualified IDs.
    actual_malicious = set()

    for line_id in ground_truth["malicious_line_ids"]:
        matches = records_by_line_id.get(line_id, [])

        if len(matches) != 1:
            raise ValueError(
                f"{scenario_dir.name}: Ground-truth ID {line_id} "
                f"matches {len(matches)} records. "
                "Use file-qualified IDs in ground_truth.json."
            )

        record = matches[0]

        filename = (
            "auth.log"
            if record["log_type"] == "auth"
            else "access.log"
        )

        actual_malicious.add(f"{filename}:{line_id}")

    # Collect all records flagged by the rule-based detector.
    detected_malicious = set()

    for finding in findings:
        detected_malicious.update(finding["evidence_ids"])

    # Build the complete set of file-qualified record IDs.
    all_record_ids = set()

    for record in records:
        filename = (
            "auth.log"
            if record["log_type"] == "auth"
            else "access.log"
        )

        all_record_ids.add(f"{filename}:{record['line_id']}")

    # Reject detections that reference nonexistent records.
    unknown_detections = detected_malicious - all_record_ids

    if unknown_detections:
        raise ValueError(
            f"Unknown detected evidence IDs: {sorted(unknown_detections)}"
        )

    # Calculate confusion-matrix counts.
    tp = len(actual_malicious & detected_malicious)
    fp = len(detected_malicious - actual_malicious)
    fn = len(actual_malicious - detected_malicious)
    tn = len(all_record_ids - actual_malicious - detected_malicious)

    # Calculate evaluation metrics.
    precision = (
        tp / (tp + fp)
        if tp + fp else None
    )

    recall = (
        tp / (tp + fn)
        if tp + fn else None
    )

    specificity = (
        tn / (tn + fp)
        if tn + fp else None
    )

    accuracy = (
        (tp + tn) / (tp + fp + fn + tn)
        if tp + fp + fn + tn else None
    )

    f1_score = (
        2 * precision * recall / (precision + recall)
        if precision is not None
        and recall is not None
        and precision + recall > 0
        else None
    )

    return {
        "scenario": scenario_dir.name,
        "total_records": len(all_record_ids),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "accuracy": accuracy,
        "f1_score": f1_score,
    }


def display_metric(value):
    """Format a metric as a percentage or N/A."""
    return "N/A" if value is None else f"{value:.2%}"


def main():
    results = []

    for scenario_dir in sorted(DATA_DIR.glob("S*")):
        if not scenario_dir.is_dir():
            continue

        if not (scenario_dir / "ground_truth.json").exists():
            continue

        result = evaluate_scenario(scenario_dir)
        results.append(result)

        print(f"\nScenario: {result['scenario']}")
        print(f"Total records: {result['total_records']}")
        print(f"True positives: {result['tp']}")
        print(f"False positives: {result['fp']}")
        print(f"False negatives: {result['fn']}")
        print(f"True negatives: {result['tn']}")
        print(f"Precision: {display_metric(result['precision'])}")
        print(f"Recall: {display_metric(result['recall'])}")
        print(f"Specificity: {display_metric(result['specificity'])}")
        print(f"Accuracy: {display_metric(result['accuracy'])}")
        print(f"F1-score: {display_metric(result['f1_score'])}")

    if not results:
        print("No scenarios with ground_truth.json were found.")
        return

    # Calculate overall metrics from the combined counts.
    totals = {
        key: sum(result[key] for result in results)
        for key in ("tp", "fp", "fn", "tn")
    }

    tp = totals["tp"]
    fp = totals["fp"]
    fn = totals["fn"]
    tn = totals["tn"]

    overall_precision = (
        tp / (tp + fp)
        if tp + fp else None
    )

    overall_recall = (
        tp / (tp + fn)
        if tp + fn else None
    )

    overall_specificity = (
        tn / (tn + fp)
        if tn + fp else None
    )

    overall_accuracy = (
        (tp + tn) / (tp + fp + fn + tn)
        if tp + fp + fn + tn else None
    )

    overall_f1 = (
        2 * overall_precision * overall_recall
        / (overall_precision + overall_recall)
        if overall_precision is not None
        and overall_recall is not None
        and overall_precision + overall_recall > 0
        else None
    )

    print("\n========== OVERALL RESULTS ==========")
    print(f"Total records: {sum(r['total_records'] for r in results)}")
    print(f"True positives: {tp}")
    print(f"False positives: {fp}")
    print(f"False negatives: {fn}")
    print(f"True negatives: {tn}")
    print(f"Precision: {display_metric(overall_precision)}")
    print(f"Recall: {display_metric(overall_recall)}")
    print(f"Specificity: {display_metric(overall_specificity)}")
    print(f"Accuracy: {display_metric(overall_accuracy)}")
    print(f"F1-score: {display_metric(overall_f1)}")


if __name__ == "__main__":
    main()
