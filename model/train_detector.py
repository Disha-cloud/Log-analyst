"""Train a RandomForest that flags suspicious IPs from per-IP log features.

Dataset: every labeled synthetic scenario, i.e. the fixed S1, S1_mitigated, S2, S3, S4, S5
in data/ plus the randomized variants in data_variants/ (generate them with
`python -m generator.generate_logs --variants 40`). REAL_SSH and UPLOAD have no labels
and are excluded. Label = `is_suspicious` from ground_truth.json (per IP).

Split: SCENARIO-level 80/20, not row-level, so no scenario contributes rows to both sides.
  * test = ~20% of the variants of each attack family (S1/S2/S3), chosen at random,
           plus the fixed benign baselines S4 and S5 (S5 = hard negatives).
  * train = everything else (including fixed S1, S1_mitigated, S2, S3).
The split is stored in the saved model so model.evaluate_detector scores exactly the
held-out scenarios.

Usage:
    python -m model.train_detector
    python -m model.train_detector --seed 7 --window 5 -o model/detector.joblib
"""
import argparse
import random
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score

from features.extract_features import DATA, FEATURE_COLUMNS, scenario_dir, scenario_features
from generator.generate_logs import VARIANTS_DIR

FIXED_LABELED = ["S1", "S1_mitigated", "S2", "S3", "S4", "S5"]
HELD_OUT_FIXED = ["S4", "S5"]      # benign baselines, never trained on
TEST_FRACTION = 0.2
DEFAULT_OUT = Path(__file__).resolve().parent / "detector.joblib"


def family(name):
    """S1_v007 -> S1; fixed names map to themselves."""
    return name.split("_v")[0]


def labeled_scenarios():
    names = [n for n in FIXED_LABELED if (DATA / n).is_dir()]
    if VARIANTS_DIR.is_dir():
        names += sorted(p.name for p in VARIANTS_DIR.iterdir() if (p / "ground_truth.json").exists())
    return names


def split_scenarios(names, seed=42, test_fraction=TEST_FRACTION):
    """Scenario-level split: per attack family, hold out round(20%) of its variants."""
    rng = random.Random(seed)
    test = [n for n in HELD_OUT_FIXED if n in names]
    by_family = {}
    for n in names:
        if "_v" in n:
            by_family.setdefault(family(n), []).append(n)
    for members in by_family.values():
        members = sorted(members)
        rng.shuffle(members)
        test += members[:max(1, round(len(members) * test_fraction))]
    train = [n for n in names if n not in test]
    return sorted(train), sorted(test)


def build_dataset(window_minutes=None, names=None):
    frames = [scenario_features(n, window_minutes) for n in (names or labeled_scenarios())]
    df = pd.concat(frames, ignore_index=True)
    df = df.dropna(subset=["is_suspicious"])
    df["is_suspicious"] = df["is_suspicious"].astype(int)
    return df


def new_forest(seed=42, trees=200):
    return RandomForestClassifier(n_estimators=trees, class_weight="balanced",
                                  random_state=seed, n_jobs=-1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--window", type=int, default=None, help="window minutes (default: per-IP rows)")
    ap.add_argument("--seed", type=int, default=42, help="seed for the scenario split and the forest")
    ap.add_argument("--trees", type=int, default=200)
    ap.add_argument("-o", "--output", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    names = labeled_scenarios()
    train_names, test_names = split_scenarios(names, args.seed)
    df = build_dataset(args.window, names)
    train, test = df[df["scenario"].isin(train_names)], df[df["scenario"].isin(test_names)]
    print(f"scenarios: {len(train_names)} train / {len(test_names)} held-out "
          f"({sum('_v' in n for n in names)} variants + {sum('_v' not in n for n in names)} fixed)")
    print(f"rows:      {len(train)} train ({int(train.is_suspicious.sum())} pos) / "
          f"{len(test)} test ({int(test.is_suspicious.sum())} pos)  "
          f"[{'per-IP' if not args.window else f'{args.window}-min windows'}]")
    if test.is_suspicious.sum() == 0 or train.is_suspicious.sum() == 0:
        raise SystemExit("need positives on both sides; generate variants first: "
                         "python -m generator.generate_logs --variants 40")

    clf = new_forest(args.seed, args.trees).fit(train[FEATURE_COLUMNS], train["is_suspicious"])
    y_test, pred = test["is_suspicious"], clf.predict(test[FEATURE_COLUMNS])
    kw = dict(zero_division=0)
    print("\nHeld-out scenarios, per-IP rows:")
    print(f"precision: {precision_score(y_test, pred, **kw):.3f}")
    print(f"recall:    {recall_score(y_test, pred, **kw):.3f}")
    print(f"f1:        {f1_score(y_test, pred, **kw):.3f}")
    print("\nconfusion matrix [[TN FP] [FN TP]]:")
    print(confusion_matrix(y_test, pred, labels=[0, 1]))
    print("\n" + classification_report(y_test, pred, labels=[0, 1],
                                       target_names=["benign", "suspicious"], **kw))
    print("top feature importances:")
    imp = pd.Series(clf.feature_importances_, index=FEATURE_COLUMNS).sort_values(ascending=False)
    print(imp.head(6).round(3).to_string())

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "features": FEATURE_COLUMNS, "window_minutes": args.window,
                 "seed": args.seed, "train_scenarios": train_names, "test_scenarios": test_names}, out)
    print(f"\nsaved model to {out}")


if __name__ == "__main__":
    main()
