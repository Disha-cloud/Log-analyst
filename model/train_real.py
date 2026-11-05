"""Train/evaluate a per-IP RandomForest on real Loghub OpenSSH logs (weak labels, see features/real_ssh.py).

    python -m model.train_real /path/to/SSH.log
Evaluation is 5-fold cross-validation GROUPED BY IP (an IP never appears in both train and test),
compared with a plain threshold baseline. `accepted` is excluded from features because the benign
label is defined by it (it would leak the label).
"""
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_fscore_support
from sklearn.model_selection import StratifiedGroupKFold

from features.real_ssh import FEATURE_COLUMNS, chunk_features, global_labels, read_events

ROOT = Path(__file__).resolve().parents[1]
FEATURES = [c for c in FEATURE_COLUMNS if c != "accepted"]
SEED = 42
REVIEW_CSV = ROOT / "docs" / "real_label_review_mixed_ips.csv"
REPEATS = 5


def review_overrides(treat_excluded_as=None):
    """Human-reviewed labels for the mixed (failures + successful login) IPs: {ip: benign|malicious|exclude}."""
    if not REVIEW_CSV.exists():   # the review file holds real IPs and is kept local, not published
        return {}
    d = pd.read_csv(REVIEW_CSV)
    return {r.ip: (treat_excluded_as if r.label_used == "exclude" and treat_excluded_as else r.label_used)
            for r in d.itertuples()}


def labeled_frame(df, labels, overrides):
    df = df.copy()
    df["label"] = df.ip.map(lambda ip: overrides.get(ip, labels[ip]))
    return df[~df.label.isin(["ambiguous", "exclude"])].reset_index(drop=True)


def cv_predict(lab, seeds=REPEATS):
    """Repeated stratified group k-fold by IP. Returns list of out-of-fold prediction arrays."""
    y = (lab.label == "malicious").astype(int).to_numpy()
    X, groups = lab[FEATURES].to_numpy(), lab.ip.to_numpy()
    runs = []
    for seed in range(seeds):
        oof = np.zeros(len(lab), dtype=int)
        for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed).split(X, y, groups):
            oof[te] = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                             random_state=seed, n_jobs=-1).fit(X[tr], y[tr]).predict(X[te])
        runs.append(oof)
    return y, runs


def summarize(y, runs):
    keys = ("precision", "recall", "f1")
    rows = [prf(y, r) for r in runs]
    return {k: {"mean": round(float(np.mean([r[k] for r in rows])), 3),
                "sd": round(float(np.std([r[k] for r in rows])), 3)} for k in keys}


def new_forest():
    return RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=SEED, n_jobs=-1)


def prf(y, p):
    pr, rc, f1, _ = precision_recall_fscore_support(y, p, average="binary", zero_division=0)
    return {"precision": round(pr, 3), "recall": round(rc, 3), "f1": round(f1, 3),
            "tp": int(((y == 1) & (p == 1)).sum()), "fp": int(((y == 0) & (p == 1)).sum()),
            "fn": int(((y == 1) & (p == 0)).sum()), "tn": int(((y == 0) & (p == 0)).sum())}


def baseline(df, k=5):
    """What a defender would do without ML: flag when this chunk shows >= k failed-auth events."""
    return ((df.failed_pw + df.invalid_user + df.pam_fail) >= k).astype(int).to_numpy()


def main(log_path, out_json=ROOT / "docs" / "real_detector_results.json"):
    events = read_events(log_path)
    labels, _ = global_labels(events)
    df = chunk_features(events)
    result = {"log": str(log_path), "repeats": REPEATS}
    for name, ov in (("main", review_overrides()), ("sensitivity_suspicious_as_benign", review_overrides("benign")),
                     ("sensitivity_suspicious_as_malicious", review_overrides("malicious"))):
        lab = labeled_frame(df, labels, ov)
        y, runs = cv_predict(lab)
        hard = lab.ip.isin([ip for ip, v in ov.items() if v == "benign"]).to_numpy()
        mean_hard_fp = float(np.mean([r[hard].mean() for r in runs]))
        res = {"ips_malicious": int(lab[y == 1].ip.nunique()), "ips_benign": int(lab[y == 0].ip.nunique()),
               "rows_malicious": int(y.sum()), "rows_benign": int((1 - y).sum()),
               "random_forest": summarize(y, runs),
               "benign_fp_rate_all": round(float(np.mean([(r[y == 0]).mean() for r in runs])), 3),
               "reviewed_hard_negative_fp_rate": round(mean_hard_fp, 3),
               "reviewed_hard_negative_rows": int(hard.sum()),
               "baseline_k3": prf(y, baseline(lab, 3)), "baseline_k5": prf(y, baseline(lab, 5))}
        result[name] = res
        if name == "main":
            main_lab, main_y, main_runs = lab, y, runs
    # per-IP view for the reviewed hard negatives (fraction of chunk rows flagged, averaged over repeats)
    per_ip = []
    for ip in review_overrides():
        m = (main_lab.ip == ip).to_numpy()
        if m.any():
            per_ip.append(round(float(np.mean([r[m].mean() for r in main_runs])), 2))
    result["reviewed_hard_negative_flag_rates"] = sorted(per_ip)   # IPs deliberately not recorded
    model = new_forest().fit(main_lab[FEATURES].to_numpy(), main_y)
    result["top_features"] = [(n, round(float(v), 3)) for n, v in
                              sorted(zip(FEATURES, model.feature_importances_), key=lambda t: -t[1])[:6]]
    joblib.dump({"model": model, "features": FEATURES, "kind": "real_ssh", "seed": SEED},
                ROOT / "model" / "detector_real.joblib")
    Path(out_json).write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    main(ap.parse_args().log)
