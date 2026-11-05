"""Train/evaluate a per-request RandomForest on CSIC 2010 (labeled normal vs anomalous HTTP requests).

    python -m model.train_web normalTrafficTraining.txt anomalousTrafficTest.txt
Compares: payload RandomForest, the project's regex rules (SQLI_RE/TRAVERSAL_RE), and a header-only
RandomForest used as a dataset-artifact check.
"""
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_fscore_support
from sklearn.model_selection import train_test_split

from features.http_requests import HEADER_COLUMNS, PAYLOAD_COLUMNS, features, split_requests

ROOT = Path(__file__).resolve().parents[1]
SEED = 42


def load(path, label):
    text = Path(path).read_text(encoding="latin-1")
    rows = [dict(features(h, b), label=label, sig=h.splitlines()[0] + "|" + b) for h, b in split_requests(text)]
    return pd.DataFrame(rows)


def prf(y, p):
    pr, rc, f1, _ = precision_recall_fscore_support(y, p, average="binary", zero_division=0)
    return {"precision": round(pr, 4), "recall": round(rc, 4), "f1": round(f1, 4),
            "tp": int(((y == 1) & (p == 1)).sum()), "fp": int(((y == 0) & (p == 1)).sum()),
            "fn": int(((y == 1) & (p == 0)).sum()), "tn": int(((y == 0) & (p == 0)).sum())}


def forest():
    return RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=SEED, n_jobs=-1)


def main(normal, anomalous):
    df = pd.concat([load(normal, 0), load(anomalous, 1)], ignore_index=True)
    dup = int(df.duplicated("sig").sum())
    # Split by unique request signature so identical requests never sit on both sides.
    sigs = df.drop_duplicates("sig")[["sig", "label"]]
    tr_s, te_s = train_test_split(sigs, test_size=0.2, stratify=sigs.label, random_state=SEED)
    tr, te = df[df.sig.isin(set(tr_s.sig))], df[df.sig.isin(set(te_s.sig))]
    out = {"requests": len(df), "normal": int((df.label == 0).sum()), "anomalous": int((df.label == 1).sum()),
           "duplicate_requests": dup, "train_rows": len(tr), "test_rows": len(te),
           "test_anomalous": int(te.label.sum())}
    m = forest().fit(tr[PAYLOAD_COLUMNS], tr.label)
    out["payload_forest"] = prf(te.label.to_numpy(), m.predict(te[PAYLOAD_COLUMNS]))
    out["regex_rules"] = prf(te.label.to_numpy(), ((te.sqli_re | te.traversal_re) > 0).astype(int).to_numpy())
    h = forest().fit(tr[HEADER_COLUMNS], tr.label)
    out["header_only_forest_artifact_check"] = prf(te.label.to_numpy(), h.predict(te[HEADER_COLUMNS]))
    imp = sorted(zip(PAYLOAD_COLUMNS, m.feature_importances_), key=lambda t: -t[1])[:6]
    out["top_features"] = [(n, round(float(v), 3)) for n, v in imp]
    # misses by the forest that regexes also miss, for qualitative inspection
    miss = te[(te.label == 1) & (m.predict(te[PAYLOAD_COLUMNS]) == 0)]
    out["sample_missed_attacks"] = [s[:160] for s in miss.sig.head(5)]
    joblib.dump({"model": m, "features": PAYLOAD_COLUMNS, "kind": "csic_web", "seed": SEED},
                ROOT / "model" / "detector_web.joblib")
    (ROOT / "docs" / "web_detector_results.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main(*sys.argv[1:3])
