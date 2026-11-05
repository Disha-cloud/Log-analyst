"""Evaluate the anomaly detector with the same held-out scenarios as the supervised model.

Fit sees ONLY the benign IPs (is_suspicious == 0) of the training scenarios; no attack row is used.
Scored per IP on held-out scenarios (S4/S5 plus ~20% of each variant family).
"""
import json
from pathlib import Path

import pandas as pd

from anomaly.baseline import fit_baseline, score
from anomaly.baseline import scenario_frame
from features.extract_features import load_suspicious_ids, scenario_dir
from model.train_detector import family, labeled_scenarios, split_scenarios

ROOT = Path(__file__).resolve().parents[1]


def prf(y, p):
    tp, fp, fn, tn = (int(((y == a) & (p == b)).sum()) for a, b in ((1, 1), (0, 1), (1, 0), (0, 0)))
    pr = tp / (tp + fp) if tp + fp else None
    rc = tp / (tp + fn) if tp + fn else None
    f1 = 2 * pr * rc / (pr + rc) if pr and rc else None
    r = lambda v: None if v is None else round(v, 3)
    return {"precision": r(pr), "recall": r(rc), "f1": r(f1), "fpr": r(fp / (fp + tn) if fp + tn else None),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def build_dataset(names):
    frames = []
    for n in names:
        d = scenario_dir(n)
        df = scenario_frame(d)
        ids = load_suspicious_ids(d)
        if ids is None:
            continue
        from parser.log_parser import parse_scenario
        recs, _ = parse_scenario(d)
        bad_ips = {r["ip"] for r in recs if r.get("ip") and r["evidence_id"] in ids}
        df["is_suspicious"] = df.ip.isin(bad_ips).astype(int)
        df.insert(0, "scenario", n)
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def main():
    names = labeled_scenarios()
    train, test = split_scenarios(names)
    tr, te = build_dataset(train), build_dataset(test)
    base = tr[tr.is_suspicious == 0]
    out = {"baseline_rows": len(base), "baseline_attack_rows_used": 0, "test_rows": len(te),
           "test_attack_ips": int(te.is_suspicious.sum()), "quantiles": {}}
    for q in (0.95, 0.99, 0.999):
        b = fit_baseline([base.drop(columns=["scenario", "is_suspicious"])], quantile=q)
        s = score(te, b)
        y, p = s.is_suspicious.to_numpy(), s.flagged.astype(int).to_numpy()
        res = {"overall": prf(y, p)}
        for fam in sorted({family(n) for n in test if "_v" in n}):
            m = s.scenario.map(family) == fam
            res[fam] = prf(y[m], p[m])
        s4 = s.scenario.isin(["S4", "S5"])
        res["benign_only_S4_S5_fpr"] = round(float(p[s4].mean()), 3)
        out["quantiles"][str(q)] = res
    (ROOT / "docs" / "anomaly_results.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
