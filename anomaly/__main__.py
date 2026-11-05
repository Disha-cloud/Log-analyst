"""CLI.   python -m anomaly fit --baseline DIR [--baseline DIR ...] -o baseline.joblib
         python -m anomaly score DIR --model baseline.joblib
DIR is a scenario folder (auth.log and/or access.log) or a name under data/."""
import argparse
from pathlib import Path

import joblib

from anomaly.baseline import fit_baseline, scenario_frame, score
from features.extract_features import scenario_dir


def resolve(p):
    return Path(p) if Path(p).is_dir() else scenario_dir(p)


def main():
    ap = argparse.ArgumentParser(prog="anomaly")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fit"); f.add_argument("--baseline", action="append", required=True)
    f.add_argument("-o", "--out", required=True); f.add_argument("--quantile", type=float, default=0.99)
    s = sub.add_parser("score"); s.add_argument("scenario"); s.add_argument("--model", required=True)
    a = ap.parse_args()
    if a.cmd == "fit":
        dirs = [resolve(b) for b in a.baseline]
        bundle = fit_baseline([scenario_frame(d) for d in dirs], a.quantile, sources=[str(d) for d in dirs])
        joblib.dump(bundle, a.out)
        print(f"fitted on {bundle['n_rows']} IP rows from {len(dirs)} source(s); threshold {bundle['threshold']:.3f}")
        if bundle["warning"]:
            print("WARNING:", bundle["warning"])
    else:
        res = score(scenario_frame(resolve(a.scenario)), joblib.load(a.model))
        for _, r in res.sort_values("anomaly_score", ascending=False).iterrows():
            if r.flagged:
                print(f"{r.ip}  {r.window_start:%Y-%m-%d}  score {r.anomaly_score:.3f}  " + "; ".join(r.reasons or ["(no single feature stands out)"]))
        print(f"{int(res.flagged.sum())} of {len(res)} IPs flagged")


if __name__ == "__main__":
    main()
