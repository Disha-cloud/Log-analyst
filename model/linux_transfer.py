"""Apply the real-SSH model to Loghub Linux (PAM-only auth lines, different machine). No true labels exist:
hosts are bucketed by total failures and the flag rate per bucket is reported next to a threshold rule.

    python -m model.linux_transfer /path/to/Linux.log
"""
import json
import re
import sys
from datetime import datetime
from pathlib import Path

import joblib

from features.real_ssh import TS_RE, chunk_features

ROOT = Path(__file__).resolve().parents[1]


def main(path):
    ev = []
    for n, line in enumerate(open(path, errors="replace")):
        m = re.search(r"sshd\(pam_unix\).*authentication failure;.*rhost=(\S+)", line)
        if not m:
            ev.append(None)
            continue
        t = TS_RE.search(line)
        ts = datetime.strptime(f"2000 {t[1]} {t[2]} {t[3]}:{t[4]}:{t[5]}", "%Y %b %d %H:%M:%S")
        u = re.search(r"\buser=(\S+)", line)
        ev.append((n, m.group(1), "pam_fail", u.group(1) if u else None, ts))
    df = chunk_features(ev, chunk_lines=2000)
    total = df.groupby("ip").pam_fail.sum()
    bundle = joblib.load(ROOT / "model" / "detector_real.joblib")
    df["ml"] = bundle["model"].predict(df[bundle["features"]].to_numpy())
    df["thr5"] = (df.pam_fail >= 5).astype(int)
    df["bucket"] = df.ip.map(lambda i: "10+ failures" if total[i] >= 10 else ("3-9 failures" if total[i] >= 3 else "1-2 failures"))
    g = df.groupby("bucket").agg(rows=("ml", "size"), hosts=("ip", "nunique"), ml_flag_rate=("ml", "mean"),
                                 thr5_flag_rate=("thr5", "mean")).round(3)
    print(g)
    (ROOT / "docs" / "linux_transfer_results.json").write_text(g.reset_index().to_json(orient="records", indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
