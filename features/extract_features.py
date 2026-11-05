"""Extract per-IP (or per-IP-per-time-window) numeric features from parsed logs.

Usage:
    python -m features.extract_features S1                  # per-IP, prints table
    python -m features.extract_features S1 --window 5       # 5-minute windows
    python -m features.extract_features --all -o features.csv

If data/<scenario>/ground_truth.json has labels, an `is_suspicious` column is
added (1 if any of the group's lines is in suspicious_evidence_ids).
"""
import argparse
import json
import sys
from pathlib import Path

import pandas as pd

from generator.generate_logs import VARIANTS_DIR
from parser.log_parser import parse_scenario

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

FEATURE_COLUMNS = [
    "failed_login_count", "successful_login_count", "distinct_usernames",
    "request_count", "requests_per_minute", "unique_endpoints",
    "ratio_2xx", "ratio_3xx", "ratio_4xx", "ratio_5xx",
    "bytes_total", "first_hour", "mean_hour", "off_hours_ratio",
    "event_count", "duration_minutes",
]

OFF_HOURS = (0, 6)  # hours [0, 6) count as unusual time-of-day


def records_to_frame(records):
    """One row per parsed record that has an IP (sudo/other lines have none)."""
    rows = []
    for r in records:
        if not r.get("ip"):
            continue
        ts = r["timestamp"]
        rows.append({
            "ip": r["ip"],
            "evidence_id": r["evidence_id"],
            "timestamp": ts,
            "hour": ts.hour + ts.minute / 60,
            "event_type": r["event_type"],
            "user": r.get("user"),
            "path": r.get("path"),
            "status": r.get("status"),
            "bytes": r.get("bytes", 0),
        })
    return pd.DataFrame(rows)


def _group_features(g, window_minutes):  # returns a plain dict to keep int dtypes
    is_http = g["event_type"] == "http_request"
    http = g[is_http]
    n_http = len(http)
    status = http["status"]
    span = (g["timestamp"].max() - g["timestamp"].min()).total_seconds() / 60
    duration = window_minutes if window_minutes else max(span, 1.0)

    def ratio(lo, hi):
        return float(((status >= lo) & (status < hi)).sum() / n_http) if n_http else 0.0

    hours = g["hour"]
    failed = g["event_type"] == "failed_authentication"
    return {
        "failed_login_count": int(failed.sum()),
        "successful_login_count": int((g["event_type"] == "successful_authentication").sum()),
        "distinct_usernames": int(g.loc[failed, "user"].nunique()),
        "request_count": n_http,
        "requests_per_minute": round(n_http / duration, 4),
        "unique_endpoints": int(http["path"].nunique()),
        "ratio_2xx": ratio(200, 300),
        "ratio_3xx": ratio(300, 400),
        "ratio_4xx": ratio(400, 500),
        "ratio_5xx": ratio(500, 600),
        "bytes_total": int(http["bytes"].sum()),
        "first_hour": round(float(g["hour"].iloc[0]), 2),
        "mean_hour": round(float(hours.mean()), 2),
        "off_hours_ratio": round(float(((hours >= OFF_HOURS[0]) & (hours < OFF_HOURS[1])).mean()), 4),
        "event_count": len(g),
        "duration_minutes": round(duration, 2),
    }


def extract_features(records, window_minutes=None, suspicious_ids=None):
    """Return a DataFrame of features.

    window_minutes=None -> one row per IP over the whole log.
    window_minutes=N    -> one row per (IP, N-minute window); requests_per_minute
                           is then count / N rather than count / observed span.
    suspicious_ids      -> optional set of evidence IDs; adds `is_suspicious`.
    """
    df = records_to_frame(records)
    if df.empty:
        return pd.DataFrame(columns=["ip"] + FEATURE_COLUMNS)
    df = df.sort_values("timestamp")

    keys = ["ip"]
    if window_minutes:
        df["window_start"] = df["timestamp"].dt.floor(f"{int(window_minutes)}min")
        keys = ["ip", "window_start"]

    rows = []
    for key, g in df.groupby(keys, sort=True):
        feats = _group_features(g, window_minutes)
        key = key if isinstance(key, tuple) else (key,)
        row = dict(zip(keys, key))
        row.update(feats)
        if suspicious_ids is not None:
            row["is_suspicious"] = int(any(e in suspicious_ids for e in g["evidence_id"]))
        rows.append(row)
    return pd.DataFrame(rows)


def load_suspicious_ids(scenario_dir):
    path = Path(scenario_dir) / "ground_truth.json"
    if not path.exists():
        return None
    gt = json.loads(path.read_text())
    if gt.get("labels_available") is False:
        return None
    return set(gt.get("suspicious_evidence_ids", []))


def scenario_dir(name):
    """data/<name> for the fixed scenarios, else data_variants/<name> for generated variants."""
    return DATA / name if (DATA / name).is_dir() else VARIANTS_DIR / name


def scenario_features(name, window_minutes=None):
    scenario_dir_ = scenario_dir(name)
    records, _ = parse_scenario(scenario_dir_)
    df = extract_features(records, window_minutes, load_suspicious_ids(scenario_dir_))
    df.insert(0, "scenario", name)
    return df


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario", nargs="?", help="scenario folder name under data/ (e.g. S1)")
    ap.add_argument("--all", action="store_true", help="process every scenario in data/")
    ap.add_argument("--variants", action="store_true", help="process every generated scenario in data_variants/")
    ap.add_argument("--window", type=int, default=None, help="window size in minutes (default: per-IP)")
    ap.add_argument("-o", "--output", help="write CSV to this path")
    args = ap.parse_args()

    if args.variants:
        names = sorted(p.name for p in VARIANTS_DIR.iterdir() if (p / "ground_truth.json").exists())
    elif args.all:
        names = sorted(p.name for p in DATA.iterdir() if p.is_dir())
    elif args.scenario:
        names = [args.scenario]
    else:
        ap.error("give a scenario name, --all or --variants")

    df = pd.concat([scenario_features(n, args.window) for n in names], ignore_index=True)
    if args.output:
        df.to_csv(args.output, index=False)
        print(f"wrote {len(df)} rows to {args.output}", file=sys.stderr)
    else:
        with pd.option_context("display.width", 250, "display.max_columns", None):
            print(df.to_string(index=False))


if __name__ == "__main__":
    main()
