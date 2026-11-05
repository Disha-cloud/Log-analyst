"""Per-environment anomaly detection: learn what NORMAL looks like in one environment, flag deviations.

Fit uses only baseline (normal) logs, no attack labels. The detector is an IsolationForest over per-IP
features; the alert threshold is the `quantile` of the baseline's own scores, so on data like the baseline
about (1 - quantile) of IPs are flagged by design. Every flag comes with the features that deviate most
from the baseline, so an analyst can see why.

Limits (also in docs/anomaly_detector.md): it only knows the environment it was fitted on; an attack that
is already in the baseline is learned as normal; a small baseline gives a noisy threshold.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from features.extract_features import FEATURE_COLUMNS, extract_features
from parser.log_parser import parse_scenario

# Request-shape features (not tied to any one site): attacks tend to have long, odd, percent-encoded paths.
EXTRA_COLUMNS = ["max_path_len", "max_special_chars", "pct_encoded_ratio"]
ALL_COLUMNS = FEATURE_COLUMNS + EXTRA_COLUMNS
RATIO_COLUMNS = {"ratio_2xx", "ratio_3xx", "ratio_4xx", "ratio_5xx", "off_hours_ratio", "pct_encoded_ratio"}
CIRCULAR = {"first_hour", "mean_hour"}   # hour-of-day is circular; encoded as sin/cos below
MIN_ROWS_REFUSE = 20
MIN_ROWS_WARN = 200


def _matrix(df):
    cols = [c for c in ALL_COLUMNS if c not in CIRCULAR]
    X = df[cols].astype(float).copy()
    for c in cols:
        if c not in RATIO_COLUMNS:
            X[c] = np.log1p(X[c].clip(lower=0))
    for c in CIRCULAR:
        ang = 2 * np.pi * df[c].astype(float) / 24
        X[c + "_sin"], X[c + "_cos"] = np.sin(ang), np.cos(ang)
    return X


def _day(ts):
    return ts.replace(hour=0, minute=0, second=0, microsecond=0)


def extra_features(records):
    """Request-shape features per (ip, day)."""
    stats = {}
    for r in records:
        if r.get("event_type") != "http_request" or not r.get("ip"):
            continue
        path = r.get("path") or ""
        d = stats.setdefault((r["ip"], _day(r["timestamp"])),
                             {"max_path_len": 0, "max_special_chars": 0, "pct": 0, "n": 0})
        d["max_path_len"] = max(d["max_path_len"], len(path))
        d["max_special_chars"] = max(d["max_special_chars"], sum(not (c.isalnum() or c in "/._-") for c in path))
        d["pct"] += "%" in path
        d["n"] += 1
    return {k: {"max_path_len": d["max_path_len"], "max_special_chars": d["max_special_chars"],
                "pct_encoded_ratio": d["pct"] / d["n"]} for k, d in stats.items()}


def scenario_frame(path):
    """Per-(IP, day) feature rows for one scenario folder (auth.log / access.log), plus request-shape extras.

    Records are split by calendar day and features extracted within each day (observed span, as for a
    single log), so a 7-day baseline and a 1-day log are compared on the same footing. A log that fits in
    one day gives exactly one row per IP."""
    records, _ = parse_scenario(path)
    by_day = {}
    for r in records:
        by_day.setdefault(_day(r["timestamp"]), []).append(r)
    extra, frames = extra_features(records), []
    for day, recs in sorted(by_day.items()):
        df = extract_features(recs)
        if df.empty:
            continue
        df.insert(1, "window_start", day)
        for c in EXTRA_COLUMNS:
            df[c] = [extra.get((ip, day), {}).get(c, 0) for ip in df.ip]
        frames.append(df)
    if not frames:
        return extract_features([]).assign(window_start=None, **{c: 0 for c in EXTRA_COLUMNS})
    return pd.concat(frames, ignore_index=True)


def _robust(Xdf, ref=None):
    """Per-feature median / spread of the (transformed) baseline; spread floors keep constant features sane."""
    med = Xdf.median()
    floor = pd.Series({c: 0.15 if c in RATIO_COLUMNS or c.endswith(("_sin", "_cos")) else 0.5 for c in Xdf.columns})
    spread = pd.concat([(Xdf - med).abs().median() * 1.4826, floor], axis=1).max(axis=1)
    return med, spread


def _zmax(Xdf, med, spread):
    z = ((Xdf - med) / spread).clip(lower=0)  # only "more than normal" counts as suspicious
    return z.max(axis=1), z


def fit_baseline(frames, quantile=0.99, seed=42, sources=()):
    """Two detectors, each thresholded at quantile' = 1 - (1 - quantile)/2 on the baseline itself, so the
    flag rate on baseline-like data is about (1 - quantile) overall."""
    df = pd.concat(frames, ignore_index=True)
    if len(df) < MIN_ROWS_REFUSE:
        raise ValueError(f"Baseline has only {len(df)} IP rows; need at least {MIN_ROWS_REFUSE}.")
    X = _matrix(df)
    scaler = StandardScaler().fit(X)
    forest = IsolationForest(n_estimators=300, random_state=seed, n_jobs=-1).fit(scaler.transform(X))
    q_each = 1 - (1 - quantile) / 2
    base_scores = -forest.score_samples(scaler.transform(X))
    med, spread = _robust(X)
    zm, _ = _zmax(X, med, spread)
    raw = df[ALL_COLUMNS].astype(float)
    return {"scaler": scaler, "forest": forest, "columns": list(X.columns), "quantile": quantile,
            "threshold": float(np.quantile(base_scores, q_each)),
            "z_threshold": float(np.quantile(zm, q_each)), "x_median": med.to_dict(), "x_spread": spread.to_dict(),
            "median": raw.median().to_dict(), "p99": raw.quantile(0.99).to_dict(), "n_rows": len(df),
            "sources": list(sources),
            "warning": (f"Small baseline ({len(df)} IP rows): thresholds are noisy." if len(df) < MIN_ROWS_WARN else None)}


def score(df, bundle, top=3):
    """Add anomaly_score (isolation forest), max_z (largest single-feature deviation), flagged, reasons."""
    out = df.copy()
    if out.empty:
        return out.assign(anomaly_score=[], max_z=[], flagged=[], reasons=[])
    X = _matrix(out)[bundle["columns"]]
    out["anomaly_score"] = -bundle["forest"].score_samples(bundle["scaler"].transform(X))
    zm, z = _zmax(X, pd.Series(bundle["x_median"]), pd.Series(bundle["x_spread"]))
    out["max_z"] = zm
    out["flagged"] = (out["anomaly_score"] > bundle["threshold"]) | (zm > bundle["z_threshold"])
    reasons = []
    for idx in out.index:
        dev = z.loc[idx]
        dev = dev[(dev > 3) & ~dev.index.str.endswith(("_sin", "_cos"))].sort_values(ascending=False)[:top]
        reasons.append([f"{c}={out.at[idx, c]:g} (baseline median {bundle['median'][c]:g}, p99 {bundle['p99'][c]:g})"
                        for c in dev.index])
    out["reasons"] = reasons
    return out
