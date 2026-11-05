"""Score a scenario's IPs with the trained RandomForest (optional second detection path).

Independent of the rule engine, LLM analyzer and validator: it only reads the parsed
logs. Returns one row per IP so the UI can show it next to the rule-based findings.
"""
from pathlib import Path

from features.extract_features import extract_features
from parser.log_parser import parse_scenario

MODEL_PATH = Path(__file__).resolve().parent / "detector.joblib"
SHOW_COLUMNS = ["failed_login_count", "distinct_usernames", "request_count",
                "requests_per_minute", "unique_endpoints", "ratio_4xx", "off_hours_ratio"]


def model_available(path=MODEL_PATH):
    return Path(path).exists()


def load_detector(path=MODEL_PATH):
    import joblib  # imported lazily so the app still starts without it
    return joblib.load(path)


def score_scenario(scenario_dir, bundle):
    """One row per IP: ml_score (max P(suspicious) over its windows), ml_flagged, key features."""
    records, _ = parse_scenario(scenario_dir)
    window = bundle.get("window_minutes")
    feats = extract_features(records, window)
    if feats.empty:
        return feats
    feats = feats.copy()
    feats["ml_score"] = bundle["model"].predict_proba(feats[bundle["features"]])[:, 1]
    feats["ml_flagged"] = bundle["model"].predict(feats[bundle["features"]]) == 1
    agg = {c: "max" for c in SHOW_COLUMNS + ["ml_score", "ml_flagged"]}
    out = feats.groupby("ip", as_index=False).agg(agg)
    out["ml_flagged"] = out["ml_flagged"].astype(bool)
    return out.sort_values(["ml_score", "ip"], ascending=[False, True]).reset_index(drop=True)
