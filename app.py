"""Log Analyst: Streamlit demo UI."""
import json
import re
import time
from collections import deque
from pathlib import Path

import pandas as pd
import streamlit as st

from feed.live_feed import stream
from generator.generate_logs import SCENARIOS
from generator.import_real import import_scenario
from llm.analyzer import MODEL, analyze_scenario, ollama_available
from model.predict import load_detector, model_available, score_scenario
from parser.log_parser import load_raw_lines, parse_scenario
from scoring.trust_score import WEIGHTS, compute_trust
from validator.claim_validator import validate_scenario

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DOCS_DIR = ROOT / "docs"
SEVERITY_COLOR = {"critical": "red", "high": "red", "medium": "orange", "low": "green", "unknown": "gray"}

st.set_page_config(page_title="Log Analyst", page_icon="🔍", layout="wide")


def load_json(path):
    path = Path(path)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def scenario_names():
    if not DATA_DIR.exists():
        return []
    return sorted(p.name for p in DATA_DIR.iterdir() if (p / "ground_truth.json").exists())


def bundle(name):
    d = DATA_DIR / name
    return {"truth": load_json(d / "ground_truth.json"), "analysis": load_json(d / "llm_analysis.json"),
            "validation": load_json(d / "claim_validation.json"), "lines": load_raw_lines(d)}


def severity_badge(severity):
    sev = (severity or "unknown").lower()
    return f":{SEVERITY_COLOR.get(sev, 'gray')}[**{sev.upper()}**]"


def show_lines(ids, lines):
    text = "\n".join(lines.get(eid, f"{eid}  (not found in logs)") for eid in ids)
    st.code(text or "(no evidence cited)", language="log")


def mitre_line(check):
    status = (check or {}).get("status")
    if status == "match":
        st.markdown(f":green[LLM-suggested ATT&CK ✓ {check['reason']}]")
    elif status in ("mismatch", "malformed"):
        st.markdown(f":orange[LLM-suggested ATT&CK ✗ {check.get('given')}: {check['reason']}]")
    elif status == "missing":
        st.markdown(":gray[LLM-suggested ATT&CK: none given]")


def render_claims(validation, lines):
    if not validation or not validation["claims"]:
        st.info("No attack-chain claims for this scenario.")
        return
    for c in validation["claims"]:
        ok = c["status"] == "verified"
        badge = ":green[**VERIFIED**]" if ok else ":red[**UNVERIFIED**]"
        st.markdown(f"**{c['claim_number']}. {c['stage']}** {badge}")
        st.write(c["explanation"])
        mitre_line(c.get("mitre_check"))
        with st.expander(f"Evidence checks ({len(c['evidence_ids'])} cited)"):
            for ch in c["evidence_checks"]:
                icon = "✅" if ch["status"] == "pass" else "❌"
                st.markdown(f"{icon} `{ch['evidence_id']}`: {ch['reason']}")
                if ch["evidence_id"] in lines:
                    st.code(lines[ch["evidence_id"]], language="log")
        st.divider()


# Sidebar
with st.sidebar:
    st.header("🔍 Log Analyst")
    up = ollama_available()
    st.markdown(f"**Ollama:** {':green[running]' if up else ':red[not running]'}")
    st.caption(f"Model: {MODEL} (local, no data leaves this machine)")

    with st.expander("Analyze your own log"):
        up_auth = st.file_uploader("auth.log (SSH/sudo syslog)", type=["log", "txt"], key="up_auth")
        up_access = st.file_uploader("access.log (Apache combined, optional)", type=["log", "txt"],
                                     key="up_access")
        up_name = re.sub(r"[^A-Za-z0-9_-]", "_", st.text_input("Scenario name", "UPLOAD")) or "UPLOAD"
        up_mask = st.checkbox("Mask public IPs", value=True)
        if st.button("Import log"):
            if up_name in SCENARIOS:
                st.error("That name belongs to a synthetic scenario. Pick another.")
            elif not (up_auth or up_access):
                st.warning("Upload at least one file.")
            else:
                import_scenario(
                    up_name,
                    auth_text=up_auth.getvalue().decode("utf-8", "replace") if up_auth else None,
                    access_text=up_access.getvalue().decode("utf-8", "replace") if up_access else None,
                    description="Uploaded log. No ground-truth labels.", source="user upload",
                    mask=up_mask)
                st.session_state["scenario"] = up_name
                st.success(f"Imported {up_name}. Click Run live analysis below.")

    names = scenario_names()
    if not names:
        st.error("No data found. Run: python -m generator.generate_logs")
        st.stop()
    name = st.selectbox("Scenario", names, key="scenario")
    if st.button("Run live analysis", disabled=not up):
        with st.spinner("Rules, LLM and validator running..."):
            analyze_scenario(name)
            validate_scenario(name)
        st.success("Done. Saved results updated.")
    ml_ok = model_available()
    ml_on = st.checkbox("Show ML detector (experimental)", value=False, disabled=not ml_ok,
                        help="Optional second detection path: RandomForest on per-IP features. "
                             "Shown beside the rules; does not change them.")
    if not ml_ok:
        st.caption("No trained model. Run: python -m model.train_detector")
    st.caption("Synthetic or masked data only. LLM output treated as untrusted until verified.")

b = bundle(name)
truth, analysis, validation, lines = b["truth"], b["analysis"], b["validation"], b["lines"]

st.title(f"Scenario {name}")
st.caption(truth["description"])
if not truth.get("labels_available", True):
    st.info(f"Unlabeled data: no ground truth, so no precision/recall. "
            f"{truth.get('masked_ip_count', 0)} public IPs masked. Source: {truth.get('source') or 'n/a'}")
if not analysis:
    st.warning("No saved analysis. Click 'Run live analysis' (Ollama must be running).")
    st.stop()

tab_overview, tab_rules, tab_chain, tab_metrics, tab_mitigation, tab_live, *tab_extra = st.tabs(
    ["Overview", "Rule findings", "Attack chain", "Metrics", "Before / After mitigation",
     "Live feed (simulated)"] + (["ML detector"] if ml_on else []))

TRUST_COLOR = {"high": "green", "moderate": "orange", "low": "red"}


def render_trust(analysis, validation):
    """Trust score box: used by the Overview tab and at the end of the simulated live feed."""
    trust = compute_trust(analysis["rule_findings"], validation)
    with st.container(border=True):
        left, right = st.columns([1, 2])
        with left:
            if trust["score"] is None:
                st.markdown("**Trust score**\n\n## N/A")
                st.caption(trust["reason"])
            else:
                st.markdown(f"**Trust score**\n\n## {trust['score']} / 100  "
                            f":{TRUST_COLOR[trust['band']]}[**{trust['band'].upper()}**]")
                st.progress(trust["score"] / 100)
        with right:
            if trust["components"]:
                st.dataframe(pd.DataFrame([{
                    "Component": c["label"], "Value": f"{c['value']:.0%}", "Weight": f"{c['weight']:.0%}",
                    "Points": round(c["points"], 1), "Built from": c["detail"]} for c in trust["components"]]),
                    hide_index=True)
        if trust["score"] is not None and validation["total_claims"] <= 2:
            st.caption(f":orange[Based on only {validation['total_claims']} LLM claim(s): "
                       "the percentages are coarse, so treat this score with extra caution.]")
        st.caption("How much deterministic evidence supports this analysis: rule confidence "
                   f"({WEIGHTS['rule_confidence']:.0%}), LLM claims verified against the cited log lines "
                   f"({WEIGHTS['claims_verified']:.0%}) and LLM ATT&CK IDs that fit ({WEIGHTS['mitre_match']:.0%}). "
                   "A heuristic with judgment-based weights: it is not a measure of how malicious the "
                   "activity is, and it does not detect prompt injection.")


with tab_overview:
    render_trust(analysis, validation)
    cols = st.columns(5)
    cols[0].markdown(f"Severity\n\n### {severity_badge(analysis['severity'])}")
    cols[1].metric("Rule findings", len(analysis["rule_findings"]))
    total = validation["total_claims"] if validation else len(analysis["attack_chain"])
    cols[2].metric("LLM claims", total)
    cols[3].metric("Evidence verified", f"{validation['verified_claims']}/{total}" if validation else "not run")
    cols[4].metric("LLM ATT&CK correct",
                   f"{validation.get('mitre_match', 0)}/{total}" if validation else "not run")
    techniques = sorted({f["mitre_id"] for f in analysis["rule_findings"] if f.get("mitre_id")})
    if techniques:
        st.markdown("**ATT&CK techniques (from rules, authoritative):** " + ", ".join(techniques))
    if analysis.get("findings_sent_to_llm") and analysis["findings_sent_to_llm"] < len(analysis["rule_findings"]):
        st.caption(f"LLM saw the top {analysis['findings_sent_to_llm']} findings by severity "
                   f"(of {len(analysis['rule_findings'])}), to stay within its context window.")
    st.subheader("Summary")
    st.write(analysis["summary"])
    if not analysis.get("llm_called", True):
        st.caption("LLM not called: no rule findings, so nothing to explain.")
    if validation:
        bad = [s for s in validation.get("summary_checks", []) if s["status"] == "fail"]
        if bad:
            st.error("Summary mentions IDs not found in logs: " + ", ".join(s["mention"] for s in bad))
    if analysis["mitigations"]:
        st.subheader("Recommended mitigations")
        for m in analysis["mitigations"]:
            st.markdown(f"- {m}")

with tab_rules:
    findings = analysis["rule_findings"]
    if not findings:
        st.success("No rules fired.")
    else:
        st.dataframe(pd.DataFrame([{"rule": f["rule_id"], "severity": f["severity"], "ip": f.get("ip"),
                                    "title": f["title"], "ATT&CK (rule)": f.get("mitre_id"),
                                    "evidence lines": len(f["evidence_ids"])} for f in findings]),
                     hide_index=True)
        for f in findings[:30]:
            with st.expander(f"{f['rule_id']}: {f['title']} ({f.get('ip') or '-'})"):
                st.write(f["description"])
                if f.get("mitre_id"):
                    st.caption(f"ATT&CK technique (rule-assigned): {f['mitre_id']}")
                show_lines(f["evidence_ids"], lines)
        if len(findings) > 30:
            st.caption(f"Showing first 30 of {len(findings)} findings.")

with tab_chain:
    st.caption("Each claim is checked against the raw lines it cites. The LLM's suggested ATT&CK ID is "
               "checked too, but never trusted: authoritative techniques come from the rules. Verified "
               "means the cited lines support the event type, not that the activity is proven malicious.")
    render_claims(validation, lines)

with tab_metrics:
    results = load_json(DOCS_DIR / "results.json")
    st.subheader("Rule detection vs ground truth (synthetic)")
    if results:
        st.dataframe(pd.DataFrame([{k: r.get(k) for k in ("scenario", "findings", "tp", "fp", "fn",
                                   "precision", "recall", "rules_unexpected", "claims_verified",
                                   "mitre_match")} for r in results]), hide_index=True)
        st.caption("Synthetic data, designed alongside rules: internal consistency, not real-world accuracy.")
    else:
        st.info("Run: python -m validator.evaluate")
    real = load_json(DOCS_DIR / "realworld.json")
    if real:
        st.subheader("Real-world run (unlabeled)")
        st.dataframe(pd.DataFrame([{**{k: r.get(k) for k in ("scenario", "lines", "parse_errors",
                                    "masked_ips", "findings", "distinct_ips_flagged",
                                    "claims_verified", "mitre_match")},
                                    "rules_fired": ", ".join(f"{k}: {v}" for k, v in r["rules_fired"].items())}
                                   for r in real]), hide_index=True)
    adv = load_json(DOCS_DIR / "adversarial.json")
    st.subheader("Adversarial validator test")
    if adv:
        s = adv["summary"]
        c1, c2, c3 = st.columns(3)
        c1.metric("Fabricated claims caught", f"{s['fabricated_caught']}/{s['fabricated_total']}")
        c2.metric("Valid claims accepted", f"{s['valid_accepted']}/{s['valid_total']}")
        c3.metric("Known blind spots", f"{s['blind_spots_passed_through']}/{s['blind_spots_total']}")
        st.dataframe(pd.DataFrame([{k: r[k] for k in ("id", "category", "description", "expected", "actual",
                                                      "reason")} for r in adv["cases"]]), hide_index=True)
    else:
        st.info("Run: python -m validator.adversarial_eval")
    abl = load_json(DOCS_DIR / "ablation.json")
    st.subheader("Ablation: grounded vs ungrounded LLM")
    if abl:
        st.dataframe(pd.DataFrame([{"mode": m, **v} for m, v in abl["summary"].items()]), hide_index=True)
        st.caption(f"Model {abl['model']}, temperature {abl['temperature']}, seeds {abl['seeds']}. "
                   f"Key result: attack coverage, not verification rate.")
    else:
        st.info("Run: python -m llm.ablation")

with tab_mitigation:
    st.caption("S1: brute force succeeds. S1_mitigated: account lockout after 5 failures, same baseline logs.")
    left, right = st.columns(2)
    for col, scen in ((left, "S1"), (right, "S1_mitigated")):
        with col:
            st.subheader(scen)
            data = bundle(scen) if (DATA_DIR / scen).exists() else None
            if not data or not data["analysis"]:
                st.info(f"Run: python -m llm.analyzer {scen}")
                continue
            a = data["analysis"]
            st.markdown(f"Severity: {severity_badge(a['severity'])}")
            st.metric("Rules fired", len(a["rule_findings"]))
            st.write("Rules: " + (", ".join(f["rule_id"] for f in a["rule_findings"]) or "none"))
            st.metric("Attack-chain stages", len(a["attack_chain"]))
            for step in a["attack_chain"]:
                st.markdown(f"- {step['stage']}")

with tab_live:
    st.caption("Replays this scenario's log lines in time order and runs the rule engine as each line "
               "arrives, so alerts fire at the line that triggers them. The LLM analysis, validation and "
               "trust score shown at the end are loaded from saved results (no model call): this "
               "simulates a live pipeline, it is not a live LLM run. Changing any control stops a replay.")
    c_delay, c_go = st.columns([3, 1])
    delay_ms = c_delay.slider("Delay per screen update (ms)", 0, 200, 30, key="live_delay",
                              help="Big logs update the screen every few lines to stay smooth.")
    go = c_go.button("▶ Start live feed", key="live_go", use_container_width=True)
    if go:
        records, _ = parse_scenario(DATA_DIR / name)
        n = len(records)
        if not n:
            st.warning("No parsable log lines in this scenario.")
        else:
            refresh = max(1, n // 300)
            status, bar = st.empty(), st.progress(0.0)
            col_feed, col_alerts = st.columns([3, 2])
            col_feed.markdown("**Incoming log lines** (⚠ = part of an alert)")
            col_alerts.markdown("**Alerts**")
            feed_box, alerts_box = col_feed.empty(), col_alerts.empty()
            tail, alerts, flagged = deque(maxlen=14), [], set()
            for i, record, new in stream(records):
                tail.append(record)
                for f in new:
                    alerts.append((i, record, f))
                    flagged.update(f["evidence_ids"])
                    st.toast(f"{f['severity'].upper()}: {f['title']} ({f.get('ip') or '-'})", icon="🚨")
                if i % refresh == 0 or new or i == n:
                    status.markdown(f"**{i}/{n} lines received** · log time "
                                    f"{record['timestamp']:%H:%M:%S} · {len(alerts)} alert(s)")
                    bar.progress(i / n)
                    feed_box.code("\n".join(("⚠ " if r["evidence_id"] in flagged else "  ") + r["raw"]
                                            for r in tail), language="log")
                    alerts_box.markdown("\n".join(
                        f"- {severity_badge(f['severity'])} **{f['rule_id']}**: {f['title']} "
                        f"({f.get('ip') or '-'}) · ATT&CK {f.get('mitre_id') or '-'} · line {k}, "
                        f"{r['timestamp']:%H:%M:%S}" for k, r, f in alerts) or "_No alerts yet_")
                    time.sleep(delay_ms / 1000)
            status.markdown(f"**Feed complete: {n}/{n} lines received** · {len(alerts)} alert(s)")
            st.divider()
            sev, found = analysis["severity"], len(analysis["rule_findings"])
            if not found:
                st.success("No alerts: no detection rules fired for this scenario.")
            elif sev in ("critical", "high"):
                st.error(f"🚨 {sev.upper()} severity alert: {found} rule finding(s) across "
                         f"{len({f['rule_id'] for _, _, f in alerts})} rule(s).")
            else:
                st.warning(f"{sev.upper()} severity: {found} rule finding(s).")
            if {f["rule_id"] for _, _, f in alerts} != {f["rule_id"] for f in analysis["rule_findings"]}:
                st.caption("Note: the rules that fired live differ from the saved analysis "
                           "(the logs may have changed since it was generated).")
            render_trust(analysis, validation)

if tab_extra:
    with tab_extra[0]:
        st.caption("Optional second detection path: a RandomForest scores each IP from numeric features "
                   "(failed logins, request rate, endpoints, status mix, time of day). It runs "
                   "independently of the rules, LLM and validator, and is shown here for comparison only.")
        st.warning("Experimental. Trained on ~100 synthetic scenarios. It is accurate on held-out variants "
                   "of attack types it was trained on (same generator as the rules), but in testing it "
                   "detected almost nothing from an attack type it had never seen, and on real SSH data "
                   "it missed most rule-flagged IPs while flagging some with only 2 failed logins. "
                   "See docs/detector_results.md. The rule findings remain authoritative.")
        scores = score_scenario(DATA_DIR / name, load_detector())
        if scores.empty:
            st.info("No IP-bearing events to score.")
        else:
            rule_ips = {f["ip"] for f in analysis["rule_findings"] if f.get("ip")}
            scores["rules_flagged"] = scores["ip"].isin(rule_ips)
            ml_ips = set(scores.loc[scores["ml_flagged"], "ip"])
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("IPs flagged by rules", len(rule_ips))
            c2.metric("IPs flagged by ML", len(ml_ips))
            c3.metric("Both agree", len(rule_ips & ml_ips))
            c4.metric("Disagree", len(rule_ips ^ ml_ips))

            def verdict(row):
                if row["rules_flagged"] and row["ml_flagged"]:
                    return "both"
                return "rules only" if row["rules_flagged"] else ("ML only" if row["ml_flagged"] else "neither")

            scores["verdict"] = scores.apply(verdict, axis=1)
            interesting = scores[scores["verdict"] != "neither"]
            if interesting.empty:
                st.success("Neither detector flagged any IP.")
            else:
                st.subheader("IPs flagged by at least one detector")
                st.dataframe(interesting.drop(columns=["rules_flagged", "ml_flagged"])
                             .round(3)[["ip", "verdict", "ml_score"] + [c for c in interesting.columns
                                       if c not in ("ip", "verdict", "ml_score", "rules_flagged", "ml_flagged")]],
                             hide_index=True)
            with st.expander(f"All scored IPs ({len(scores)})"):
                st.dataframe(scores.drop(columns=["rules_flagged", "ml_flagged"]).round(3), hide_index=True)
