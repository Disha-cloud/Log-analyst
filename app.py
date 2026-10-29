"""Log Analyst: Streamlit demo UI."""
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from llm.analyzer import MODEL, analyze_scenario, ollama_available
from parser.log_parser import load_raw_lines
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


def render_claims(validation, lines):
    if not validation or not validation["claims"]:
        st.info("No attack-chain claims for this scenario.")
        return
    for c in validation["claims"]:
        ok = c["status"] == "verified"
        badge = ":green[**VERIFIED**]" if ok else ":red[**UNVERIFIED**]"
        st.markdown(f"**{c['claim_number']}. {c['stage']}** {badge}")
        st.write(c["explanation"])
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
    names = scenario_names()
    if not names:
        st.error("No data found. Run: python -m generator.generate_logs")
        st.stop()
    name = st.selectbox("Scenario", names)
    if st.button("Run live analysis", disabled=not up):
        with st.spinner("Rules, LLM, validator running..."):
            analyze_scenario(name)
            validate_scenario(name)
        st.success("Done. Saved results updated.")
    st.caption("Synthetic data only. Private 10.x IPs. LLM output treated as untrusted until verified.")

b = bundle(name)
analysis, validation, lines = b["analysis"], b["validation"], b["lines"]

st.title(f"Scenario {name}")
st.caption(b["truth"]["description"])
if not analysis:
    st.warning("No saved analysis. Click 'Run live analysis' or run: python -m llm.analyzer")
    st.stop()

tab_overview, tab_rules, tab_chain, tab_metrics, tab_mitigation = st.tabs(
    ["Overview", "Rule findings", "Attack chain", "Metrics", "Before / After mitigation"])

with tab_overview:
    cols = st.columns(4)
    cols[0].markdown(f"Severity\n\n### {severity_badge(analysis['severity'])}")
    cols[1].metric("Rule findings", len(analysis["rule_findings"]))
    total = validation["total_claims"] if validation else len(analysis["attack_chain"])
    cols[2].metric("LLM claims", total)
    cols[3].metric("Verified", f"{validation['verified_claims']}/{total}" if validation else "not run")
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
        st.dataframe(pd.DataFrame([{"rule": f["rule_id"], "severity": f["severity"], "title": f["title"],
                                    "evidence lines": len(f["evidence_ids"])} for f in findings]),
                     hide_index=True)
        for f in findings:
            with st.expander(f"{f['rule_id']}: {f['title']}"):
                st.write(f["description"])
                show_lines(f["evidence_ids"], lines)

with tab_chain:
    st.caption("Each claim is checked against the raw lines it cites. Verified means the cited lines "
               "support the event type, not that the activity is proven malicious.")
    render_claims(validation, lines)

with tab_metrics:
    results = load_json(DOCS_DIR / "results.json")
    st.subheader("Rule detection vs ground truth")
    if results:
        st.dataframe(pd.DataFrame([{k: r.get(k) for k in ("scenario", "findings", "tp", "fp", "fn",
                                   "precision", "recall", "rules_unexpected")} for r in results]),
                     hide_index=True)
        st.caption("Synthetic data, designed alongside rules: internal consistency, not real-world accuracy.")
    else:
        st.info("Run: python -m validator.evaluate")
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
        st.caption(f"Model {abl['model']}, temperature {abl['temperature']}, seeds {abl['seeds']}.")
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
            a, v = data["analysis"], data["validation"]
            st.markdown(f"Severity: {severity_badge(a['severity'])}")
            st.metric("Rules fired", len(a["rule_findings"]))
            st.write("Rules: " + (", ".join(f["rule_id"] for f in a["rule_findings"]) or "none"))
            st.metric("Attack-chain stages", len(a["attack_chain"]))
            for step in a["attack_chain"]:
                st.markdown(f"- {step['stage']}")