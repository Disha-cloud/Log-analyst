"""Log Analyst: Streamlit demo UI."""
import json
import re
from pathlib import Path

import pandas as pd
import streamlit as st

from generator.generate_logs import SCENARIOS
from generator.import_real import import_scenario
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

tab_overview, tab_rules, tab_chain, tab_metrics, tab_mitigation = st.tabs(
    ["Overview", "Rule findings", "Attack chain", "Metrics", "Before / After mitigation"])

with tab_overview:
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
