"""Ask a local Ollama model to explain rule findings as a structured, evidence-cited report."""
import json
import os
import sys
from datetime import datetime
from pathlib import Path

import ollama

from parser.correlator import correlate
from parser.log_parser import parse_scenario

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
NUM_CTX = 8192
MAX_FINDINGS_FOR_LLM = 12
MAX_EVIDENCE_PER_FINDING = 8
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

STAGES = ["authentication_attempt", "successful_authentication", "privileged_activity",
          "exploitation_attempt", "large_data_transfer", "correlated_events"]
RULE_TO_STAGE = {
    "ssh_brute_force": "authentication_attempt",
    "failure_then_success": "successful_authentication",
    "unusual_hour_login": "successful_authentication",
    "login_then_sudo": "privileged_activity",
    "sql_injection_indicator": "exploitation_attempt",
    "path_traversal_indicator": "exploitation_attempt",
    "large_data_transfer": "large_data_transfer",
    "correlated_events": "correlated_events",
}
OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "attack_chain": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "stage": {"type": "string", "enum": STAGES},
                "mitre_id": {"type": "string"},
                "explanation": {"type": "string"},
                "evidence_ids": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["stage", "mitre_id", "explanation", "evidence_ids"]}},
        "mitigations": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "severity", "attack_chain", "mitigations"],
}

SYSTEM_PROMPT = """You are a cautious security log analyst.
Rules:
- Use ONLY the rule findings and evidence lines provided. Never invent log lines or IDs.
- Every attack_chain item must cite evidence IDs copied exactly from the evidence lines, for example auth.log:L0012.
- stage must be one of:
  authentication_attempt = failed login attempts
  successful_authentication = a suspicious successful login
  privileged_activity = sudo or administrative commands
  exploitation_attempt = SQL injection or path traversal requests
  large_data_transfer = unusually large successful HTTP response
  correlated_events = suspicious login linked to a large transfer from the same IP
- Each finding includes suggested_stage. Use it unless clearly wrong.
- mitre_id: closest MITRE ATT&CK technique ID (for example T1110), or "unknown".
- Some findings show only a sample of their evidence; total_evidence_lines gives the full count.
- An indicator is not proof of success. Correlation is not proof of exfiltration. Sudo use is not automatically privilege escalation.
- Order attack_chain by time. Give 2 to 5 concrete mitigations.
- Return only JSON."""


def ollama_available():
    try:
        ollama.list()
        return True
    except Exception:
        return False


def findings_for_llm(findings):
    """Keep at most MAX findings (highest severity wins) but in original order; sample evidence."""
    by_severity = sorted(range(len(findings)), key=lambda i: SEVERITY_RANK.get(findings[i]["severity"], 9))
    keep = sorted(by_severity[:MAX_FINDINGS_FOR_LLM])
    trimmed = []
    for i in keep:
        f = findings[i]
        ids = f["evidence_ids"]
        if len(ids) > MAX_EVIDENCE_PER_FINDING:
            half = MAX_EVIDENCE_PER_FINDING // 2
            ids = ids[:half] + ids[-half:]
        trimmed.append({**f, "evidence_ids": ids, "total_evidence": len(f["evidence_ids"])})
    return trimmed


def select_evidence(records, findings):
    cited = {eid for f in findings for eid in f["evidence_ids"]}
    return {r["evidence_id"]: r["raw"] for r in records if r["evidence_id"] in cited}


def build_user_prompt(scenario_name, findings, evidence):
    compact = [{"rule_id": f["rule_id"], "title": f.get("title"), "description": f.get("description"),
                "severity": f["severity"], "evidence_ids": f["evidence_ids"],
                "total_evidence_lines": f.get("total_evidence", len(f["evidence_ids"])),
                "suggested_stage": RULE_TO_STAGE.get(f["rule_id"])} for f in findings]
    lines = "\n".join(f"{eid} | {raw}" for eid, raw in evidence.items())
    return (f"Scenario: {scenario_name}\n\nRule findings:\n{json.dumps(compact, indent=2)}\n\n"
            f"Evidence lines:\n{lines}\n\nProduce the JSON report.")


def call_llm(user_prompt, system_prompt=SYSTEM_PROMPT, seed=42, temperature=0.0):
    if not ollama_available():
        raise RuntimeError("Ollama is not running. Open the Ollama app or run: ollama serve")
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}]
    last_error = None
    for attempt in (1, 2):
        try:
            response = ollama.chat(model=MODEL, messages=messages, format=OUTPUT_SCHEMA,
                                   options={"temperature": temperature, "seed": seed,
                                            "num_ctx": NUM_CTX})
        except ollama.ResponseError as exc:
            raise RuntimeError(f"Ollama error: {exc}. Did you run: ollama pull {MODEL}?") from exc
        content = response["message"]["content"]
        try:
            return json.loads(content), attempt
        except json.JSONDecodeError as exc:
            last_error = str(exc)
            messages = messages + [
                {"role": "assistant", "content": content},
                {"role": "user", "content": "That was not valid JSON. Return valid JSON only."}]
    raise ValueError(f"Model returned invalid JSON twice: {last_error}")


def analyze_scenario(scenario_name, data_dir=DATA_DIR, seed=42, temperature=0.0, save=True):
    scenario_dir = Path(data_dir) / scenario_name
    if not scenario_dir.exists():
        raise FileNotFoundError(f"No scenario folder: {scenario_dir}")
    records, errors = parse_scenario(scenario_dir)
    findings = correlate(records)
    base = {"scenario": scenario_name, "model": MODEL, "mode": "grounded",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "parse_error_count": len(errors), "rule_findings": findings}
    if not findings:
        result = {"summary": "No suspicious activity was identified by the detection rules.",
                  "severity": "low", "attack_chain": [], "mitigations": [], "llm_called": False}
    else:
        llm_findings = findings_for_llm(findings)
        evidence = select_evidence(records, llm_findings)
        try:
            output, attempts = call_llm(build_user_prompt(scenario_name, llm_findings, evidence),
                                        seed=seed, temperature=temperature)
            result = {**output, "llm_called": True, "llm_attempts": attempts,
                      "findings_sent_to_llm": len(llm_findings)}
        except (RuntimeError, ValueError) as exc:
            result = {"summary": f"LLM analysis failed: {exc}", "severity": "unknown",
                      "attack_chain": [], "mitigations": [], "llm_called": False,
                      "error": str(exc)}
    report = {**base, **result}
    if save:
        (scenario_dir / "llm_analysis.json").write_text(json.dumps(report, indent=2),
                                                        encoding="utf-8")
    return report


def all_scenarios(data_dir=DATA_DIR):
    return sorted(p.name for p in Path(data_dir).iterdir() if (p / "ground_truth.json").exists())


if __name__ == "__main__":
    for name in sys.argv[1:] or all_scenarios():
        report = analyze_scenario(name)
        print(f"{name}: severity={report['severity']}, claims={len(report['attack_chain'])}, "
              f"llm_called={report['llm_called']}" + (f", ERROR={report['error']}"
                                                      if report.get("error") else ""))