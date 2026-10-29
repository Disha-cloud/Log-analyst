"""Ablation: grounded (rules first) vs ungrounded (raw logs only) LLM analysis."""
import argparse
import json
import random
from pathlib import Path

from llm.analyzer import DATA_DIR, MODEL, analyze_scenario, call_llm, ollama_available
from parser.log_parser import load_raw_lines
from validator.claim_validator import normalize_evidence_id, verify_claim

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = PROJECT_ROOT / "docs"
BENIGN_SAMPLE = 120

UNGROUNDED_SYSTEM = """You are a security log analyst. Read the raw log lines and identify attack activity.
- stage must be one of:
  authentication_attempt = failed login attempts
  successful_authentication = a suspicious successful login
  privileged_activity = sudo or administrative commands
  exploitation_attempt = SQL injection or path traversal requests
  large_data_transfer = unusually large successful HTTP response
  correlated_events = suspicious login linked to a large transfer from the same IP
- Cite evidence IDs exactly as written before the | symbol, for example auth.log:L0012.
- mitre_id: closest MITRE ATT&CK technique ID, or "unknown".
- If nothing is suspicious, return an empty attack_chain.
- Return only JSON."""


def ungrounded_prompt(name, lines, truth, seed):
    rng = random.Random(seed)
    attack = set(truth["suspicious_evidence_ids"])
    benign = [eid for eid in lines if eid not in attack]
    sample = attack | set(rng.sample(benign, min(BENIGN_SAMPLE, len(benign))))
    body = "\n".join(f"{eid} | {raw}" for eid, raw in lines.items() if eid in sample)
    return f"Scenario: {name}\n\nLog lines:\n{body}\n\nProduce the JSON report."


def score(report, lines, truth):
    claims = report.get("attack_chain", [])
    results = [verify_claim(cl, lines) for cl in claims]
    invalid = sum(1 for r in results for ch in r["evidence_checks"] if ch["status"] == "fail"
                  and any(w in ch["reason"] for w in ("exist", "Malformed", "Ambiguous")))
    cited = set()
    for cl in claims:
        for raw in cl.get("evidence_ids", []):
            eid, _ = normalize_evidence_id(raw, lines)
            if eid:
                cited.add(eid)
    truth_ids = set(truth["suspicious_evidence_ids"])
    verified = sum(r["status"] == "verified" for r in results)
    return {"claims": len(claims), "verified": verified, "invalid_ids": invalid,
            "attack_lines_cited": len(cited & truth_ids), "attack_lines_total": len(truth_ids),
            "benign_lines_cited": len(cited - truth_ids), "error": report.get("error")}


def summarize(rows):
    summary = {}
    for mode in ("grounded", "ungrounded"):
        rs = [r for r in rows if r["mode"] == mode]
        claims = sum(r["claims"] for r in rs)
        total_attack = sum(r["attack_lines_total"] for r in rs)
        summary[mode] = {
            "runs": len(rs), "claims": claims, "verified": sum(r["verified"] for r in rs),
            "verification_rate": round(sum(r["verified"] for r in rs) / claims, 4) if claims else None,
            "invalid_ids": sum(r["invalid_ids"] for r in rs),
            "benign_lines_cited": sum(r["benign_lines_cited"] for r in rs),
            "attack_coverage": round(sum(r["attack_lines_cited"] for r in rs) / total_attack, 4) if total_attack else None,
            "errors": sum(1 for r in rs if r["error"]),
        }
    return summary


def pct(v):
    return "N/A" if v is None else f"{100 * v:.1f}%"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", nargs="+", default=["S1", "S2", "S3"])
    ap.add_argument("--runs", type=int, default=2)
    ap.add_argument("--temperature", type=float, default=0.2)
    args = ap.parse_args()
    if not ollama_available():
        raise SystemExit("Ollama is not running. Open the Ollama app first.")
    seeds, rows = list(range(1, args.runs + 1)), []
    for name in args.scenarios:
        d = DATA_DIR / name
        lines = load_raw_lines(d)
        truth = json.loads((d / "ground_truth.json").read_text(encoding="utf-8"))
        for seed in seeds:
            grounded = analyze_scenario(name, seed=seed, temperature=args.temperature, save=False)
            rows.append({"scenario": name, "mode": "grounded", "seed": seed, **score(grounded, lines, truth)})
            try:
                output, _ = call_llm(ungrounded_prompt(name, lines, truth, seed),
                                     system_prompt=UNGROUNDED_SYSTEM, seed=seed,
                                     temperature=args.temperature)
            except (RuntimeError, ValueError) as exc:
                output = {"attack_chain": [], "error": str(exc)}
            rows.append({"scenario": name, "mode": "ungrounded", "seed": seed, **score(output, lines, truth)})
            print(f"{name} seed {seed}: grounded {rows[-2]['verified']}/{rows[-2]['claims']} verified, "
                  f"ungrounded {rows[-1]['verified']}/{rows[-1]['claims']} verified")
    summary = summarize(rows)
    DOCS_DIR.mkdir(exist_ok=True)
    (DOCS_DIR / "ablation.json").write_text(json.dumps(
        {"model": MODEL, "temperature": args.temperature, "seeds": seeds,
         "benign_sample": BENIGN_SAMPLE, "summary": summary, "rows": rows}, indent=2), encoding="utf-8")
    md = ["# Ablation: grounded vs ungrounded", "",
          f"Model {MODEL}, temperature {args.temperature}, seeds {seeds}, scenarios {args.scenarios}. "
          f"Ungrounded mode sees all attack lines plus {BENIGN_SAMPLE} random benign lines, no rule findings.", "",
          "| Mode | Runs | Claims | Verified rate | Invalid IDs | Benign lines cited | Attack coverage | Errors |",
          "|---|---|---|---|---|---|---|---|"]
    for mode, s in summary.items():
        md.append(f"| {mode} | {s['runs']} | {s['claims']} | {pct(s['verification_rate'])} | {s['invalid_ids']} | "
                  f"{s['benign_lines_cited']} | {pct(s['attack_coverage'])} | {s['errors']} |")
    (DOCS_DIR / "ablation.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))


if __name__ == "__main__":
    main()