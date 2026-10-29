"""Import a real-world or uploaded log into a scenario folder.

Adds evidence IDs, masks public IPs to 10.200.x.y (consistent per IP, private IPs kept),
and writes an unlabeled ground_truth.json (no precision/recall possible without labels).
"""
import argparse
import ipaddress
import json
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ID_PREFIX_RE = re.compile(r"^L\d+\s+")
MAX_AUTH_LINES = 5000  # auth IDs must stay below L5001, where access IDs start
STALE_OUTPUTS = ("llm_analysis.json", "claim_validation.json", "evaluation.json")
LOGHUB_CITATION = ("Loghub OpenSSH_2k sample. J. Zhu, S. He, P. He, J. Liu, M. R. Lyu, "
                   "'Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics', "
                   "ISSRE 2023. https://github.com/logpai/loghub")


class IpMasker:
    def __init__(self):
        self.mapping = {}

    def __call__(self, match):
        ip = match.group(0)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ip
        if addr.is_private or addr.is_loopback:
            return ip
        if ip not in self.mapping:
            n = len(self.mapping) + 1
            self.mapping[ip] = f"10.200.{n // 250}.{n % 250 + 1}"
        return self.mapping[ip]


def import_lines(text, filename, masker, mask=True):
    start = 1 if filename == "auth.log" else 5001
    out = []
    for line in text.splitlines():
        line = ID_PREFIX_RE.sub("", line.strip())
        if not line:
            continue
        if mask:
            line = IP_RE.sub(masker, line)
        out.append(f"L{start + len(out):04d} {line}")
    return out


def import_scenario(name, auth_text=None, access_text=None, description="", source="",
                    mask=True, out_root=DATA_DIR):
    out = Path(out_root) / name
    out.mkdir(parents=True, exist_ok=True)
    for stale in STALE_OUTPUTS:
        (out / stale).unlink(missing_ok=True)
    masker, all_ids, truncated = IpMasker(), [], False
    for filename, text in (("auth.log", auth_text), ("access.log", access_text)):
        path = out / filename
        if text is None:
            path.unlink(missing_ok=True)
            continue
        lines = import_lines(text, filename, masker, mask)
        if filename == "auth.log" and len(lines) > MAX_AUTH_LINES:
            lines, truncated = lines[:MAX_AUTH_LINES], True
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        all_ids += [f"{filename}:{line.split()[0]}" for line in lines]
    truth = {"scenario": name, "description": description, "source": source,
             "labels_available": False, "ip_masking": mask,
             "masked_ip_count": len(masker.mapping), "truncated": truncated,
             "expected_rules": [], "suspicious_evidence_ids": [], "all_evidence_ids": all_ids}
    (out / "ground_truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    return truth


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="log file to import")
    ap.add_argument("--name", default="REAL_SSH")
    ap.add_argument("--kind", choices=["auth", "access"], default="auth")
    ap.add_argument("--no-mask", action="store_true")
    args = ap.parse_args()
    text = Path(args.path).expanduser().read_text(encoding="utf-8", errors="replace")
    description = ("Real-world OpenSSH server log (public research dataset). Public IPs masked. "
                   "No ground-truth labels.")
    truth = import_scenario(args.name,
                            auth_text=text if args.kind == "auth" else None,
                            access_text=text if args.kind == "access" else None,
                            description=description, source=LOGHUB_CITATION, mask=not args.no_mask)
    print(f"{args.name}: {len(truth['all_evidence_ids'])} lines imported, "
          f"{truth['masked_ip_count']} public IPs masked, truncated={truth['truncated']}")


if __name__ == "__main__":
    main()