"""Parse raw HTTP request dumps (CSIC 2010 format) and extract per-request numeric features.

Two feature sets: PAYLOAD (path, query, body: what an access.log line can also show) and HEADER
(headers only, used as an artifact check: a payload-free model that still scores well means the
dataset leaks through how it was generated).
"""
import re
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from parser.correlator import SQLI_RE, TRAVERSAL_RE

REQ_RE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)\s+HTTP/", re.M)
SPECIALS = "'\";<>()%-/\\=&|`{}[]$*!"
KEYWORDS = ["select", "union", "insert", "drop", "update", "delete", "from", "where", "or ", "and ", "--",
            "script", "alert", "onerror", "onload", "javascript", "../", "etc/passwd", "cmd", "exec", "sleep",
            "<!--", "../.."]
PAYLOAD_COLUMNS = (["path_len", "path_depth", "query_len", "body_len", "n_params", "max_val_len", "is_post",
                    "digit_ratio", "alpha_ratio", "upper_ratio", "non_ascii", "pct_encoded", "sqli_re",
                    "traversal_re", "has_ext_jsp"]
                   + [f"sp_{i}" for i in range(len(SPECIALS))] + [f"kw_{i}" for i in range(len(KEYWORDS))])
HEADER_COLUMNS = ["n_headers", "has_cookie", "has_content_type", "content_length", "ua_len", "accept_len"]


def split_requests(text):
    """Yield (head, body) per request. Requests are separated by blank lines; POST bodies follow headers."""
    blocks = re.split(r"\r?\n\r?\n", text)
    i = 0
    while i < len(blocks):
        head = blocks[i]
        if REQ_RE.match(head.lstrip()):
            body = ""
            if head.lstrip().startswith(("POST", "PUT")) and i + 1 < len(blocks) \
                    and not REQ_RE.match(blocks[i + 1].lstrip()):
                body = blocks[i + 1]
                i += 1
            yield head.strip(), body.strip()
        i += 1


def features(head, body):
    lines = head.splitlines()
    m = REQ_RE.match(lines[0])
    method, target = m.group(1), m.group(2)
    u = urlsplit(target)
    hdr = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdr[k.strip().lower()] = v.strip()
    raw_payload = u.path + "?" + u.query + "&" + body
    dec = unquote_plus(unquote_plus(raw_payload, encoding="latin-1"), encoding="latin-1")
    low = dec.lower()
    params = parse_qsl(u.query, keep_blank_values=True) + parse_qsl(body, keep_blank_values=True)
    n = max(len(dec), 1)
    f = {"path_len": len(u.path), "path_depth": u.path.count("/"), "query_len": len(u.query),
         "body_len": len(body), "n_params": len(params),
         "max_val_len": max((len(v) for _, v in params), default=0), "is_post": int(method == "POST"),
         "digit_ratio": sum(c.isdigit() for c in dec) / n, "alpha_ratio": sum(c.isalpha() for c in dec) / n,
         "upper_ratio": sum(c.isupper() for c in dec) / n, "non_ascii": sum(ord(c) > 127 for c in dec),
         "pct_encoded": raw_payload.count("%"), "sqli_re": int(bool(SQLI_RE.search(dec))),
         "traversal_re": int(bool(TRAVERSAL_RE.search(dec))), "has_ext_jsp": int(u.path.endswith(".jsp"))}
    for i, ch in enumerate(SPECIALS):
        f[f"sp_{i}"] = dec.count(ch)
    for i, kw in enumerate(KEYWORDS):
        f[f"kw_{i}"] = low.count(kw)
    f.update({"n_headers": len(hdr), "has_cookie": int("cookie" in hdr), "has_content_type": int("content-type" in hdr),
              "content_length": int(hdr.get("content-length", 0) or 0), "ua_len": len(hdr.get("user-agent", "")),
              "accept_len": len(hdr.get("accept", ""))})
    return f
