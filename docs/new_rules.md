# Parser and rule additions (SSH)

## Parser (`parser/log_parser.py`)
New auth event types, previously all `other_auth_event` with no IP:
- `preauth_disconnect`: lines marked `[preauth]` (connection closed/reset/disconnected, "Received disconnect ...
  [preauth]") plus "Did not receive identification string" and pre-auth timeouts. IP and user extracted when present.
- `max_auth_attempts`: "maximum authentication attempts exceeded for X from IP" and "Disconnecting: Too many
  authentication failures for X [preauth]". The second form has no IP; it is filled from the latest earlier line of
  the same sshd process (host + pid) within 5 minutes and marked `ip_source="pid"`. Lines with their own IP are `"line"`.
- `invalid_user`: "Invalid user X from IP". The follow-up "input_userauth_request: invalid user X [preauth]" stays
  `other_auth_event` so one attempt is not counted twice.
- A normal post-login "Received disconnect ... disconnected by user" is not preauth.

## Rules (`parser/correlator.py`)
| Rule | Fires when | Severity | ATT&CK |
|---|---|---|---|
| `username_spraying` | >=4 failed/invalid-user attempts covering >=3 usernames from one IP within 10 min | high | T1110.003 |
| `auth_attempts_exhausted` | sshd reports the attempt limit reached for an IP | medium; high at 3+ events | T1110 |
| `probe_then_success` | >=2 attempts across >=2 usernames, then a success from the same IP within 10 min (and not already `failure_then_success`) | high | T1078 |

Deliberately not flagged: one user mistyping a password then succeeding. It is indistinguishable from legitimate use
(see `docs/real_detector_results.md`, reviewed hard negatives).

Also updated so the new rules flow through: `llm/analyzer.py` (rule-to-stage), `validator/claim_validator.py` (stage map,
and "failed" evidence now also matches Invalid user / attempt-limit lines), `scoring/trust_score.py` (rule confidence),
`feed/live_feed.py` (one live alert per IP for growing rules), `generator/generate_logs.py` (S1 variants whose attacker
uses >=3 usernames now list `username_spraying` in expected_rules).

## Second batch: slow guessing and denied sudo
| Rule | Fires when | Severity | ATT&CK |
|---|---|---|---|
| `slow_brute_force` | >=5 failed/invalid-user attempts from one IP within 24 h, no successful login from it, and the IP is not already reported as brute force or spraying | medium | T1110.001 |
| `denied_sudo` | sudo refused a command ("user NOT in sudoers", "command not allowed", "N incorrect password attempts"); grouped per user within 1 h | medium; high if it targets /etc/shadow, /etc/sudoers, ssh keys, /root, or 3+ retries | T1548.003 |

Parser: a denied sudo line is now `sudo_denied` (it was `privileged_activity`, i.e. treated as a command that ran, which
could also feed `login_then_sudo`). Typos are kept out of `slow_brute_force` because an IP that ever logs in is skipped
and the attempts must fall within 24 h (3 typos over a week do not fire). Window searches are linear-time sliding windows.

## Effect
Findings for the fixed scenarios S1-S5, S1_mitigated, S6_injection and S2/S3 variants are unchanged (checked by hashing
before/after). 20 generated S1 variants gain a `username_spraying` finding, all on attacker lines. Real logs gain findings.
