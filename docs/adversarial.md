# Adversarial validator evaluation

- Fabricated claims caught: **15/15**
- Valid claims accepted: **5/5**
- Known blind spots (true lines, wrong interpretation) passed through: **2/2**

| ID | Category | Case | Expected | Actual | OK | Reason |
|---|---|---|---|---|---|---|
| V1 | valid_control | Real brute-force lines | verified | verified | yes | All cited lines passed. |
| V2 | valid_control | Failures then success | verified | verified | yes | All cited lines passed. |
| V3 | valid_control | Login then sudo | verified | verified | yes | All cited lines passed. |
| V4 | valid_control | SQLi and traversal requests | verified | verified | yes | All cited lines passed. |
| V5 | valid_control | Login linked to large download | verified | verified | yes | All cited lines passed. |
| F1 | fabricated | Nonexistent ID | unverified | unverified | yes | Evidence ID does not exist in the source logs.; Claim needs at least one line showing: failed. |
| F2 | fabricated | Malformed ID | unverified | unverified | yes | Malformed evidence ID.; Claim needs at least one line showing: failed. |
| F3 | fabricated | No evidence at all | unverified | unverified | yes | No evidence IDs supplied. |
| F4 | fabricated | Invented stage and event | unverified | unverified | yes | Unrecognized claim type. |
| F5 | fabricated | Benign login cited as brute force | unverified | unverified | yes | Line does not support a authentication_attempt claim.; Claim needs at least one line showing: failed. |
| F6 | fabricated | Benign request cited as exploit | unverified | unverified | yes | Line does not support a exploitation_attempt claim.; Claim needs at least one line showing: web_attack. |
| F7 | fabricated | Small response cited as large transfer | unverified | unverified | yes | Line does not support a large_data_transfer claim.; Claim needs at least one line showing: large. |
| F8 | fabricated | Correlation with login only | unverified | unverified | yes | Claim needs at least one line showing: large. |
| F9 | fabricated | Correlation with transfer only | unverified | unverified | yes | Claim needs at least one line showing: accepted. |
| F10 | fabricated | Privilege claim without sudo line | unverified | unverified | yes | Claim needs at least one line showing: sudo. |
| F11 | fabricated | Success claim with only failures | unverified | unverified | yes | Claim needs at least one line showing: accepted. |
| F12 | fabricated | Mixed real and fake IDs | unverified | unverified | yes | Evidence ID does not exist in the source logs. |
| F13 | fabricated | Right number, wrong file | unverified | unverified | yes | Evidence ID does not exist in the source logs.; Claim needs at least one line showing: failed. |
| F14 | fabricated | Cron job cited as sudo | unverified | unverified | yes | Line does not support a privileged_activity claim.; Claim needs at least one line showing: sudo. |
| F15 | fabricated | Auth failure cited as web exploit | unverified | unverified | yes | Line does not support a exploitation_attempt claim.; Claim needs at least one line showing: web_attack. |
| B1 | known_blind_spot | Single typo cited as brute force | verified | verified | yes | All cited lines passed. |
| B2 | known_blind_spot | Backup cited as exfiltration | verified | verified | yes | All cited lines passed. |

Blind spots show the validator checks whether cited lines support the event type, not whether the interpretation (malicious vs benign) is correct.
