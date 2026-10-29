# Case study: validator catches off-by-one citations

Cause: analyzer sorted findings by severity, breaking time order in the prompt.
Effect on S1: LLM shifted citations by one line.

| Claim stage | Cited | Validator result |
|---|---|---|
| authentication_attempt | L0001-L0006 (failures) | verified |
| successful_authentication | L0007 (login), L0008 (sudo) | unverified: sudo line does not support a login claim |
| privileged_activity | L0007 (login only) | unverified: needs a sudo line |

Fix: keep findings in original order when capping. Result: S1 back to 3/3 verified.
Lesson: plausible-looking LLM citations can be wrong; automatic checking caught what a skim would miss.
