"""Simulated live log feed: replay parsed records in time order and run the rule engine as each
line "arrives", so alerts fire at the line that triggers them.

The rule engine itself is unchanged: after every new line we call correlate() on the records
received so far (about 7 ms for 2,000 lines) and report findings not seen before.
"""
from parser.correlator import correlate


GROWING_RULES = {"ssh_brute_force", "username_spraying", "auth_attempts_exhausted", "slow_brute_force",
                 "denied_sudo"}


def alert_key(finding):
    """Identity of an alert across successive re-evaluations.

    A brute-force finding's evidence grows as more failures arrive, so it is keyed by IP
    (one alert per attacking IP); every other rule is keyed by the lines it cites.
    """
    if finding["rule_id"] in GROWING_RULES:
        return (finding["rule_id"], finding.get("ip") or finding.get("user"))
    return (finding["rule_id"], tuple(sorted(finding["evidence_ids"])))


def stream(records):
    """Yield (line_number, record, new_alerts) for each record, in the order given.

    `records` must be time-ordered (parse_scenario returns them that way). new_alerts are the
    findings that first appear once this line has been received.
    """
    seen = set()
    for i, record in enumerate(records, start=1):
        new = []
        for finding in correlate(records[:i]):
            key = alert_key(finding)
            if key not in seen:
                seen.add(key)
                new.append(finding)
        yield i, record, new
