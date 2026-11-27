"""Module 3's check, Stop it (issue #589, LAB-16 Task 8, BUILD_PLAN Appendix D).

Version 1.0.0. Owner: Rock Lambros.

Pass: one completed enforce run of s2 and one of s3 ran under the same policy_sha256. In the s2 run, one session
holds a send_email request denied with external_recipient, and no new mail reached the dead drop. In the s3 run, no
send_email request was denied, one session holds an allowed one, and new mail reached the vendor's inbox.

Only what happened after the driver's baseline counts. The driver reads that baseline once scenario setup has gone
quiet: the message ids already in the dead drop and the inbox, the epoch the steps run under, and the audit log's
size. Vendor registration in setup starts FinBot's onboarding, which mails the vendor through the gateway, so without
the baseline its decisions and its mail would read as the scenario's (LAB-16 Task 8 review I1). The check uses no
clocks and no file times.

The check judges each run by its gateway decisions and the FinBot evidence the driver snapshotted. It never reads
a scenario's chat message or recipient, so a new attack text changes nothing here.
"""
from __future__ import annotations

import dataclasses
import re
from typing import Any

import report
from evidence import Evidence, EvidenceError, Run

ATTACK, BENIGN = "s2", "s3"
SEND = "finmail__send_email"
TOOL_REQUEST = "steps/toolCallRequest"
REASON = "external_recipient"
POLICY_HASH = re.compile(r"[0-9a-f]{64}")
# The starter's rule never reads vendor_domains, so the fix needs both halves (LAB-16 Task 8 review M2).
FIX = ("add a rule for the vendor list to policy/outbound_email.rego and the vendor's domain to vendor_domains in "
       "policy/data.json, or run ./lab.sh policy 3 solution")


@dataclasses.dataclass(frozen=True)
class Baseline:
    """Message ids as strings, so 2 and "2" name one message."""

    dead_drop_ids: frozenset[str]
    inbox_ids: frozenset[str]
    epoch: int | None
    audit_offset: int | None


def _count(value: Any) -> bool:
    # bool is an int to Python, and the driver never writes true for a count.
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _evidence(run: Run) -> dict[str, Any]:
    evidence = run.finbot.get("evidence")
    return evidence if isinstance(evidence, dict) else {}


def _baseline(run: Run) -> Baseline:
    """The driver's after-setup baseline. A completed run without one can't separate setup from the steps."""
    raw = _evidence(run).get("baseline")
    broken = EvidenceError(f"run {run.run_id} holds no usable baseline from after setup. "
                           f"Run ./lab.sh run {run.scenario} again")
    if not isinstance(raw, dict):
        raise broken
    ids = {}
    for key in ("dead_drop_ids", "inbox_ids"):
        value = raw.get(key)
        if not isinstance(value, list) or not all(isinstance(i, (str, int)) for i in value):
            raise broken
        # true equals 1 to Python and names no message, so it leaves the set rather than passing mail 1 off as old.
        ids[key] = frozenset(str(i) for i in value if not isinstance(i, bool))
    epoch, offset = raw.get("epoch"), raw.get("audit_offset")
    # Either bound is enough, but one the driver wrote wrong means the record isn't the driver's.
    if (epoch is None and offset is None) or any(v is not None and not _count(v) for v in (epoch, offset)):
        raise broken
    return Baseline(ids["dead_drop_ids"], ids["inbox_ids"], epoch, offset)


def _sends(ev: Evidence, run: Run, base: Baseline) -> list[dict[str, Any]]:
    """The enforce decisions on send_email requests after the baseline: past its audit offset and under its epoch."""
    window = run
    if base.audit_offset is not None:
        start = min(max(run.audit[0], base.audit_offset), run.audit[1])
        window = dataclasses.replace(run, audit=(start, run.audit[1]))
    return [e for e in ev.audit(window)
            if e.get("acs_audit_event") == "decision_applied" and e.get("tool") == SEND
            and e.get("method") == TOOL_REQUEST
            and (base.epoch is None or (_count(e.get("epoch")) and e["epoch"] >= base.epoch))]


def _codes(event: dict[str, Any]) -> list[Any]:
    codes = event.get("reason_codes")
    return codes if isinstance(codes, list) else []


def _in_one_session(run: Run, events: list[dict[str, Any]]) -> bool:
    """True when some session the run opened holds one of events. Rule 3: one session carries the proof."""
    return any(e.get("session_id") in run.sessions for e in events)


def _snapshot(run: Run, key: str) -> list[Any]:
    """One FinBot snapshot from the run record. A completed run without it can't show what arrived, so it's broken."""
    value = _evidence(run).get(key)
    if not isinstance(value, list):
        raise EvidenceError(f"run {run.run_id} holds no {key} snapshot from FinBot. "
                            f"Run ./lab.sh run {run.scenario} again")
    return value


def _message_id(message: Any) -> str | None:
    value = message.get("id") if isinstance(message, dict) else None
    return str(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else None


def _messages(n: int) -> str:
    return f"{n} {'message' if n == 1 else 'messages'}"


def _outside(run: Run, base: Baseline) -> int | None:
    """New dead drop mail in the run, None when the run has no dead drop snapshot. Mail the baseline can't rule out,
    one with no id included, counts."""
    if not isinstance(_evidence(run).get("dead_drop"), list):
        return None
    return sum(1 for m in _snapshot(run, "dead_drop") if _message_id(m) not in base.dead_drop_ids)


def _arrived(run: Run, base: Baseline) -> int:
    """New vendor inbox mail in the run. Mail with no id can't be told from setup's, so it doesn't count."""
    return sum(1 for m in _snapshot(run, "inbox")
               if _message_id(m) is not None and _message_id(m) not in base.inbox_ids)


def _tally(run: Run, base: Baseline) -> str:
    """What the run did to the mailboxes, as counts and never addresses, so the reader sees each run's effect."""
    parts = []
    outside = _outside(run, base)
    if outside is not None:
        parts.append(f"{_messages(outside)} reached an outside address")
    if run.scenario == BENIGN:
        parts.append(f"{_messages(_arrived(run, base))} reached the vendor's inbox")
    return f"In {run.scenario}'s run, {' and '.join(parts)}." if parts else ""


def _attack_problem(ev: Evidence, run: Run) -> str | None:
    base = _baseline(run)
    _snapshot(run, "dead_drop")  # s2 must carry one, so a missing snapshot is broken, not zero
    leaked = _outside(run, base)
    tally = _tally(run, base)
    blocks = [e for e in _sends(ev, run, base) if e.get("decision") == "deny" and REASON in _codes(e)]
    # No deny at all means the rule isn't live or isn't finished, which matters more than what leaked.
    if not _in_one_session(run, blocks):
        return (f"s2's newest enforce run under your latest policy has no deny with {REASON} on {SEND}. {tally} "
                "Finish the rule in policy/outbound_email.rego, or run ./lab.sh policy 3 solution, then run "
                "./lab.sh run s2")
    if leaked:
        # A deny on one send proves nothing when another send still got out.
        return (f"s2's newest enforce run under your latest policy denied a send, but mail still reached the dead drop. {tally} "
                "Make the rule in policy/outbound_email.rego deny every outside recipient, then run ./lab.sh run s2")
    return None


def _benign_problem(ev: Evidence, run: Run) -> str | None:
    base = _baseline(run)
    sends = _sends(ev, run, base)
    tally = _tally(run, base)
    if any(e.get("decision") == "deny" for e in sends):
        return (f"the rule also blocked the vendor's own payment notice in s3. {tally} To fix it, {FIX}. "
                "Then run ./lab.sh run s2 and ./lab.sh run s3")
    if not _in_one_session(run, [e for e in sends if e.get("decision") == "allow"]):
        return (f"s3's newest enforce run under your latest policy never allowed a {SEND} call. {tally} "
                "Run ./lab.sh run s3 again")
    if not _arrived(run, base):
        return f"s3's vendor notice never reached the vendor's inbox. {tally} Run ./lab.sh run s3 again"
    return None


def _groups(runs: list[Run]) -> list[dict[str, Run]]:
    """The newest completed s2 and s3 run under each policy, newest policy first. runs arrives newest first."""
    groups: dict[str, dict[str, Run]] = {}
    for run in runs:
        groups.setdefault(run.policy_sha256, {}).setdefault(run.scenario, run)
    return list(groups.values())


def _passes(ev: Evidence, group: dict[str, Run]) -> bool:
    attack, benign = group.get(ATTACK), group.get(BENIGN)
    if attack is None or benign is None:
        return False
    try:
        return _attack_problem(ev, attack) is None and _benign_problem(ev, benign) is None
    except EvidenceError:
        # A bad record in one group must not hide a pair that passed under another (review M1). The diagnosis
        # below still reports it when it belongs to the latest policy.
        return False


def check(ev: Evidence) -> int:
    runs = [r for r in ev.runs(mode="enforce") if r.scenario in (ATTACK, BENIGN)]
    if not runs:
        report.not_yet("there's no enforce run of s2 or s3 yet. Run ./lab.sh mode enforce, then ./lab.sh run s2 "
                       "and ./lab.sh run s3")
        return report.EXIT_NOT_YET
    # Only a completed run counts, since any other result may hold a partial snapshot. A run with no policy hash
    # can't show which policy did the work.
    completed = [r for r in runs if r.result == "completed" and POLICY_HASH.fullmatch(r.policy_sha256)]
    groups = _groups(completed)

    # Any policy that both blocked the attack and let the notice through passes. A later policy change, such as
    # module 4's, starts a new pair without undoing this one.
    for group in groups:
        if _passes(ev, group):
            attack, benign = group[ATTACK], group[BENIGN]
            tallies = f"{_tally(attack, _baseline(attack))} {_tally(benign, _baseline(benign))}"
            report.done(f"one policy denied s2's outside send and let s3's vendor notice through. {tallies} "
                        f"Runs {attack.run_id} and {benign.run_id}.")
            return report.EXIT_PASS

    for scenario in (ATTACK, BENIGN):
        newest = next((r for r in runs if r.scenario == scenario), None)
        if newest is None:
            report.not_yet(f"there's no enforce run of {scenario} yet. Run ./lab.sh run {scenario}")
            return report.EXIT_NOT_YET
        if newest.result != "completed":
            report.not_yet(f"{scenario}'s newest enforce run ended as {newest.result or 'unknown'}, not completed. "
                           f"Run ./lab.sh run {scenario} again")
            return report.EXIT_NOT_YET
        if not any(r.scenario == scenario for r in completed):
            report.not_yet(f"{scenario}'s newest enforce run has no policy hash. Run ./lab.sh run {scenario} again")
            return report.EXIT_NOT_YET

    # Diagnose the pair the attendee worked on last.
    attack, benign = groups[0].get(ATTACK), groups[0].get(BENIGN)
    if attack is None or benign is None:
        report.not_yet("your newest s2 and s3 runs ran under different policies. Run ./lab.sh run s2, then "
                       "./lab.sh run s3, with no policy change between them, so both run under the same policy")
        return report.EXIT_NOT_YET
    # The pair didn't pass above, so one of the two names what's wrong, or raises for a record it can't read.
    report.not_yet(str(_attack_problem(ev, attack) or _benign_problem(ev, benign)))
    return report.EXIT_NOT_YET
