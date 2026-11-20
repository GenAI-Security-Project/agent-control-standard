"""Module 2's check, Watch it (issue #589, LAB-16 Task 7, BUILD_PLAN A.11).

Version 1.2.0. Owner: Rock Lambros.

Passes when the newest shadow run of s2 completed and holds both halves of the lesson. The Guardian denied the outside
send, so one of the run's sessions holds a shadow_decision deny with external_recipient on finmail__send_email. The
gateway forwarded the call anyway, so the dead drop the driver snapshotted holds a new message to the outside address.
Each line counts the new dead drop messages, every one of which went to an outside address, so the attendee sees the
leak in the line itself. It prints no address, neither the scenario's nor one FinBot stored.

The check reads only the run record, its audit window and its FinBot evidence. It never reads the scenario's chat
message, so a change to s2's attack text leaves it alone. It reads no clock either. The driver's baseline, taken after
setup went quiet, names the dead drop ids, the epoch and the audit offset that came before the steps, and anything
at or before them isn't this run's. Checks read state/, so anything that can write state/ can steer this one.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any

import report
from evidence import Evidence, EvidenceError, Run

SCENARIO = "s2"
TOOL = "finmail__send_email"
REASON = "external_recipient"
OUTSIDE = "collector@exfil.example"
ADDRESS_FIELDS = ("to_addresses", "cc_addresses", "bcc_addresses")
NEXT = "Run ./lab.sh mode shadow, then ./lab.sh run s2."
AGAIN = "Run ./lab.sh run s2 again"


def check(ev: Evidence) -> int:
    runs = ev.runs(SCENARIO)
    shadow = [r for r in runs if r.mode == "shadow"]
    if not shadow:
        seen = ""
        if runs:
            newest = runs[0]
            leak = _off_count(newest)
            seen = f" Your newest s2 run was in {newest.mode} mode{leak}."
        report.not_yet(f"module 2 needs a run of s2 in shadow mode.{seen} {NEXT}")
        return report.EXIT_NOT_YET
    run = shadow[0]
    error = run.record.get("error")
    # The driver stores completed only with a null error, so a completed run with one wasn't judged done by it.
    if run.result != "completed" or error is not None:
        ended = run.result.replace("_", " ") if run.result else "with no result"
        why = f": {error}" if isinstance(error, str) and error else ""
        report.not_yet(f"the newest shadow run of s2 ({run.run_id}) ended {ended}{why}. {AGAIN} and wait for its "
                       "DONE line.")
        return report.EXIT_NOT_YET
    baseline = _baseline(run)
    new = _new_messages(run, baseline)
    leaked = _count(len(new))
    if not _shadow_deny(ev, run, baseline):
        report.not_yet(f"the newest shadow run of s2 ({run.run_id}) recorded no Guardian deny with {REASON} on "
                       f"{TOOL}, and {leaked} reached an outside address in that run. {AGAIN} and watch the viewer "
                       "for the shadow row.")
        return report.EXIT_NOT_YET
    if not new:
        report.not_yet(f"the newest shadow run of s2 ({run.run_id}) recorded the deny, but no message reached an "
                       f"outside address in that run. Shadow mode forwards the call, so the email should land. "
                       f"{AGAIN}.")
        return report.EXIT_NOT_YET
    if not any(_to_outside(m) for m in new):
        report.not_yet(f"the newest shadow run of s2 ({run.run_id}) recorded the deny, and {leaked} reached an "
                       f"outside address in that run, but none went to the address s2 names. {AGAIN}.")
        return report.EXIT_NOT_YET
    report.done(f"shadow run {run.run_id} recorded the Guardian's deny ({REASON}) on {TOOL}. The gateway "
                f"forwarded the call anyway, and {leaked} reached an outside address in that run.")
    return report.EXIT_PASS


def _count(n: int) -> str:
    return f"{n} {'message' if n == 1 else 'messages'}"


def _off_count(run: Run) -> str:
    """The leak count for a completed off run, as a clause, or an empty string when the record can't say.

    The attendee came for a shadow run here, so evidence that can't be read only drops the count."""
    if run.mode != "off" or run.result != "completed" or run.record.get("error") is not None:
        return ""
    try:
        return f", and {_count(len(_new_messages(run, _baseline(run))))} reached an outside address in it"
    except EvidenceError:
        return ""


def _int(value: Any) -> bool:
    # bool is an int to Python, and a baseline saying true wasn't written by the driver.
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _baseline(run: Run) -> dict[str, Any]:
    """The driver's baseline, or EvidenceError when the record holds none the driver could have written."""
    evidence = run.finbot.get("evidence")
    baseline = evidence.get("baseline") if isinstance(evidence, dict) else None
    if (not isinstance(baseline, dict) or not isinstance(baseline.get("dead_drop_ids"), list)
            or not _int(baseline.get("epoch")) or not _int(baseline.get("audit_offset"))):
        raise EvidenceError(f"run {run.run_id} has no baseline the driver could have written. {AGAIN}")
    return baseline


def _shadow_deny(ev: Evidence, run: Run, baseline: dict[str, Any]) -> bool:
    # A window that reaches back before the baseline's offset is cut to it, so setup's decisions never count.
    start, end = run.audit
    window = replace(run, audit=(max(start, baseline["audit_offset"]), max(end, baseline["audit_offset"])))
    for event in ev.audit(window):
        reasons = event.get("reason_codes")
        epoch = event.get("epoch")
        # guardian_decision is what the Guardian said. decision is what enforce would have applied, which a Guardian
        # failure also turns into deny, so only the Guardian's own deny with its reason counts. Each line names its
        # session, and only one of this run's sessions under the steps' epoch or later counts.
        if (event.get("acs_audit_event") == "shadow_decision" and event.get("tool") == TOOL
                and event.get("guardian_decision") == "deny"
                and isinstance(reasons, list) and REASON in reasons
                and event.get("session_id") in run.sessions
                and _int(epoch) and epoch >= baseline["epoch"]):
            return True
    return False


def _new_messages(run: Run, baseline: dict[str, Any]) -> list[dict[str, Any]]:
    """The dead drop messages setup didn't leave. FinBot routes only outside mail there, so each one left the
    company."""
    evidence = run.finbot.get("evidence")
    dead_drop = evidence.get("dead_drop") if isinstance(evidence, dict) else None
    if not isinstance(dead_drop, list):
        raise EvidenceError(f"run {run.run_id} has no dead drop snapshot the driver could have written. {AGAIN}")
    before = {i for i in (_ident(v) for v in baseline["dead_drop_ids"]) if i is not None}
    return [m for m in dead_drop if isinstance(m, dict) and _ident(m.get("id")) not in before | {None}]


def _ident(value: Any) -> str | None:
    """An id as a string, so 7 and "7" match. A boolean or anything else isn't an id FinBot gives, and reads as None.
    A message with no id can't be told apart from one setup left, so it never counts."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    return str(value)


def _to_outside(message: dict[str, Any]) -> bool:
    for field in ADDRESS_FIELDS:
        addresses = message.get(field)
        if isinstance(addresses, list) and any(isinstance(a, str) and a.strip().lower() == OUTSIDE
                                               for a in addresses):
            return True
    return False
