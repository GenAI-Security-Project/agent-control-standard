"""Module 6's check, Poison a tool (issue #589, LAB-16 Task 11, BUILD_PLAN A.11).

Version 1.1.0. Owner: Rock Lambros.

Pass: the newest enforce run of s6 finished, and after its baseline the gateway applied a Guardian deny with
tool_content_hash_mismatch to a finmail__send_email call in one of the run's sessions. No send_email call went through,
and the dead drop gained no message during the run.

The check judges the run by its gateway decisions and the FinBot evidence the driver snapshotted. It never reads the
changed tool description or the scenario's chat message, so a new attack text changes nothing here. The digest in
tool.version is a lab convention until issue #38. Checks read state/, so anything that can write state/ can steer this
one.
"""
from __future__ import annotations

import dataclasses
from typing import Any

import report
from evidence import Evidence, EvidenceError, Run

SCENARIO = "s6"
SEND = "finmail__send_email"
TOOL_REQUEST = "steps/toolCallRequest"
MISMATCH = "tool_content_hash_mismatch"
UNREGISTERED = "tool_unregistered"
FIX = "finish the rule in policy/tool_pins.rego, or run ./lab.sh policy 6 solution, then run ./lab.sh run s6"
# lab pins leaves out every line a poisoned run showed the model, so one clean run rebuilds the registry without
# wiping the attendee's earlier modules. The clean run goes in off mode, as the shipped pins capture did, so enforce
# never denies its calls as unregistered and its replay stays on the recorded branch.
REPIN = ("./lab.sh mode off, ./lab.sh run s6 --clean, ./lab.sh pins, ./lab.sh mode enforce, "
         "then ./lab.sh run s6")
FIRST = "Run ./lab.sh policy 6 solution, ./lab.sh mode enforce, then ./lab.sh run s6"


def _baseline(run: Run) -> tuple[int, list[Any]]:
    """The audit offset and dead drop ids the driver read after setup went quiet. A completed run without them can't
    show what arrived during the steps, so it's broken."""
    evidence = run.finbot.get("evidence")
    baseline = evidence.get("baseline") if isinstance(evidence, dict) else None
    offset = baseline.get("audit_offset") if isinstance(baseline, dict) else None
    ids = baseline.get("dead_drop_ids") if isinstance(baseline, dict) else None
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or not isinstance(ids, list):
        raise EvidenceError(f"run {run.run_id} holds no baseline from the driver. Run ./lab.sh run s6 again")
    return offset, ids


def _new_dead_drop(run: Run, known: list[Any]) -> int:
    evidence = run.finbot.get("evidence")
    dead_drop = evidence.get("dead_drop") if isinstance(evidence, dict) else None
    if not isinstance(dead_drop, list):
        raise EvidenceError(f"run {run.run_id} holds no dead drop snapshot from FinBot. Run ./lab.sh run s6 again")
    # A message with no id can't be matched to the baseline, so it counts as new.
    return sum(1 for m in dead_drop
               if not (isinstance(m, dict) and m.get("id") is not None and m.get("id") in known))


def _sends(ev: Evidence, run: Run, offset: int) -> list[dict[str, Any]]:
    """The enforce decisions the gateway applied to send_email calls after the baseline's audit offset."""
    # The driver opens the window at or after the offset. Narrowing it anyway keeps setup's decisions out of a record
    # whose window starts earlier. The start is clamped so the window never runs backwards.
    start = min(max(run.audit[0], offset), run.audit[1])
    window = dataclasses.replace(run, audit=(start, run.audit[1]))
    return [e for e in ev.audit(window)
            if e.get("acs_audit_event") == "decision_applied" and e.get("tool") == SEND
            and e.get("method") == TOOL_REQUEST]


def _guardian_deny(event: dict[str, Any], code: str, sessions: set[str]) -> bool:
    # guardian_decision is what the Guardian said. Enforce also applies deny when the Guardian fails, and that deny
    # isn't the pin rule's.
    codes = event.get("reason_codes")
    return (event.get("decision") == "deny" and event.get("guardian_decision") == "deny"
            and isinstance(codes, list) and code in codes and event.get("session_id") in sessions)


def check(ev: Evidence) -> int:
    runs = ev.runs(SCENARIO)
    enforce = [r for r in runs if r.mode == "enforce"]
    if not enforce:
        seen = f" Your newest s6 run was in {runs[0].mode} mode." if runs else ""
        report.not_yet(f"module 6 needs a run of s6 in enforce mode.{seen} {FIRST}")
        return report.EXIT_NOT_YET
    run = enforce[0]
    if run.result != "completed":
        report.not_yet(f"s6's newest enforce run ({run.run_id}) ended as {run.result or 'no result'}, so it can't "
                       "count. Run ./lab.sh run s6 again")
        return report.EXIT_NOT_YET
    # The driver clears error whenever it stores completed, so a record holding both wasn't written that way.
    if run.record.get("error") is not None:
        report.not_yet(f"s6's newest enforce run ({run.run_id}) says completed but recorded an error. "
                       "Run ./lab.sh run s6 again")
        return report.EXIT_NOT_YET

    offset, known = _baseline(run)
    leaked = _new_dead_drop(run, known)
    sends = _sends(ev, run, offset)
    sessions = set(run.sessions)

    # One session must hold the pin's deny on the call itself. A deny on the result comes after the call ran.
    if not any(_guardian_deny(e, MISMATCH, sessions) for e in sends):
        if any(_guardian_deny(e, UNREGISTERED, sessions) for e in sends):
            report.not_yet(f"s6's newest enforce run denied {SEND} as {UNREGISTERED}. The tool registry in "
                           "policy/data.json doesn't hold it, so your pin rule never judged the call. Rebuild it from a "
                           f"clean run, which leaves out what your other s6 runs showed: {REPIN}")
            return report.EXIT_NOT_YET
        landed = f", and the dead drop gained {leaked} message(s)" if leaked else ""
        report.not_yet(f"s6's newest enforce run has no deny with {MISMATCH} on {SEND}{landed}. To fix it, {FIX}")
        return report.EXIT_NOT_YET

    # Only the run's own sessions count. FinBot's background onboarding mails the vendor a status note, and now and
    # then it sends that note just before the description changes, so the unchanged declaration rightly passes.
    through = [e for e in sends if e.get("decision") != "deny" and e.get("session_id") in sessions]
    if through:
        # A deny on one call proves nothing when another call of the same tool still ran.
        report.not_yet(f"s6's newest enforce run denied one {SEND} call but let {len(through)} more through. Make "
                       "the rule in policy/tool_pins.rego deny every call whose tool.version isn't pinned, or run "
                       "./lab.sh policy 6 solution, then run ./lab.sh run s6")
        return report.EXIT_NOT_YET
    if leaked:
        report.not_yet(f"s6's newest enforce run denied {SEND}, but the dead drop gained {leaked} message(s) during "
                       "the run. Open ./lab.sh viewer to see which step sent it, then run ./lab.sh run s6 again")
        return report.EXIT_NOT_YET

    report.done(f"enforce run {run.run_id} denied the changed {SEND} with {MISMATCH}, no {SEND} call went "
                "through, and the dead drop gained nothing")
    return report.EXIT_PASS
