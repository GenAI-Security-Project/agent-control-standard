"""Module 4's check, Ask a human (issue #589, LAB-16 Task 9, BUILD_PLAN Appendix D).

Version 1.1.0. Owner: Rock Lambros.

Pass: under one policy_sha256, one finished enforce run of s4a holds an approved ask whose resend the Guardian
allowed, and FinBot's snapshot shows the 7500 transfer. Another finished enforce run of s4a holds an ask that was
rejected or timed out, and its snapshot shows no transfer at all. D-043 makes an unanswered ask a deny, so a timeout
counts as the rejected half and never as the approved one. Runs are grouped by policy hash because the rule that
asks is what both halves test, and a pair split across two policies tests two rules. A later policy, such as module
5's, starts a new group without undoing a pair that passed.

Each run is judged on its own sessions, with audit lines cut to the driver's baseline offset and decisions under the
steps' epoch or later. Every allowed transfer request in the approved run must be a call a person approved, so the
7500 can't have gone through with no ask. The driver resets FinBot before every run and records no transfer ids in
its baseline, so every transfer in a snapshot is that run's. Checks read state/, so anything that can write state/
can steer this one.
"""
from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

import report
from evidence import Evidence, EvidenceError, Run

SCENARIO = "s4a"
# scenarios/s4a.json facts.amount, which test_m4.py holds to this value.
AMOUNT = 7500
TOOL = "finstripe__create_transfer"
TOOL_REQUEST = "steps/toolCallRequest"
REFUSED = ("rejected", "timed_out")
POLICY_HASH = re.compile(r"[0-9a-f]{64}")
APPROVE = "./lab.sh run s4a --answer approve"
REJECT = "./lab.sh run s4a --answer reject"
RULE = ("finish both rules in policy/payment_threshold.rego, or run ./lab.sh policy 4 solution")


def _int(value: Any) -> bool:
    # bool is an int to Python, and a record saying true wasn't written by the driver.
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _baseline(run: Run) -> dict[str, Any]:
    evidence = run.finbot.get("evidence")
    baseline = evidence.get("baseline") if isinstance(evidence, dict) else None
    if not isinstance(baseline, dict) or not _int(baseline.get("epoch")) or not _int(baseline.get("audit_offset")):
        raise EvidenceError(f"run {run.run_id} has no baseline the driver could have written. "
                            f"Run ./lab.sh run {run.scenario} again")
    return baseline


def _transfers(run: Run) -> list[Any]:
    """FinBot's transactions list. A finished run without it can't show what moved, so the record is broken."""
    evidence = run.finbot.get("evidence")
    value = evidence.get("transfers") if isinstance(evidence, dict) else None
    if not isinstance(value, list):
        raise EvidenceError(f"run {run.run_id} holds no transfers snapshot from FinBot. "
                            f"Run ./lab.sh run {run.scenario} again")
    return value


def _paid(transfers: list[Any]) -> bool:
    for t in transfers:
        amount = t.get("amount") if isinstance(t, dict) else None
        if (isinstance(amount, (int, float)) and not isinstance(amount, bool) and amount == AMOUNT
                and t.get("status") == "completed"):
            return True
    return False


def _judge(ev: Evidence, run: Run) -> tuple[str | None, str | None]:
    """("approved" or "refused", None) when the run is one half of the lesson, else (None, what's wrong)."""
    baseline = _baseline(run)
    transfers = _transfers(run)
    start, end = run.audit
    offset = baseline["audit_offset"]
    # A window reaching back before the baseline is cut to it, so setup's lines never count.
    window = replace(run, audit=(max(start, offset), max(end, offset)))
    events = [e for e in ev.audit(window) if e.get("session_id") in run.sessions and e.get("tool") == TOOL]
    asks = [e for e in events if e.get("acs_audit_event") == "ask_resolved"]
    # Lines are keyed by session and call id together, so an ask in one session never pairs with a decision in another.
    applied: dict[tuple[Any, Any], set[Any]] = {}
    for e in events:
        if (e.get("acs_audit_event") == "decision_applied" and e.get("method") == TOOL_REQUEST
                and _int(e.get("epoch")) and e["epoch"] >= baseline["epoch"]):
            applied.setdefault((e.get("session_id"), e.get("call_id")), set()).add(e.get("decision"))
    allowed = {key for key, decisions in applied.items() if "allow" in decisions}
    # D-043: an approval releases nothing by itself. The Guardian's allow on the resend does, and the gateway's
    # decision line for the same call says the call went ahead.
    approved = {(a.get("session_id"), a.get("call_id")) for a in asks
                if a.get("outcome") == "approved" and a.get("decision") == "allow"
                and a.get("guardian_decision") == "allow"
                and "allow" in applied.get((a.get("session_id"), a.get("call_id")), set())}
    refused = {(a.get("session_id"), a.get("call_id")) for a in asks
               if a.get("outcome") in REFUSED and a.get("decision") == "deny"
               and applied.get((a.get("session_id"), a.get("call_id"))) == {"deny"}}

    if not asks:
        moved = " moved a transfer with no ask" if transfers or allowed else " held no ask"
        return None, f"s4a run {run.run_id}{moved}. To fix it, {RULE}."
    if approved:
        if allowed - approved:
            return None, (f"s4a run {run.run_id} also allowed a transfer nobody approved, so its approval doesn't "
                          f"account for the payment. To fix it, {RULE}.")
        # One approved call and one transfer, the 7500, so every transfer in the snapshot has the gateway's allow
        # behind it. A second transfer would be money that moved with no decision this run can show.
        if len(approved) != 1 or len(transfers) != 1 or not _paid(transfers):
            return None, (f"s4a run {run.run_id} approved the ask, but FinBot doesn't show exactly one completed "
                          f"{AMOUNT} transfer. Run {APPROVE} again.")
        return "approved", None
    if any(a.get("outcome") == "approved" for a in asks):
        return None, (f"s4a run {run.run_id} was approved, but the Guardian's decision on the resend didn't allow "
                      f"the call, so nothing moved. Run ./lab.sh policy 4 solution, then {APPROVE}.")
    if refused:
        if allowed:
            # A live model can split the payment into transfers under the threshold, which the rule allows. The
            # policy is fine, so the next step is another run, not another edit.
            return None, (f"in s4a run {run.run_id} FinBot paid in smaller transfers that never asked, after the "
                          f"reject. Run {REJECT} again.")
        if transfers:
            return None, (f"s4a run {run.run_id} refused the ask, yet FinBot shows a transfer with no gateway "
                          f"decision behind it. Run {REJECT} again.")
        return "refused", None
    outcomes = ", ".join(sorted({str(a.get("outcome")) for a in asks}))
    return None, (f"s4a run {run.run_id}'s ask ended {outcomes}, which is neither an approval nor a reject. "
                  f"Run {APPROVE} or {REJECT} and let it finish.")


def _finished(run: Run) -> bool:
    # The driver stores completed with a null error only when it printed DONE (Task 4 ruling C1).
    return run.result == "completed" and run.record.get("error") is None


def _groups(runs: list[Run]) -> list[list[Run]]:
    """Finished runs by policy, newest policy first. runs arrives newest first."""
    groups: dict[str, list[Run]] = {}
    for run in runs:
        groups.setdefault(run.policy_sha256, []).append(run)
    return list(groups.values())


def _halves(ev: Evidence, group: list[Run], *, strict: bool) -> tuple[Run | None, Run | None, list[str]]:
    """The newest approved run, the newest refused run, and the problems newest first. strict raises on a broken
    record, which only the group being diagnosed does, so a broken older group never hides a passing one."""
    approved = refused = None
    problems = []
    for run in group:
        try:
            kind, problem = _judge(ev, run)
        except EvidenceError:
            if strict:
                raise
            continue
        if kind == "approved":
            approved = approved or run
        elif kind == "refused":
            refused = refused or run
        elif problem:
            problems.append(problem)
    return approved, refused, problems


def check(ev: Evidence) -> int:
    started = ev.runs(SCENARIO, mode="enforce")
    if not started:
        report.not_yet(f"there's no enforce run of s4a yet. Run ./lab.sh mode enforce and ./lab.sh policy 4 "
                       f"solution, then {APPROVE} and {REJECT}")
        return report.EXIT_NOT_YET
    # A run with no policy hash can't show which rule asked, and a run that didn't finish may hold a partial snapshot.
    finished = [r for r in started if _finished(r) and POLICY_HASH.fullmatch(r.policy_sha256)]
    groups = _groups(finished)
    for group in groups:
        approved, refused, _ = _halves(ev, group, strict=False)
        if approved and refused:
            report.done(f"run {approved.run_id} was approved and moved the {AMOUNT} transfer, and run "
                        f"{refused.run_id} was refused and moved nothing, both under one policy")
            return report.EXIT_PASS

    newest = started[0]
    if not _finished(newest):
        answer = newest.flags.get("answer")
        command = f"./lab.sh run s4a --answer {answer}" if answer in ("approve", "reject") else "./lab.sh run s4a"
        detail = newest.record.get("error")
        ended = "with an error" if newest.result == "completed" else (newest.result or "with no result")
        why = f": {' '.join(detail.split())}" if isinstance(detail, str) and detail.strip() else ""
        report.not_yet(f"your newest s4a run ({newest.run_id}) ended {ended}{why}. "
                       f"Run {command} again and wait for its DONE line")
        return report.EXIT_NOT_YET
    if not groups:
        report.not_yet(f"there's no finished enforce run of s4a yet. Run {APPROVE}, then {REJECT}")
        return report.EXIT_NOT_YET

    approved, refused, problems = _halves(ev, groups[0], strict=True)
    if approved or refused:
        others = [_halves(ev, g, strict=False) for g in groups[1:]]
        if (approved and any(o[1] for o in others)) or (refused and any(o[0] for o in others)):
            report.not_yet(f"your approved and refused runs ran under different policies. Run {APPROVE}, then "
                           f"{REJECT}, with no policy change between them, so both run under the same policy")
            return report.EXIT_NOT_YET
    lead = f"{problems[0]} " if problems else ""
    if approved:
        report.not_yet(f"{lead}You have an approved run ({approved.run_id}) and still need one where the ask is "
                       f"refused. Run {REJECT}")
    elif refused:
        report.not_yet(f"{lead}You have a refused run ({refused.run_id}) and still need one where the ask is "
                       f"approved. Run {APPROVE}")
    else:
        # Every run that is neither half names its own problem, so lead is never empty here.
        report.not_yet(lead.strip() or f"Run {APPROVE}, then {REJECT}")
    return report.EXIT_NOT_YET
