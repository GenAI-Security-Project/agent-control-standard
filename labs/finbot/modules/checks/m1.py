"""Module 1's check, Wire it in (issue #589, LAB-16 Task 6). lab check 1 runs it.

Version 1.0.0. Owner: Rock Lambros. Standard library only, like evidence.py, which it reads every source through.

Module 1 passes on two runs of s1, judged as the newest of each mode. Each counts only when the driver wrote
result completed with no error and no replay miss, since any other run shows nothing about the wiring.

- The newest off run leaves no ACS record. Its audit window opens no session, no transcript changed while it ran, and
  its model input window holds at least one line, which shows FinBot reached the model through the gateway. "No
  transcript changed" compares the driver's transcripts_before and transcripts_after size maps, never file times.
- The newest enforce run reached the model, nothing in it was denied or modified, and FinBot made at least one tool
  call. One of its sessions holds the whole record on its own: a ServerHello that agreed to sign decisions with
  ML-DSA-65, requests signed with HMAC-SHA256, an answered steps/sessionStart, an allow for every function_call in the
  run's model input window, and a transcript acs-verify passes with the key document, the fingerprint lab init wrote
  to .env, and the audit chain. Each allow is an applied allow in the audit log for that session, that call_id and
  that tool, whose request the session's transcript answers with an allow for the same tool. Allows from any other
  session don't count, since acs-verify judged only this one (review C1, re-review N1).

A model input line the check can't read for calls, a call with no call_id, or one call_id under two tool names is
not yet rather than skipped, so no call can go uncounted (review I1, M2, re-review N1). A string input can't carry a
call, so it counts as none (re-review N4). Answers pair with requests by JSON-RPC id, not by line order.

Checks trust the files the lab wrote in state/, so a plain file planted there steers this check like any other.

Lab conventions: ML-DSA-65 response signing and the ServerHello field x_acs_lab_response_algorithm (issue #316), and
the key document and its fingerprint (issue #460).
"""
from __future__ import annotations

import json
from typing import Any

import report
from evidence import Evidence, EvidenceError, Run

SCENARIO = "s1"
ML_DSA_65 = "ML-DSA-65"
HMAC_SHA256 = "HMAC-SHA256"
RESPONSE_ALGORITHM = "x_acs_lab_response_algorithm"
HANDSHAKE = "handshake/hello"
SESSION_START = "steps/sessionStart"
TOOL_CALL_REQUEST = "steps/toolCallRequest"
GOVERNED = ("steps/toolCallRequest", "steps/toolCallResult")
APPLIED = "decision_applied"

RUN_OFF = "Run ./lab.sh mode off, then ./lab.sh run s1"
RUN_ON = "Run ./lab.sh mode enforce, then ./lab.sh run s1"
RUN_AGAIN = "Run ./lab.sh run s1 again"


class _NotYet(Exception):
    """One NOT YET line and its exit code: 1 for a step still to do, 2 for a lab that can't judge it."""

    def __init__(self, message: str, code: int = report.EXIT_NOT_YET) -> None:
        super().__init__(message)
        self.code = code


def check(ev: Evidence) -> int:
    try:
        _judge_off_run(ev)
        run, session_id, fingerprint = _judge_on_run(ev)
    except _NotYet as e:
        report.not_yet(str(e))
        return e.code
    report.done(f"module 1. With ACS off, FinBot reached the model through the gateway and left no ACS record. "
                f"Enforce run {run.run_id} governed every call, and acs-verify passed session {session_id} "
                f"under {ML_DSA_65} with the Guardian's key {fingerprint}")
    return report.EXIT_PASS


def _judge_completed(run: Run, command: str) -> None:
    """The driver writes completed only when the run finished clean (guide-phase rule 1, re-review N2)."""
    where = f"{run.mode} run {run.run_id}"
    if run.result != "completed":
        raise _NotYet(f"{where} ended {run.result or 'with no result'}, not completed. {command}")
    error = run.record.get("error")
    if error is not None:
        raise _NotYet(f"{where} says completed, but the driver noted: {error}. {command}")
    misses = run.record.get("replay_misses", 0)
    if not isinstance(misses, int) or isinstance(misses, bool):
        raise EvidenceError(f"run {run.run_id} has replay_misses {misses!r}, which isn't a count")
    if misses:
        raise _NotYet(f"{where} had {misses} replay miss{'es' if misses > 1 else ''}. {command}")


# ---------------------------------------------------------------------------------------------------------------------
# the off run
# ---------------------------------------------------------------------------------------------------------------------

def _judge_off_run(ev: Evidence) -> None:
    runs = ev.runs(SCENARIO, "off")
    if not runs:
        raise _NotYet(f"module 1 starts with an off run of {SCENARIO}, and there isn't one yet. {RUN_OFF}")
    run = runs[0]
    _judge_completed(run, RUN_OFF)
    if run.sessions or any(event.get("session_id") for event in ev.audit(run)):
        raise _NotYet(f"off run {run.run_id} opened an ACS session, so the gateway wasn't off. {RUN_OFF}")
    changed = _transcripts_changed(run)
    if changed:
        raise _NotYet(f"the transcript {changed} changed during off run {run.run_id}, so ACS was still governing "
                      f"FinBot. {RUN_OFF}")
    if not ev.model_inputs(run):
        raise _NotYet(f"off run {run.run_id} has no model input line, so FinBot never reached the model through the "
                      f"gateway. {RUN_OFF} again, and if this repeats, run ./lab.sh logs acs-gateway")


def _sizes(run: Run, key: str) -> dict[str, int]:
    """One of the driver's transcript size maps, file name to size in bytes."""
    found = run.finbot.get("evidence", {}).get(key) if isinstance(run.finbot.get("evidence"), dict) else None
    if not isinstance(found, dict):
        raise EvidenceError(f"run {run.run_id} has no {key} map of transcript sizes, which the driver writes on "
                            f"every completed run")
    for name, size in found.items():
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise EvidenceError(f"run {run.run_id} gives {name} the size {size!r} in {key}, which isn't a count "
                                f"of bytes")
    return found


def _transcripts_changed(run: Run) -> str | None:
    """The name of a transcript the run added, grew, cut or removed, from the driver's two size maps, or None."""
    before, after = _sizes(run, "transcripts_before"), _sizes(run, "transcripts_after")
    return next((name for name in sorted(before.keys() | after.keys()) if before.get(name) != after.get(name)), None)


# ---------------------------------------------------------------------------------------------------------------------
# the enforce run
# ---------------------------------------------------------------------------------------------------------------------

def _judge_on_run(ev: Evidence) -> tuple[Run, str, str]:
    runs = ev.runs(SCENARIO, "enforce")
    if not runs:
        raise _NotYet(f"the off run is in. Module 1 needs an enforce run of {SCENARIO} next. {RUN_ON}")
    run = runs[0]
    _judge_completed(run, RUN_AGAIN)
    if not run.sessions:
        raise _NotYet(f"enforce run {run.run_id} opened no ACS session. {RUN_ON}")
    bodies = ev.model_inputs(run)
    if not bodies:
        raise _NotYet(f"enforce run {run.run_id} has no model input line, so FinBot never reached the model through "
                      f"the gateway. {RUN_AGAIN}, and if this repeats, run ./lab.sh logs acs-gateway")
    audit = ev.audit(run)
    transcripts = {session_id: ev.transcript(session_id) for session_id in run.sessions}
    # Before the call count: the gateway removes a denied call, so a run whose only call was denied shows no call,
    # and the line should name the deny (re-review N3).
    _judge_decisions(run, audit, transcripts)
    calls = _function_calls(run, bodies)
    if not calls:
        raise _NotYet(f"FinBot made no tool call in enforce run {run.run_id}, so nothing was governed. {RUN_AGAIN}")
    # One session with the whole record passes the run. A session the gateway retried leaves an unopened one behind.
    problems: list[_NotYet] = []
    for session_id, lines in transcripts.items():
        try:
            return run, session_id, _judge_session(ev, run, session_id, lines, calls, audit)
        except _NotYet as e:
            problems.append(e)
    raise problems[0]


def _pairs(lines: list[dict[str, Any]]) -> list[tuple[dict[str, Any], Any]]:
    """(request, answer envelope) for each request line, in send order. The answer is the first response line whose
    JSON-RPC id matches the request's, or None when there is none, such as a gap line the gateway wrote."""
    answers: dict[str, dict[str, Any]] = {}
    for line in lines:
        envelope = line.get("envelope")
        if line.get("dir") == "resp" and isinstance(envelope, dict) and isinstance(envelope.get("id"), (str, int)):
            answers.setdefault(json.dumps(envelope["id"]), envelope)
    pairs = []
    for line in lines:
        envelope = line.get("envelope")
        if line.get("dir") != "req" or not isinstance(envelope, dict):
            continue
        key = envelope.get("id")
        pairs.append((envelope, answers.get(json.dumps(key)) if isinstance(key, (str, int)) else None))
    return pairs


def _result(envelope: Any) -> dict[str, Any]:
    result = envelope.get("result") if isinstance(envelope, dict) else None
    return result if isinstance(result, dict) else {}


def _params(envelope: dict[str, Any]) -> dict[str, Any]:
    params = envelope.get("params")
    return params if isinstance(params, dict) else {}


def _tool_name(request: dict[str, Any]) -> str:
    payload = _params(request).get("payload")
    tool = payload.get("tool") if isinstance(payload, dict) else None
    return str(tool.get("name")) if isinstance(tool, dict) else "a tool"


def _judge_decisions(run: Run, audit: list[dict[str, Any]],
                     transcripts: dict[str, list[dict[str, Any]]]) -> None:
    """Module 1 shows the wiring on calls the starter policies allow, so any other decision is not yet."""
    found = [(str(e.get("decision")), str(e.get("tool"))) for e in audit
             if e.get("acs_audit_event") == APPLIED and e.get("method") in GOVERNED and e.get("decision") != "allow"]
    for lines in transcripts.values():
        for request, answer in _pairs(lines):
            decision = _result(answer).get("decision")
            if request.get("method") in GOVERNED and decision not in (None, "allow"):
                found.append((str(decision), _tool_name(request)))
    if found:
        decision, tool = found[0]
        raise _NotYet(f"enforce run {run.run_id} has a {decision} on {tool}, and module 1 expects every call allowed. "
                      f"{RUN_AGAIN}, and if the {decision} repeats, run ./lab.sh logs acs-guardian to see why")


def _function_calls(run: Run, bodies: list[dict[str, Any]]) -> dict[str, str]:
    """call_id to function name for every function_call FinBot sent the model. The model input resends each turn's
    calls, so one call appears in many lines and counts once. A line that can't be read for calls is not yet, since
    any call in it would otherwise need no allow. A string input holds no call items, so it adds none."""
    calls: dict[str, str] = {}
    for body in bodies:
        if set(body) == {"raw"}:
            raise _NotYet(f"a model input line in enforce run {run.run_id} isn't a JSON object, so its calls can't be "
                          f"read. {RUN_AGAIN}", report.EXIT_BROKEN)
        items = body.get("input")
        if isinstance(items, str):
            continue
        if not isinstance(items, list):
            raise _NotYet(f"a model input line in enforce run {run.run_id} has no list or text of input items, so its "
                          f"calls can't be read. {RUN_AGAIN}")
        for item in items:
            if not isinstance(item, dict) or item.get("type") != "function_call":
                continue
            call_id, name = item.get("call_id"), str(item.get("name"))
            if not isinstance(call_id, str) or not call_id:
                raise _NotYet(f"FinBot's call to {name} in enforce run {run.run_id} has no call_id, so no allow can "
                              f"be matched to it. {RUN_AGAIN}")
            if calls.setdefault(call_id, name) != name:
                raise _NotYet(f"enforce run {run.run_id} sent call_id {call_id} for both {calls[call_id]} and {name}, "
                              f"so one allow could cover two calls. {RUN_AGAIN}")
    return calls


def _judge_calls(run: Run, session_id: str, pairs: list[tuple[dict[str, Any], Any]], calls: dict[str, str],
                 audit: list[dict[str, Any]]) -> None:
    """Every call the model saw had an allow the gateway applied in this session, for this call_id and tool, on a
    request this session's transcript answers allow for the same tool."""
    applied: dict[tuple[str, str], set[str]] = {}
    for event in audit:
        call_id, request_id, tool = event.get("call_id"), event.get("request_id"), event.get("tool")
        if (event.get("acs_audit_event") == APPLIED and event.get("session_id") == session_id
                and event.get("method") == TOOL_CALL_REQUEST and event.get("decision") == "allow"
                and isinstance(call_id, str) and call_id and isinstance(request_id, str) and request_id
                and isinstance(tool, str)):
            applied.setdefault((call_id, tool), set()).add(request_id)
    answered: dict[str, str] = {}
    for request, answer in pairs:
        request_id = _params(request).get("request_id")
        result = _result(answer)
        if (request.get("method") == TOOL_CALL_REQUEST and isinstance(request_id, str)
                and result.get("request_id") == request_id and result.get("decision") == "allow"):
            answered[request_id] = _tool_name(request)
    for call_id, name in calls.items():
        if not any(answered.get(request_id) == name for request_id in applied.get((call_id, name), set())):
            raise _NotYet(f"FinBot's call to {name} ({call_id}) in enforce run {run.run_id} has no allow for that tool "
                          f"in session {session_id}, the session that must hold the signed record. {RUN_AGAIN}")


def _judge_session(ev: Evidence, run: Run, session_id: str, lines: list[dict[str, Any]], calls: dict[str, str],
                   audit: list[dict[str, Any]]) -> str:
    """The fingerprint acs-verify pinned when the session holds the whole record, or _NotYet saying what's missing."""
    where = f"session {session_id} of enforce run {run.run_id}"
    if not lines:
        raise _NotYet(f"{where} wrote no transcript. {RUN_AGAIN}")
    pairs = _pairs(lines)
    for request, _answer in pairs:
        signature = _params(request).get("signature")
        algorithm = signature.get("algorithm") if isinstance(signature, dict) else None
        if algorithm != HMAC_SHA256:
            raise _NotYet(f"{where} sent a {request.get('method')} request signed with {algorithm or 'nothing'}, "
                          f"not {HMAC_SHA256}. {RUN_AGAIN}")
    hellos = [_result(answer) for request, answer in pairs if request.get("method") == HANDSHAKE]
    if not hellos:
        raise _NotYet(f"{where} has no handshake. {RUN_AGAIN}")
    agreed = hellos[0].get(RESPONSE_ALGORITHM)
    if agreed != ML_DSA_65:
        raise _NotYet(f"in {where} the Guardian's ServerHello named {agreed or 'no algorithm'} for its decisions, "
                      f"not {ML_DSA_65}. Run ./lab.sh sign mldsa, then ./lab.sh run s1")
    if not any(request.get("method") == SESSION_START and _result(answer) for request, answer in pairs):
        raise _NotYet(f"{where} has no answered {SESSION_START}, so the session never opened. {RUN_AGAIN}")
    _judge_calls(run, session_id, pairs, calls, audit)
    result = ev.verify(session_id)
    if result.outcome == "not_yet":
        raise _NotYet(result.detail)
    if result.outcome == "error":
        raise _NotYet(f"acs-verify couldn't judge {where}: {result.detail}", report.EXIT_BROKEN)
    if result.outcome != "verified":
        raise _NotYet(f"acs-verify failed on {where}: {result.detail}. {RUN_AGAIN} for a fresh record")
    verdict = result.report or {}
    if verdict.get("response_algorithm") != ML_DSA_65 or verdict.get("chain_checked") is not True:
        raise _NotYet(f"acs-verify checked {where} without the key document and the audit chain. {RUN_AGAIN}",
                      report.EXIT_BROKEN)
    return str(ev.fingerprint())
