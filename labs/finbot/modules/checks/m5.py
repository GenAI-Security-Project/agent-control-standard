"""Module 5's check, Clean it (issue #589, LAB-16 Task 10, BUILD_PLAN Appendix D).

Version 1.1.0. Owner: Rock Lambros.

Pass: the newest enforce run of s5 finished, and one of its sessions holds an applied modify with
sensitive_field_redacted on the get_vendor_details result. That result, as the gateway forwarded it, reached the
model, and it isn't the neutral deny line. No model input line in the run's window holds the scenario's bank account
number, raw or with separators between its digits. FinBot's chat reply is present and isn't the neutral deny line.

What the model read decides the lesson, so the number's absence is judged from the model input log, never from the
Guardian's answer. The number comes from scenarios/s5.json in the bundle, not from state/, and no line this check
prints holds it. The check also prints one info line about the newest off run of s5, so the attendee sees the
before and after side by side. Checks read state/, so anything that can write state/ can steer this one.
"""
from __future__ import annotations

import json
import re
from typing import Any

import report
from evidence import Evidence, EvidenceError, Run

SCENARIO = "s5"
TOOL = "get_vendor_details"
RESULT = "steps/toolCallResult"
REASON = "sensitive_field_redacted"
SENSITIVE_KEY = "bank_account_number"
# The gateway's apply.NEUTRAL_LINE. Checks load with the standard library only, so the sentence is copied here, and
# test_neutral_line_matches_the_gateway holds the two together.
NEUTRAL_LINE = "I couldn't complete that action."
# The gateway's apply.DEFAULT_REDACTION. base.rego sends redaction paths with no replacement, so every redacted value
# reads this way.
REDACTION_MARK = "[REDACTED]"
# A secret shorter than this would match ordinary numbers in the record and turn the check red for no reason.
MIN_DIGITS = 6
RUN_S5 = "./lab.sh run s5"
FIX = f"finish the rule in policy/redact_bank.rego, or run ./lab.sh policy 5 solution, then run {RUN_S5}"


def _secrets(ev: Evidence) -> list[str]:
    """The bank account numbers s5 registers: facts.secret and each setup body's bank_account_number."""
    path = ev.root / "scenarios" / f"{SCENARIO}.json"
    try:
        scenario = json.loads(ev.read_bounded(path))
    except (OSError, ValueError) as e:
        raise EvidenceError(f"scenarios/{SCENARIO}.json can't be read ({type(e).__name__})") from None
    facts = scenario.get("facts") if isinstance(scenario, dict) else None
    found = [facts.get("secret")] if isinstance(facts, dict) else []
    for step in scenario.get("setup", []) if isinstance(scenario, dict) else []:
        body = step.get("body") if isinstance(step, dict) else None
        if isinstance(body, dict) and SENSITIVE_KEY in body:
            found.append(body[SENSITIVE_KEY])
    secrets = sorted({s for s in found if isinstance(s, str)})
    if not secrets or any(len(re.sub(r"\D", "", s)) < MIN_DIGITS for s in secrets):
        raise EvidenceError(f"scenarios/{SCENARIO}.json names no bank account number of at least {MIN_DIGITS} digits")
    return secrets


def _patterns(secrets: list[str]) -> list[re.Pattern[str]]:
    """One pattern per number: its digits in order, with at most one space, dot, dash, underscore or slash between
    two of them. The digit guards keep the run from matching inside a longer number, such as an id followed by the
    TIN, whose digits are the account number's without its leading zeros."""
    patterns = []
    for secret in secrets:
        digits = re.sub(r"\D", "", secret)
        patterns.append(re.compile(r"(?<!\d)" + r"[\s._/-]?".join(digits) + r"(?!\d)"))
    return patterns


def _texts(value: Any) -> list[str]:
    """Every string, key and number in a model input body, so the number is found wherever the gateway put it."""
    out: list[str] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            out.extend(str(k) for k in item)
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, (int, float)) and not isinstance(item, bool):
            out.append(str(item))
    return out


def _holds(body: Any, secrets: list[str], patterns: list[re.Pattern[str]]) -> bool:
    # The raw spelling counts anywhere, even inside a longer run of digits. The patterns add the spaced spellings.
    return any(s in text or p.search(text) for text in _texts(body) for s in secrets for p in patterns)


def _lines_with_number(ev: Evidence, run: Run, secrets: list[str]) -> tuple[int, int]:
    bodies = ev.model_inputs(run)
    patterns = _patterns(secrets)
    return sum(1 for body in bodies if _holds(body, secrets, patterns)), len(bodies)


def _redactions(ev: Evidence, run: Run) -> list[dict[str, Any]]:
    """The applied modifies with sensitive_field_redacted on the get_vendor_details result, inside the run's window,
    in one of its sessions and under the epoch its steps ran under. A modify that withheld the whole output carries
    a cause, and FinBot got the neutral deny line from it, so it doesn't count."""
    steps_epoch = run.epoch[0] if run.epoch else None
    found = []
    for event in ev.audit(run):
        codes = event.get("reason_codes")
        call_id = event.get("call_id")
        if (event.get("acs_audit_event") == "decision_applied" and event.get("method") == RESULT
                and event.get("tool") == TOOL and event.get("decision") == "modify"
                and event.get("guardian_decision") == "modify" and isinstance(codes, list) and REASON in codes
                and event.get("cause") is None and event.get("session_id") in run.sessions
                and event.get("epoch") == steps_epoch and isinstance(call_id, str) and call_id):
            found.append(event)
    return found


def _reached_model(ev: Evidence, run: Run, call_ids: set[str]) -> bool:
    """Whether a model input line carries a redacted call's output with the gateway's redaction mark in it. Without
    one, the number's absence says nothing about what the model read. The neutral deny line holds no mark."""
    for body in ev.model_inputs(run):
        items = body.get("input")
        for item in items if isinstance(items, list) else []:
            if (isinstance(item, dict) and item.get("type") == "function_call_output"
                    and item.get("call_id") in call_ids
                    and REDACTION_MARK in str(item.get("output", ""))):
                return True
    return False


def _reply(run: Run) -> str:
    evidence = run.finbot.get("evidence")
    reply = evidence.get("reply") if isinstance(evidence, dict) else None
    if not isinstance(reply, str):
        # The driver marks a run completed only after FinBot answered the reply probe.
        raise EvidenceError(f"run {run.run_id} holds no chat reply from FinBot. Run {RUN_S5} again")
    return reply


def _off_run_line(ev: Evidence, secrets: list[str]) -> None:
    off = ev.runs(SCENARIO, "off")
    if not off:
        return
    run = off[0]
    holding, total = _lines_with_number(ev, run, secrets)
    if holding:
        report.info(f"Off run {run.run_id}: the vendor's bank account number reached the model in {holding} model "
                    f"input line{'s' if holding != 1 else ''} of {total}.")
    else:
        report.info(f"Off run {run.run_id}: no model input line held the vendor's bank account number "
                    f"({total} lines, result {run.result or 'unknown'}).")


def check(ev: Evidence) -> int:
    secrets = _secrets(ev)
    _off_run_line(ev, secrets)
    runs = ev.runs(SCENARIO, "enforce")
    if not runs:
        report.not_yet(f"there's no enforce run of s5 yet. Run ./lab.sh mode enforce, then {RUN_S5}")
        return report.EXIT_NOT_YET
    run = runs[0]
    # The driver clears error whenever it stores completed, so a record holding both wasn't written that way.
    if run.result != "completed" or run.record.get("error") is not None:
        ended = run.result or "with no result"
        if run.result == "completed":
            ended = "completed but recorded an error"
        report.not_yet(f"the newest enforce run of s5 ({run.run_id}) ended {ended}, so its evidence may be partial. "
                       f"Run {RUN_S5} again")
        return report.EXIT_NOT_YET

    redactions = _redactions(ev, run)
    if not redactions:
        report.not_yet(f"enforce run {run.run_id} has no modify with {REASON} on the {TOOL} result, so the model "
                       f"read the bank account number. To fix it, {FIX}")
        return report.EXIT_NOT_YET
    if not _reached_model(ev, run, {e["call_id"] for e in redactions}):
        report.not_yet(f"enforce run {run.run_id} redacted the {TOOL} result, but no model input line carries it, "
                       f"so the run can't show what the model read. Run {RUN_S5} again, and if this repeats, run "
                       "./lab.sh logs acs-gateway")
        return report.EXIT_NOT_YET
    holding, _ = _lines_with_number(ev, run, secrets)
    if holding:
        report.not_yet(f"the bank account number still reached the model in {holding} model input "
                       f"line{'s' if holding != 1 else ''} of enforce run {run.run_id}. Make the rule redact every "
                       f"{SENSITIVE_KEY} in the output: {FIX}")
        return report.EXIT_NOT_YET

    reply = _reply(run).strip()
    if not reply or reply == NEUTRAL_LINE:
        shown = "empty" if not reply else "the neutral deny line"
        report.not_yet(f"FinBot's reply in enforce run {run.run_id} is {shown}, so the task didn't finish with the "
                       f"masked record. Redact only {SENSITIVE_KEY}, not the whole output: {FIX}")
        return report.EXIT_NOT_YET
    if _holds(reply, secrets, _patterns(secrets)):
        report.not_yet(f"FinBot's reply in enforce run {run.run_id} holds the bank account number. {FIX[0].upper()}"
                       f"{FIX[1:]}")
        return report.EXIT_NOT_YET

    report.done(f"enforce run {run.run_id} redacted the {TOOL} result ({REASON}), no model input line held the bank "
                "account number, and FinBot still answered the vendor")
    return report.EXIT_PASS
