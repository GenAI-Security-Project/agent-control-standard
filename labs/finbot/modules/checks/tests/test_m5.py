"""Module 5's check, Clean it (issue #589, LAB-16 Task 10).

Runs in the adapters environment with the pqc extra, like every module check test:

    uv run --project adapters --locked --extra pqc --group test python -m pytest \
        labs/finbot/modules/checks/tests/test_m5.py -v

Each run is built the way the gateway writes it: decision lines in the audit window, and the request bodies it
forwarded to the model in the model input window, each one resending the turn's calls and their outputs. The bank
number comes from the shipped scenarios/s5.json, copied into the test bundle, so the check reads the same file it
reads in the lab. No assertion here lets the number reach the printed line.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Any

import pytest

from fixtures import BUNDLE, SESSION_A, SESSION_B, LabState

import lab_modules  # noqa: E402  (the CLI's dispatcher, for the exit code a broken record gets)
import m5  # noqa: E402  (fixtures put the checks directory on sys.path)
from acs_gateway.apply import DEFAULT_REDACTION, NEUTRAL_LINE
from evidence import Evidence, EvidenceError

SCENARIO_FILE = BUNDLE / "scenarios" / "s5.json"
SECRET = json.loads(SCENARIO_FILE.read_text(encoding="utf-8"))["facts"]["secret"]
TOOL = "get_vendor_details"
CALL = "call_vendor_1"
REPLY = "Northwind Supplies is on file with First Example Bank. The account number is masked."
RECORD = {"company_name": "Northwind Supplies", "tin": "12-3456789", "bank_name": "First Example Bank",
          "bank_routing_number": "123456780", "bank_account_number": SECRET}
REDACTED = {**RECORD, "bank_account_number": "[REDACTED]"}


@pytest.fixture
def lab(tmp_path) -> LabState:
    state = LabState(tmp_path / "bundle")
    (state.root / "scenarios").mkdir()
    shutil.copy(SCENARIO_FILE, state.root / "scenarios" / "s5.json")
    return state


def _run(lab: LabState, minute: int, *, mode: str = "enforce", result_decision: str = "modify",
         reason_codes: list[str] | None = None, cause: str | None = None, method: str = "steps/toolCallResult",
         tool: str = TOOL, session: str = SESSION_A, run_sessions: list[str] | None = None, decision_epoch: int = 1,
         output: Any = REDACTED, fed_back: bool = True, extra_inputs: tuple[Any, ...] = (),
         reply: str | None = REPLY, result: str = "completed") -> str:
    """One driver run of s5: the call and its result gated in the audit window, then each request body the gateway
    forwarded to the model, then the record. output is what the model read for the call, as a dict the gateway
    serialized or as the exact string it forwarded. Off runs gate nothing and open no session."""
    a0, m0 = lab.size(lab.audit_file), lab.size(lab.model_input_file)
    if mode != "off":
        event = "decision_applied" if mode == "enforce" else "shadow_decision"
        lab.audit("session_opened", session_id=session, epoch=decision_epoch)
        lab.audit(event, session_id=session, epoch=decision_epoch, method="steps/toolCallRequest", tool=TOOL,
                  call_id=CALL, request_id=None, decision="allow", guardian_decision="allow", reason_codes=[],
                  cause=None, failure_class=None)
        codes = ["sensitive_field_redacted"] if reason_codes is None and result_decision == "modify" else []
        lab.audit(event, session_id=session, epoch=decision_epoch, method=method, tool=tool, call_id=CALL,
                  request_id=None, decision=result_decision, guardian_decision=result_decision,
                  reason_codes=codes if reason_codes is None else reason_codes, cause=cause, failure_class=None)
    turn: list[dict[str, Any]] = [{"type": "message", "role": "user",
                                   "content": "Please show me the details FinBot holds for our vendor account."}]
    lab.model_input({"model": "gpt-5-nano", "input": list(turn)})
    if fed_back:
        turn += [{"type": "function_call", "name": TOOL, "call_id": CALL, "arguments": "{}"},
                 {"type": "function_call_output", "call_id": CALL,
                  "output": output if isinstance(output, str) else json.dumps(output)}]
        lab.model_input({"model": "gpt-5-nano", "input": list(turn)})
    for body in extra_inputs:
        lab.model_input(body)
    run_id = f"20261125T10{minute:02d}00Z-s5"
    evidence: dict[str, Any] = {"baseline": {"dead_drop_ids": [], "inbox_ids": [], "epoch": 1, "audit_offset": a0}}
    if reply is not None:
        evidence["reply"] = reply
    sessions = run_sessions if run_sessions is not None else ([] if mode == "off" else [session])
    lab.run_record(run_id, scenario="s5", mode=mode, started=f"2026-11-25T10:{minute:02d}:00Z",
                   audit=(a0, lab.size(lab.audit_file)), model_inputs=(m0, lab.size(lab.model_input_file)),
                   sessions=sessions, result=result, epoch=[1, 2],
                   finbot={"namespace": "ns_user_test", "vendor": {}, "evidence": evidence})
    return run_id


def _check(lab: LabState, capsys) -> tuple[int, list[str]]:
    code = m5.check(Evidence(lab.root))
    out = capsys.readouterr().out
    # The check names the number's absence or presence, never the number.
    assert SECRET not in out and SECRET[-6:] not in out, out
    lines = out.splitlines()
    assert lines and lines[-1].startswith(("DONE:", "NOT YET:")), out
    assert all(not line.startswith(("DONE:", "NOT YET:")) for line in lines[:-1]), out
    return code, lines


# ---------------------------------------------------------------------------------------------------------------------
# the four the plan names
# ---------------------------------------------------------------------------------------------------------------------

def test_redacted_and_completed(lab, capsys):
    run_id = _run(lab, 10)
    code, lines = _check(lab, capsys)
    assert code == 0
    assert lines == [lines[-1]] and lines[-1].startswith("DONE:")
    assert run_id in lines[-1] and "sensitive_field_redacted" in lines[-1]


def test_number_in_model_input_is_not_yet(lab, capsys):
    # The result was redacted, but a later request still carried the number to the model, here in a resent copy of
    # the vendor record. What the model read is the test, not what the Guardian said.
    _run(lab, 10, extra_inputs=({"model": "gpt-5-nano", "input": [
        {"type": "message", "role": "user", "content": json.dumps(RECORD)}]},))
    code, lines = _check(lab, capsys)
    assert code == 1 and lines[-1].startswith("NOT YET:")
    assert "1 model input line" in lines[-1] and "./lab.sh run s5" in lines[-1]


def test_redacted_but_failed_task_is_not_yet(lab, capsys):
    # FinBot read the neutral deny line in place of the vendor's answer, so the task didn't finish with masked data.
    _run(lab, 10, reply=NEUTRAL_LINE)
    code, lines = _check(lab, capsys)
    assert code == 1 and "neutral deny line" in lines[-1] and "./lab.sh run s5" in lines[-1]
    # A run the driver didn't see finish is not yet too, whatever its decisions say.
    _run(lab, 20, result="timed_out")
    code, lines = _check(lab, capsys)
    assert code == 1 and "timed_out" in lines[-1] and "./lab.sh run s5" in lines[-1]


def test_off_run_shows_the_number(lab, capsys):
    off = _run(lab, 5, mode="off", output=RECORD)
    _run(lab, 10)
    code, lines = _check(lab, capsys)
    assert code == 0 and len(lines) == 2
    assert off in lines[0] and "bank account number" in lines[0] and "1 model input line" in lines[0]
    assert lines[-1].startswith("DONE:")


# ---------------------------------------------------------------------------------------------------------------------
# what else must not pass
# ---------------------------------------------------------------------------------------------------------------------

def test_off_run_without_the_number_says_so(lab, capsys):
    off = _run(lab, 5, mode="off", fed_back=False)
    _run(lab, 10)
    code, lines = _check(lab, capsys)
    assert code == 0 and off in lines[0] and "no model input line" in lines[0]


def test_no_enforce_run_names_the_first_commands(lab, capsys):
    code, lines = _check(lab, capsys)
    assert code == 1 and "./lab.sh mode enforce" in lines[-1] and "./lab.sh run s5" in lines[-1]
    # Off and shadow runs never count, even when the shadow run's Guardian redacted.
    _run(lab, 5, mode="off", output=RECORD)
    _run(lab, 10, mode="shadow", output=RECORD)
    code, lines = _check(lab, capsys)
    assert code == 1 and "./lab.sh mode enforce" in lines[-1]


def test_starter_reaches_the_model_and_names_the_fix(lab, capsys):
    # The starter's rule never matches, so the Guardian allows the result and the model reads the raw record.
    _run(lab, 10, result_decision="allow", output=RECORD)
    code, lines = _check(lab, capsys)
    assert code == 1 and "sensitive_field_redacted" in lines[-1]
    assert "policy/redact_bank.rego" in lines[-1] and "./lab.sh policy 5 solution" in lines[-1]
    assert "./lab.sh run s5" in lines[-1]


def test_number_with_separators_is_not_yet(lab, capsys):
    spaced = " ".join(SECRET[i:i + 4] for i in range(0, len(SECRET), 4))
    dashed = "-".join(SECRET[i:i + 3] for i in range(0, len(SECRET), 3))
    for minute, shown in ((10, spaced), (20, dashed)):
        _run(lab, minute, extra_inputs=({"input": [{"type": "message", "role": "user", "content": shown}]},))
        code, lines = _check(lab, capsys)
        assert code == 1 and "model input line" in lines[-1], shown


def test_number_in_a_line_that_is_not_json_is_not_yet(lab, capsys):
    # The gateway logs a body that wasn't JSON as a string. The number in it still reached the model.
    _run(lab, 10, extra_inputs=(f"account {SECRET}",))
    assert _check(lab, capsys)[0] == 1


def test_other_numbers_in_the_record_do_not_count(lab, capsys):
    # The TIN's digits match the account number without its leading zeros, and the routing number shares its run of
    # digits. Neither is the account number, and neither is redacted, so neither may turn the check red.
    _run(lab, 10, extra_inputs=({"input": [{"type": "message", "role": "user",
                                            "content": "TIN 12-3456789, routing 123456780, id 1000 123456789"}]},))
    assert _check(lab, capsys)[0] == 0


def test_newest_enforce_run_is_the_one_judged(lab, capsys):
    _run(lab, 10)
    _run(lab, 20, result_decision="allow", output=RECORD)
    code, lines = _check(lab, capsys)
    assert code == 1 and "20261125T1020" in lines[-1]


def test_redacted_output_that_never_reached_the_model_is_not_yet(lab, capsys):
    # No line in the window carries the redacted result, so the number's absence shows nothing about what the
    # model read.
    _run(lab, 10, fed_back=False)
    code, lines = _check(lab, capsys)
    assert code == 1 and "./lab.sh run s5" in lines[-1]


def test_withheld_output_is_not_yet(lab, capsys):
    # A redaction of the whole output forwards the neutral line, so FinBot never got the masked record.
    _run(lab, 10, cause="output_withheld", output=NEUTRAL_LINE)
    assert _check(lab, capsys)[0] == 1
    _run(lab, 20, output=NEUTRAL_LINE)
    assert _check(lab, capsys)[0] == 1
    # The cause alone rules a modify out, so neither guard leans on the other.
    _run(lab, 30, cause="output_withheld")
    assert _check(lab, capsys)[0] == 1


def test_completed_with_an_error_is_not_yet(lab, capsys):
    # The driver clears error whenever it stores completed. A record holding both wasn't written that way.
    run_id = _run(lab, 10)
    record = lab.state / "runs" / f"{run_id}.json"
    data = json.loads(record.read_text(encoding="utf-8"))
    record.write_text(json.dumps({**data, "error": "replay miss"}), encoding="utf-8")
    code, lines = _check(lab, capsys)
    assert code == 1 and "recorded an error" in lines[-1] and "./lab.sh run s5" in lines[-1]


def test_output_without_the_redaction_mark_is_not_yet(lab, capsys):
    # The gateway forwards the item it edited, so the redacted call's output carries its [REDACTED] mark. Any other
    # text there isn't the masked record.
    _run(lab, 10, output="Northwind Supplies, First Example Bank")
    assert _check(lab, capsys)[0] == 1


@pytest.mark.parametrize("change", [
    {"tool": "get_invoice_for_payment"},
    {"method": "steps/toolCallRequest"},
    {"reason_codes": ["egress_blocked"]},
    {"run_sessions": [SESSION_B]},
    {"decision_epoch": 7},
])
def test_modify_that_is_not_this_lesson_does_not_count(lab, capsys, change):
    _run(lab, 10, **change)
    assert _check(lab, capsys)[0] == 1


def test_completed_run_without_a_reply_is_broken(lab):
    # The driver writes a completed s5 run only after FinBot answered the reply probe.
    _run(lab, 10, reply=None)
    with pytest.raises(EvidenceError, match="./lab.sh run s5"):
        m5.check(Evidence(lab.root))
    assert lab_modules._call(lambda: m5.check(Evidence(lab.root))) == 2


def test_missing_scenario_file_is_broken(lab):
    _run(lab, 10)
    (lab.root / "scenarios" / "s5.json").unlink()
    with pytest.raises(EvidenceError, match="s5.json"):
        m5.check(Evidence(lab.root))


def test_neutral_line_matches_the_gateway():
    # The check runs with the standard library only, so it keeps its own copy of the gateway's sentence.
    assert m5.NEUTRAL_LINE == NEUTRAL_LINE
    assert m5.REDACTION_MARK == DEFAULT_REDACTION


# ---------------------------------------------------------------------------------------------------------------------
# the guide's Rego (fix round 1, review I-1)
# ---------------------------------------------------------------------------------------------------------------------

POLICY = BUNDLE / "policy"
GUIDE = BUNDLE / "modules" / "5.md"
REGO_FENCE = re.compile(r"^```rego\n(.*?)^```", re.M | re.S)
# The starter's one rule, from its head to the closing brace at column 0. The guide tells the reader to replace it.
STARTER_RULE = re.compile(r"^redaction_paths contains .*?^}\n", re.M | re.S)
HEAD = re.compile(r"^([a-z_][a-z0-9_]*)\b", re.M)
TOKEN = re.compile(r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)")
STRING = re.compile(r'"(?:[^"\\]|\\.)*"|`[^`]*`')
KEYWORDS = {"package", "import", "if", "contains", "not", "in", "some", "every", "else", "default", "input", "data",
            "true", "false", "null", "with", "as", "_"}
# The OPA built-ins a redaction rule reasonably calls. A dotted built-in counts by its first part.
BUILTINS = {"walk", "count", "concat", "array", "replace", "format_int", "is_string", "is_number", "split", "sprintf",
            "object", "startswith", "endswith", "lower", "upper", "regex", "strings", "to_number", "trim"}


def _guide_rego() -> str:
    blocks = REGO_FENCE.findall(GUIDE.read_text(encoding="utf-8"))
    assert len(blocks) == 1, "modules/5.md should show exactly one rego block, the one the reader pastes"
    return blocks[0]


def _pasted_starter() -> str:
    """The starter as the guide says to edit it: its one rule replaced by the guide's Rego."""
    starter = (POLICY / "starters" / "m5" / "redact_bank.rego").read_text(encoding="utf-8")
    assert len(STARTER_RULE.findall(starter)) == 1, "the starter should hold one redaction_paths rule"
    return STARTER_RULE.sub(lambda _: _guide_rego(), starter)


def _code(text: str) -> str:
    return STRING.sub('""', "\n".join(line.split("#", 1)[0] for line in text.splitlines()))


def _locals(rego: str) -> set[str]:
    """Names a rule binds for itself: function parameters, := and = targets, some and walk bindings."""
    found: set[str] = set()
    for params in re.findall(r"^[a-z_]\w*\(([^)]*)\)", rego, re.M):
        found.update(p.strip() for p in params.split(","))
    found.update(re.findall(r"\b(\w+)\s*:?=(?!=)", rego))
    found.update(re.findall(r"\bsome\s+(\w+)", rego))
    for pair in re.findall(r"\[(\w+),\s*(\w+)\]", rego):
        found.update(pair)
    return found


def test_guide_rego_names_only_what_the_pasted_file_defines():
    # Pasted into the starter, the guide's Rego must compile, since one broken file stops OPA deciding for every
    # module. Each name it uses is a keyword, a built-in, a name the rule binds, or a rule the live pack defines.
    pasted = _code(_pasted_starter())
    others = {path.name: _code(path.read_text(encoding="utf-8")) for path in POLICY.glob("*.rego")
              if path.name != "redact_bank.rego"}
    defined = set(HEAD.findall(pasted)) | {h for text in others.values() for h in HEAD.findall(text)}
    used = set(TOKEN.findall(_code(_guide_rego())))
    unknown = used - KEYWORDS - BUILTINS - _locals(_code(_guide_rego())) - defined
    assert not unknown, f"modules/5.md's Rego uses names nothing defines once pasted: {sorted(unknown)}"
    # A helper the snippet adds must not collide with a rule another live file already defines.
    partial = {"redaction_paths", "deny_codes", "ask_requests", "package"}
    added = set(HEAD.findall(_code(_guide_rego()))) - partial
    clashes = {name for name in added for text in others.values() if name in HEAD.findall(text)}
    assert not clashes, f"modules/5.md's Rego redefines {sorted(clashes)}"


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa is not on PATH. The static test above still runs")
def test_guide_rego_compiles_in_the_pack(tmp_path):
    for path in POLICY.glob("*.rego"):
        shutil.copy(path, tmp_path / path.name)
    shutil.copy(POLICY / "data.json", tmp_path / "data.json")
    (tmp_path / "redact_bank.rego").write_text(_pasted_starter(), encoding="utf-8")
    shutil.copytree(POLICY / "tests", tmp_path / "tests")
    done = subprocess.run(["opa", "test", str(tmp_path), "--run", "finbot_test.m5"], capture_output=True, text=True,
                          timeout=120, check=False)
    assert done.returncode == 0, done.stdout + done.stderr
