"""Module 1's check, Wire it in (issue #589, LAB-16 Task 6).

Version 1.0.0. Owner: Rock Lambros.

The evidence is written by the code that writes it in the lab (fixtures.py), and each enforce run is judged by the real
acs-verify against a real ML-DSA-65 decision key, so the tests need the pqc extra:

    uv run --project adapters --locked --extra pqc --group test python -m pytest \
        labs/finbot/modules/checks/tests/test_m1.py -v
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa", reason="needs the pqc extra")

import fixtures  # noqa: E402
from fixtures import SESSION_A, LabState, answer, request, tool_request  # noqa: E402

import evidence  # noqa: E402
import lab_modules  # noqa: E402
import m1  # noqa: E402
from evidence import Evidence  # noqa: E402

OFF_RUN, ON_RUN = "20261125T100000Z-s1", "20261125T101500Z-s1"
OFF_STARTED, OFF_ENDED = "2026-11-25T10:00:00Z", "2026-11-25T10:05:00Z"
ON_STARTED, ON_ENDED = "2026-11-25T10:15:00Z", "2026-11-25T10:20:00Z"
METHODS = ["steps/sessionStart", "steps/toolCallRequest", "steps/toolCallResult"]
CLIENT_HELLO = {"acs_versions_supported": ["0.1.0"], "methods_implemented": METHODS, "transports_supported": ["http"],
                "provenance_producer": "acs-gateway", "profiles_supported": ["acs-core"],
                "x_acs_lab_response_algorithms": ["ML-DSA-65"]}
# The two calls s1's onboarding agent makes, as the gateway gates them.
CALLS = (("get_vendor_details", "call_1"), ("update_vendor_status", "call_2"))


def transcript_sizes(lab: LabState) -> dict[str, int]:
    """Each transcript's name and size, as the driver records them at a window's start and end."""
    return {p.name: p.stat().st_size for p in sorted((lab.state / "transcripts").glob("*.jsonl"))}


def finbot(before: dict[str, int], after: dict[str, int]) -> dict[str, Any]:
    return {"namespace": "ns_user_test", "vendor": {},
            "evidence": {"transcripts_before": before, "transcripts_after": after}}


def _server_hello(algorithm: str) -> dict[str, Any]:
    hello = {"negotiated_version": "0.1.0", "methods_evaluated": METHODS, "selected_transport": "http",
             "signature_algorithms_supported": ["HMAC-SHA256"], "timeout_config": {"default_ms": 5000},
             "skew_window_ms": 30000, "on_decision_failure": "deny", "policy_requires_provenance": False,
             "profiles_accepted": ["acs-core"]}
    if algorithm:
        hello["x_acs_lab_response_algorithm"] = algorithm
    return hello


@pytest.fixture
def lab(tmp_path) -> LabState:
    return LabState(tmp_path / "bundle")


@pytest.fixture
def key(lab) -> fixtures.DecisionKey:
    # The key document lands at state/keys/guardian-keys.json and its pin in .env, as lab init leaves them.
    found = fixtures.decision_key(lab.state / "keys")
    lab.write_env(LAB_GUARDIAN_FINGERPRINT=found.fingerprint)
    return found


def off_run(lab: LabState, *, run_id: str = OFF_RUN, started: str = OFF_STARTED, ended: str = OFF_ENDED,
            model_input: bool = True, session: bool = False, grow: str | None = None, result: str = "completed",
            **extra: Any) -> None:
    """An off run: FinBot's model calls pass through the gateway, which governs nothing and opens no session.

    grow names a session whose transcript gains a line during the run, which an off gateway never writes."""
    a0, m0 = lab.size(lab.audit_file), lab.size(lab.model_input_file)
    before = transcript_sizes(lab)
    if session:
        lab.audit("session_opened", session_id=SESSION_A, epoch=1)
    if model_input:
        lab.model_input({"model": "gpt-5-mini", "input": [{"type": "message", "role": "user", "content": "onboard"}]})
    if grow:
        req = tool_request("get_vendor_details", session_id=grow)
        lab.pair(req, answer(req))
    extra.setdefault("finbot", finbot(before, transcript_sizes(lab)))
    lab.run_record(run_id, mode="off", started=started, ended=ended, result=result,
                   audit=(a0, lab.size(lab.audit_file)), model_inputs=(m0, lab.size(lab.model_input_file)),
                   sessions=[SESSION_A] if session else [], **extra)


def on_run(lab: LabState, key: fixtures.DecisionKey, *, run_id: str = ON_RUN, started: str = ON_STARTED,
           ended: str = ON_ENDED, deny: str | None = None, algorithm: str = "ML-DSA-65",
           session_start: bool = True, unlogged_call: str | None = None, session_id: str = SESSION_A,
           calls: tuple[tuple[str, str], ...] = CALLS, opening: bool = True, signed: bool = True,
           result: str = "completed", model_input: bool = True, extra_inputs: tuple[Any, ...] = (),
           record: bool = True, **extra: Any) -> tuple[int, int]:
    """An enforce run of s1 as the gateway records it: a session opened with a handshake and sessionStart, then each
    call gated on request and on result, audited with its call_id, and fed back to the model in the next request.
    Returns the audit and model input offsets it started from, so a test can write one record over several sessions.

    deny names a call the Guardian denies. The gateway removes a denied call, so the model never sees it again.
    unlogged_call names a call the model input holds that no gated step covers. Each run gets its own session, as
    the gateway opens a fresh one for each FinBot started from empty data. opening=False leaves out the handshake and
    sessionStart, signed=False leaves the tool answers unsigned, and extra_inputs are model input lines added last."""
    a0, m0 = lab.size(lab.audit_file), lab.size(lab.model_input_file)
    before = transcript_sizes(lab)

    def sign(response: dict[str, Any], req: dict[str, Any]) -> dict[str, Any]:
        return key.sign(response, req) if signed else response

    if opening:
        lab.audit("session_opened", session_id=session_id, epoch=1)
        hello = request("handshake/hello", CLIENT_HELLO, session_id=session_id)
        lab.pair(hello, key.sign({"jsonrpc": "2.0", "id": hello["id"], "result": _server_hello(algorithm)}, hello))
        if session_start:
            start = request("steps/sessionStart", session_id=session_id)
            lab.pair(start, key.sign(answer(start), start))
    fed_back: list[dict[str, Any]] = [{"type": "message", "role": "user", "content": "onboard"}]
    if model_input:
        lab.model_input({"model": "gpt-5-mini", "input": list(fed_back)})
    for name, call_id in calls:
        decision = "deny" if name == deny else "allow"
        req = tool_request(name, {"vendor_id": 7}, session_id=session_id)
        lab.pair(req, sign(answer(req, decision), req))
        lab.audit("decision_applied", session_id=session_id, epoch=1, method="steps/toolCallRequest", tool=name,
                  call_id=call_id, request_id=req["params"]["request_id"], decision=decision,
                  guardian_decision=decision, reason_codes=[], cause=None, failure_class=None)
        if decision != "allow":
            continue
        done = request("steps/toolCallResult", {"tool": {"name": name}, "exit_status": "success",
                                                "outputs": [{"value": "ok"}]}, session_id=session_id)
        lab.pair(done, sign(answer(done), done))
        lab.audit("decision_applied", session_id=session_id, epoch=1, method="steps/toolCallResult", tool=name,
                  call_id=call_id, request_id=done["params"]["request_id"], decision="allow",
                  guardian_decision="allow", reason_codes=[], cause=None, failure_class=None)
        fed_back += [{"type": "function_call", "name": name, "call_id": call_id, "arguments": '{"vendor_id": 7}'},
                     {"type": "function_call_output", "call_id": call_id, "output": "ok"}]
        if model_input:
            lab.model_input({"model": "gpt-5-mini", "input": list(fed_back)})
    if unlogged_call:
        fed_back.append({"type": "function_call", "name": unlogged_call, "call_id": "call_9", "arguments": "{}"})
        lab.model_input({"model": "gpt-5-mini", "input": list(fed_back)})
    for body in extra_inputs:
        lab.model_input(body)
    if record:
        extra.setdefault("finbot", finbot(before, transcript_sizes(lab)))
        lab.run_record(run_id, mode="enforce", started=started, ended=ended, result=result,
                       audit=(a0, lab.size(lab.audit_file)), model_inputs=(m0, lab.size(lab.model_input_file)),
                       sessions=[session_id], **extra)
    return a0, m0


def run_check(lab: LabState, capsys) -> tuple[int, list[str]]:
    code = m1.check(Evidence(lab.root))
    return code, capsys.readouterr().out.splitlines()


def assert_one_line(code: int, out: list[str], expected_code: int, *needles: str) -> None:
    assert code == expected_code, out
    assert len(out) == 1, out
    prefix = "DONE: " if expected_code == 0 else "NOT YET: "
    assert out[0].startswith(prefix), out
    for needle in needles:
        assert needle in out[0], (needle, out)


def test_off_run_leaves_no_acs_record(lab, key, capsys):
    on_run(lab, key)
    off_run(lab)
    assert_one_line(*run_check(lab, capsys), 0, "module 1")

    # An off run that opened a session wasn't off.
    off_run(lab, run_id="20261125T110000Z-s1", started="2026-11-25T11:00:00Z", ended="2026-11-25T11:05:00Z",
            session=True)
    assert_one_line(*run_check(lab, capsys), 1, "./lab.sh mode off", "./lab.sh run s1")

    # An off run during which a transcript grew, by the driver's size maps, wasn't off either, even with no session
    # in its record. A new transcript counts the same as a longer one.
    off_run(lab, run_id="20261125T120000Z-s1", started="2026-11-25T12:00:00Z", ended="2026-11-25T12:05:00Z",
            grow=SESSION_A)
    assert_one_line(*run_check(lab, capsys), 1, "transcript", "./lab.sh mode off", "./lab.sh run s1")
    off_run(lab, run_id="20261125T121000Z-s1", started="2026-11-25T12:10:00Z", ended="2026-11-25T12:15:00Z",
            grow=str(uuid.uuid4()))
    assert_one_line(*run_check(lab, capsys), 1, "transcript", "./lab.sh mode off", "./lab.sh run s1")

    # An off run with no model input line never reached the gateway, so it proves nothing about FinBot's path.
    off_run(lab, run_id="20261125T130000Z-s1", started="2026-11-25T13:00:00Z", ended="2026-11-25T13:05:00Z",
            model_input=False)
    assert_one_line(*run_check(lab, capsys), 1, "model input", "./lab.sh run s1")


def test_on_run_has_a_full_record(lab, key, capsys):
    off_run(lab)
    on_run(lab, key)
    code, out = run_check(lab, capsys)
    assert_one_line(code, out, 0, ON_RUN, key.fingerprint)

    # Each part of the record is needed. Every later run is the newest, so it is the one judged.
    def later(index: int) -> dict[str, str]:
        return {"run_id": f"20261125T1{index}0000Z-s1", "started": f"2026-11-25T1{index}:00:00Z",
                "ended": f"2026-11-25T1{index}:05:00Z", "session_id": str(uuid.uuid4())}

    on_run(lab, key, **later(1), algorithm="")
    assert_one_line(*run_check(lab, capsys), 1, "ML-DSA-65", "./lab.sh sign mldsa")

    on_run(lab, key, **later(2), session_start=False)
    assert_one_line(*run_check(lab, capsys), 1, "sessionStart", "./lab.sh run s1")

    on_run(lab, key, **later(3), unlogged_call="send_email")
    assert_one_line(*run_check(lab, capsys), 1, "send_email", "./lab.sh run s1")

    # No enforce run with a session at all.
    fourth = later(4)
    lab.run_record(fourth["run_id"], mode="enforce", started=fourth["started"], ended=fourth["ended"], sessions=[])
    assert_one_line(*run_check(lab, capsys), 1, "./lab.sh mode enforce", "./lab.sh run s1")


def test_a_deny_in_the_on_run_is_not_yet(lab, key, capsys):
    off_run(lab)
    on_run(lab, key, deny="update_vendor_status")
    assert_one_line(*run_check(lab, capsys), 1, "deny", "update_vendor_status", "./lab.sh run s1")


def test_missing_off_run_says_which_command(lab, key, capsys):
    assert_one_line(*run_check(lab, capsys), 1, "./lab.sh mode off", "./lab.sh run s1")
    on_run(lab, key)
    assert_one_line(*run_check(lab, capsys), 1, "off run", "./lab.sh mode off", "./lab.sh run s1")
    # The off run alone isn't enough either, and the line names the enforce run still to make.
    other = LabState(lab.root.parent / "other")
    other.write_env(LAB_GUARDIAN_FINGERPRINT=key.fingerprint)
    off_run(other)
    assert_one_line(*run_check(other, capsys), 1, "./lab.sh mode enforce", "./lab.sh run s1")


def test_tampered_transcript_is_not_yet(lab, key, capsys):
    off_run(lab)
    on_run(lab, key)
    path = lab.transcript_path()
    lines = path.read_text(encoding="utf-8").splitlines()
    # The sessionStart answer, line 4, now says something the Guardian never signed.
    record = json.loads(lines[3])
    record["envelope"]["result"]["reasoning"] = "edited after signing"
    lines[3] = json.dumps(record, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert_one_line(*run_check(lab, capsys), 1, "acs-verify", "./lab.sh run s1")


def test_a_request_not_on_hmac_is_not_yet(lab, key, capsys):
    """Requests stay on HMAC in every response mode (issue #316), so a request signed any other way wasn't the
    gateway's."""
    off_run(lab)
    on_run(lab, key)
    path = lab.transcript_path()
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[2])
    record["envelope"]["params"]["signature"]["algorithm"] = "none"
    lines[2] = json.dumps(record, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert_one_line(*run_check(lab, capsys), 1, "HMAC-SHA256", "./lab.sh run s1")


def test_allows_from_an_unverified_session_are_not_yet(lab, key, capsys):
    """Review C1: session A verifies and makes no call, session B holds both allows unsigned. The allows must come
    from the session acs-verify passed."""
    off_run(lab)
    second = str(uuid.uuid4())
    a0, m0 = on_run(lab, key, calls=(), model_input=False, record=False)
    on_run(lab, key, session_id=second, opening=False, signed=False, record=False)
    lab.run_record(ON_RUN, mode="enforce", started=ON_STARTED, ended=ON_ENDED, audit=(a0, lab.size(lab.audit_file)),
                   model_inputs=(m0, lab.size(lab.model_input_file)), sessions=[SESSION_A, second])
    code, out = run_check(lab, capsys)
    assert code != 0, out
    assert_one_line(code, out, 1, "./lab.sh run s1")


@pytest.mark.parametrize(("shape", "needle"), [
    ({"result": "failed", "calls": ()}, "failed"),
    ({"result": "timed_out", "calls": (), "model_input": False}, "timed_out"),
    ({"calls": (), "model_input": False}, "model input"),
    ({"calls": ()}, "no tool"),
])
def test_a_failed_or_empty_run_is_not_yet(lab, key, capsys, shape, needle):
    """Review C2: a run that failed, timed out, reached no model, or made no call proves nothing about governing."""
    off_run(lab)
    on_run(lab, key, **shape)
    assert_one_line(*run_check(lab, capsys), 1, needle, "./lab.sh run s1")


def test_a_string_input_holds_no_calls(lab, key, capsys):
    """Re-review N4, by ruling: the Responses API takes a string input, which can't carry a function_call, so it
    counts as zero calls rather than as a line the check can't read."""
    off_run(lab)
    on_run(lab, key, extra_inputs=({"model": "gpt-5-mini", "input": "onboard the vendor"},))
    assert_one_line(*run_check(lab, capsys), 0, ON_RUN)


@pytest.mark.parametrize("body", [
    {"model": "gpt-5-mini", "input": {"type": "function_call", "name": "send_email", "call_id": "call_9"}},
    {"model": "gpt-5-mini"},
    "not json at all",
])
def test_a_model_input_the_check_cant_read_is_not_yet(lab, key, capsys, body):
    """Review I1: calls in a body whose input is neither a list nor a string would need no allow, so the body isn't
    skipped."""
    off_run(lab)
    on_run(lab, key, extra_inputs=(body,))
    code, out = run_check(lab, capsys)
    assert code in (1, 2) and len(out) == 1 and out[0].startswith("NOT YET: ") and "model input" in out[0], out


def test_a_call_without_a_call_id_is_refused(lab, key, capsys):
    """Review M2: a missing call_id never matches an audited allow that also lacks one."""
    off_run(lab)
    on_run(lab, key, extra_inputs=({"model": "gpt-5-mini", "input": [
        {"type": "function_call", "name": "send_email", "arguments": "{}"}]},))
    assert_one_line(*run_check(lab, capsys), 1, "call_id", "./lab.sh run s1")


@pytest.mark.parametrize("half", ["off", "enforce"])
@pytest.mark.parametrize(("result", "fields", "needle"), [
    ("not_yet", {}, "not_yet"),
    ("broken", {"error": "the driver hit an error"}, "broken"),
    ("completed", {"error": "replay miss on turn 3"}, "replay miss on turn 3"),
    ("completed", {"replay_misses": 1}, "replay miss"),
])
def test_both_halves_need_a_clean_completed_run(lab, key, capsys, half, result, fields, needle):
    """Guide-phase rule 1 and re-review N2: each half counts only a completed run with no error and no replay miss,
    and the line names the command that makes a fresh one."""
    if half == "off":
        on_run(lab, key)
        off_run(lab, result=result, **fields)
        command = "./lab.sh mode off"
    else:
        off_run(lab)
        on_run(lab, key, result=result, **fields)
        command = "./lab.sh run s1"
    assert_one_line(*run_check(lab, capsys), 1, needle, command)


def test_the_allow_must_name_the_tool_the_model_called(lab, key, capsys):
    """Re-review N1: the model saw send_email as call_3, and the only allow for call_3 sits on a get_vendor_details
    request. An allow covers only the tool it names."""
    off_run(lab)
    on_run(lab, key, calls=(("get_vendor_details", "call_3"),), extra_inputs=({"model": "gpt-5-mini", "input": [
        {"type": "function_call", "name": "send_email", "call_id": "call_3", "arguments": "{}"}]},))
    assert_one_line(*run_check(lab, capsys), 1, "call_3", "./lab.sh run s1")


def test_the_signed_request_must_name_the_tool_the_audit_names(lab, key, capsys):
    """Re-review N1: the audit line says send_email for call_3, but the signed request it points at asks about
    get_vendor_details. The Guardian never allowed send_email."""
    off_run(lab)
    a0, m0 = on_run(lab, key, record=False)
    req = tool_request("get_vendor_details", {"vendor_id": 7})
    lab.pair(req, key.sign(answer(req), req))
    lab.audit("decision_applied", session_id=SESSION_A, epoch=1, method="steps/toolCallRequest", tool="send_email",
              call_id="call_3", request_id=req["params"]["request_id"], decision="allow", guardian_decision="allow",
              reason_codes=[], cause=None, failure_class=None)
    lab.model_input({"model": "gpt-5-mini", "input": [
        {"type": "function_call", "name": "send_email", "call_id": "call_3", "arguments": "{}"}]})
    lab.run_record(ON_RUN, mode="enforce", started=ON_STARTED, ended=ON_ENDED, audit=(a0, lab.size(lab.audit_file)),
                   model_inputs=(m0, lab.size(lab.model_input_file)), sessions=[SESSION_A],
                   finbot=finbot({}, transcript_sizes(lab)))
    assert_one_line(*run_check(lab, capsys), 1, "send_email", "call_3", "./lab.sh run s1")


def test_audit_lines_that_swap_two_call_ids_are_not_yet(lab, key, capsys):
    """Re-review N1: both tools allowed, but each audit line names the other call's id, so neither call's allow
    names its own tool."""
    off_run(lab)
    on_run(lab, key, calls=(("get_vendor_details", "call_2"), ("update_vendor_status", "call_1")),
           extra_inputs=({"model": "gpt-5-mini", "input": [
               {"type": "function_call", "name": "get_vendor_details", "call_id": "call_1", "arguments": "{}"},
               {"type": "function_call", "name": "update_vendor_status", "call_id": "call_2", "arguments": "{}"}]},))
    assert_one_line(*run_check(lab, capsys), 1, "./lab.sh run s1")


def test_a_call_id_used_for_two_tools_is_refused(lab, key, capsys):
    """Re-review N1: one call_id under two tool names would let one allow hide the second call."""
    off_run(lab)
    on_run(lab, key, extra_inputs=({"model": "gpt-5-mini", "input": [
        {"type": "function_call", "name": "send_email", "call_id": "call_1", "arguments": "{}"}]},))
    assert_one_line(*run_check(lab, capsys), 1, "call_1", "send_email", "./lab.sh run s1")


def test_a_run_whose_only_call_was_denied_names_the_deny(lab, key, capsys):
    """Re-review N3: the gateway removes a denied call, so the model input holds none. The line names the deny,
    not a run with no call."""
    off_run(lab)
    on_run(lab, key, calls=(("send_email", "call_1"),), deny="send_email")
    assert_one_line(*run_check(lab, capsys), 1, "deny", "send_email", "./lab.sh logs acs-guardian")


def test_a_pin_other_than_the_guardians_is_not_yet(lab, key, capsys):
    off_run(lab)
    on_run(lab, key)
    lab.write_env(LAB_GUARDIAN_FINGERPRINT="sha256:" + "ef" * 32)
    assert_one_line(*run_check(lab, capsys), 1, "acs-verify")
    lab.write_env()
    assert_one_line(*run_check(lab, capsys), 1, "./lab.sh init")


@pytest.mark.parametrize("evidence_field", [
    {"transcripts_after": {}},
    {"transcripts_before": {}, "transcripts_after": {"a.jsonl": "12"}},
    {"transcripts_before": [], "transcripts_after": {}},
])
def test_unreadable_evidence_is_broken(lab, key, capsys, monkeypatch, evidence_field):
    """A completed off run without the driver's two size maps, or with a size that isn't a count, is evidence the
    driver never wrote. lab check prints one line and exits 2."""
    on_run(lab, key)
    off_run(lab, finbot={"namespace": "ns_user_test", "vendor": {}, "evidence": evidence_field})
    monkeypatch.setitem(lab_modules.sys.modules, "evidence", evidence)
    code = lab_modules._call(lambda: m1.check(Evidence(lab.root)))
    out = capsys.readouterr().out.splitlines()
    assert code == 2 and len(out) == 1 and out[0].startswith("NOT YET: "), out


@pytest.mark.parametrize("size", [5.0, "5", -1, None, True, [5]])
def test_a_bad_size_names_the_file_not_a_missing_map(lab, key, capsys, monkeypatch, size):
    """Guide review M6: the map is there, but one value isn't a count, so the line names that file."""
    on_run(lab, key)
    off_run(lab, finbot=finbot({"a.jsonl": 3}, {"a.jsonl": size}))
    monkeypatch.setitem(lab_modules.sys.modules, "evidence", evidence)
    code = lab_modules._call(lambda: m1.check(Evidence(lab.root)))
    out = capsys.readouterr().out.splitlines()
    assert code == 2 and len(out) == 1, out
    assert "a.jsonl" in out[0] and "isn't a count" in out[0] and "no transcripts_after map" not in out[0], out


def test_a_call_with_no_allow_says_run_s1_again(lab, key, capsys):
    """Guide review M7: the enforce run exists already, so the line asks for another run, not for the mode."""
    off_run(lab)
    on_run(lab, key, unlogged_call="send_email")
    code, out = run_check(lab, capsys)
    assert_one_line(code, out, 1, "send_email", "./lab.sh run s1 again")
    assert "mode enforce" not in out[0], out


def test_check_names_no_trace_view():
    """Belt to test_evidence's guard: m1 reads files only."""
    source = Path(m1.__file__).read_text(encoding="utf-8")
    for banned in ("import socket", "import http", "import urllib", "import requests", "import httpx"):
        assert banned not in source
