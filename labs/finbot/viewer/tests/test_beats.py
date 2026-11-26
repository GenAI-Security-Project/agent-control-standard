"""The A.12 beats each row paints, and the "no ACS record" state (issue #586).

The module 7 result files are a lab convention the coordinator accepted for LAB-16 (plan LAB-13, open question 1).
"""
from __future__ import annotations

import json
import time

import pytest

from beats import BEATS, NO_RECORD_TEXT, verify_dir_beats
from lab_lines import SESSION_A, SESSION_B, LabLogs, answer, error_answer, request, sign_hmac, tool_request
from model import Model


def model_for(logs: LabLogs) -> Model:
    return Model(logs.transcript_dir, logs.audit_file, None, verify_dir=logs.verify_dir)


def painted(logs: LabLogs) -> list[str | None]:
    model = model_for(logs)
    model.refresh()
    return [row.beat for row in model.rows_after(0)]


def step(logs: LabLogs, tool: str, decision: str, *, session_id: str = SESSION_A, **result) -> dict:
    req = tool_request(tool, session_id=session_id)
    logs.pair(req, answer(req, decision, **result))
    return req


def applied(logs: LabLogs, req: dict, event: str, decision: str, guardian: str, **fields) -> None:
    logs.audit(event, session_id=req["params"]["metadata"]["session_id"], epoch=0, method=req["method"],
               tool=req["params"]["payload"]["tool"]["name"], call_id="c1", request_id=req["params"]["request_id"],
               decision=decision, guardian_decision=guardian, reason_codes=fields.pop("reason_codes", None),
               cause=fields.pop("cause", None), failure_class=None)


def result_file(logs: LabLogs, name: str, **fields) -> None:
    logs.verify_dir.mkdir(parents=True, exist_ok=True)
    (logs.verify_dir / name).write_text(json.dumps(fields), encoding="utf-8")


def test_beats_are_a12_in_order():
    assert BEATS == ("handshake", "first_allow", "shadow_decision", "deny", "allow_after_fix", "ask_pending",
                     "ask_resolved", "modify", "digest_mismatch", "forge_passes_hmac", "forge_fails_mldsa",
                     "keys_only_verify", "downgrade_refused")


def test_handshake(tmp_path):
    logs = LabLogs(tmp_path)
    hello = request("handshake/hello", {"client": "lab"})
    logs.pair(hello, sign_hmac({"jsonrpc": "2.0", "id": hello["id"],
                                "result": {"request_id": hello["params"]["request_id"], "negotiated_version": "0.1.0"}}))
    assert painted(logs) == ["handshake"]


def test_handshake_that_failed_verification_paints_nothing(tmp_path):
    logs = LabLogs(tmp_path)
    hello = request("handshake/hello", {"client": "lab"})
    logs.pair(hello, None, cause="transport_failure")
    assert painted(logs) == [None]


def test_first_allow(tmp_path):
    logs = LabLogs(tmp_path)
    start = request("steps/sessionStart", {"source": "startup"})
    logs.pair(start, answer(start, "allow"))
    step(logs, "finstripe__get_invoice", "allow")
    step(logs, "finstripe__get_invoice", "allow")
    # sessionStart's allow names no tool, so the first tool call is the first allow.
    assert painted(logs) == [None, "first_allow", None]


def test_shadow_decision(tmp_path):
    logs = LabLogs(tmp_path)
    req = step(logs, "finmail__send_email", "deny", reason_codes=["external_recipient"])
    applied(logs, req, "shadow_decision", "allow", "deny", reason_codes=["external_recipient"])
    assert painted(logs) == ["shadow_decision"]


def test_deny(tmp_path):
    logs = LabLogs(tmp_path)
    req = step(logs, "finmail__send_email", "deny", reason_codes=["external_recipient"])
    applied(logs, req, "decision_applied", "deny", "deny", reason_codes=["external_recipient"])
    assert painted(logs) == ["deny"]


def test_allow_after_fix(tmp_path):
    logs = LabLogs(tmp_path)
    step(logs, "finmail__send_email", "deny", reason_codes=["external_recipient"])
    step(logs, "finmail__send_email", "allow", session_id=SESSION_B)
    assert painted(logs) == ["deny", "allow_after_fix"]


def test_ask_pending(tmp_path):
    logs = LabLogs(tmp_path)
    logs.audit("ask_pending", session_id=SESSION_A, call_id="c1", tool="finstripe__create_transfer",
               request_id="r1", approver="lab-approver", question="Pay 9000?", deadline_s=120, remaining_s=119.5)
    assert painted(logs) == ["ask_pending"]


def test_ask_resolved(tmp_path):
    logs = LabLogs(tmp_path)
    logs.audit("ask_resolved", session_id=SESSION_A, call_id="c1", tool="finstripe__create_transfer",
               ask_request_id="r1", approver="lab-approver", deadline_s=120, outcome="approved", waited_s=4.2,
               resent=True, request_id="r2", guardian_decision="allow", decision="allow", cause=None)
    model = model_for(logs)
    model.refresh()
    [row] = model.rows_after(0)
    assert (row.beat, row.decision, row.note) == ("ask_resolved", "allow", "ask approved")


def test_modify(tmp_path):
    logs = LabLogs(tmp_path)
    req = request("steps/toolCallResult", {"tool": {"name": "finstripe__get_vendor"}, "exit_status": "success",
                                           "outputs": [{"value": {"bank_account_number": "x"}}]})
    logs.pair(req, answer(req, "modify", reason_codes=["sensitive_field_redacted"]))
    assert painted(logs) == ["modify"]


def test_digest_mismatch(tmp_path):
    logs = LabLogs(tmp_path)
    step(logs, "finmail__send_email", "deny", reason_codes=["tool_content_hash_mismatch"])
    assert painted(logs) == ["digest_mismatch"]


def test_forge_passes_hmac(tmp_path):
    logs = LabLogs(tmp_path)
    result_file(logs, "1-forge.json", kind="forge", algorithm="HMAC-SHA256", result="verified", entry=7,
                detail="a forged allow verifies under the shared secret")
    assert painted(logs) == ["forge_passes_hmac"]


def test_forge_fails_mldsa(tmp_path):
    logs = LabLogs(tmp_path)
    result_file(logs, "2-forge.json", kind="forge", algorithm="ML-DSA-65", result="broken", entry=7,
                detail="signature_invalid")
    assert painted(logs) == ["forge_fails_mldsa"]


def test_keys_only_verify(tmp_path):
    logs = LabLogs(tmp_path)
    result_file(logs, "3-verify.json", kind="keys_only", algorithm="ML-DSA-65", result="verified", entry=None,
                detail="PASS, signatures only")
    assert painted(logs) == ["keys_only_verify"]


def test_downgrade_refused(tmp_path):
    logs = LabLogs(tmp_path)
    hello = request("handshake/hello", {"client": "lab"})
    logs.pair(hello, error_answer(hello, -32000, "SESSION_REFUSED: unsupported_signature_algorithm",
                                  {"reason": "unsupported_signature_algorithm"}))
    result_file(logs, "4-downgrade.json", kind="downgrade", algorithm="HMAC-SHA256", result="refused", entry=None,
                detail="the Guardian refused HMAC")
    assert painted(logs) == ["downgrade_refused", "downgrade_refused"]


def test_replay_miss_is_marked(tmp_path):
    logs = LabLogs(tmp_path)
    logs.audit("replay_miss", cause="no_recording", step=3, branch="main", stream=True)
    model = model_for(logs)
    model.refresh()
    [row] = model.rows_after(0)
    assert row.note == "replay miss: recorded neutral reply"
    assert row.reason_codes == ["no_recording"]
    # A replay miss isn't an ACS record. Off mode has them too.
    assert model.no_record


def test_no_rows_reads_no_acs_record(tmp_path):
    logs = LabLogs(tmp_path)
    model = model_for(logs)
    model.refresh()
    assert model.no_record and NO_RECORD_TEXT == "no ACS record"
    step(logs, "echo", "allow")
    model.refresh()
    assert not model.no_record
    # lab mode off bumps the epoch. Rows from before the bump no longer count as this session's record.
    # Lab timestamps carry milliseconds, and the epoch test compares them, so the steps sit apart from the bump.
    time.sleep(0.005)
    logs.audit("epoch_bumped", epoch=1)
    model.refresh()
    assert model.no_record
    time.sleep(0.005)
    step(logs, "echo", "allow", session_id=SESSION_B)
    model.refresh()
    assert not model.no_record


@pytest.mark.parametrize("content", ["not json", json.dumps({"kind": "teleport", "algorithm": "ML-DSA-65",
                                                              "result": "verified", "entry": 1, "detail": ""}),
                                     json.dumps({"kind": "forge", "algorithm": "RSA", "result": "verified",
                                                 "entry": 1, "detail": ""}),
                                     json.dumps(["forge"])])
def test_unknown_result_file_is_skipped(tmp_path, content):
    logs = LabLogs(tmp_path)
    logs.verify_dir.mkdir()
    (logs.verify_dir / "bad.json").write_text(content, encoding="utf-8")
    assert verify_dir_beats(logs.verify_dir) == []
    assert painted(logs) == []


def test_result_file_rewritten_updates_its_row(tmp_path):
    logs = LabLogs(tmp_path)
    result_file(logs, "forge.json", kind="forge", algorithm="ML-DSA-65", result="verified", entry=1, detail="")
    model = model_for(logs)
    model.refresh()
    [first] = model.rows_after(0)
    assert first.beat is None and first.verify == "not_checked" and first.decision == "verified"
    result_file(logs, "forge.json", kind="forge", algorithm="ML-DSA-65", result="broken", entry=1, detail="x")
    import os
    os.utime(logs.verify_dir / "forge.json", ns=(1, 1))
    model.refresh()
    [second] = model.rows_after(first.seq)
    assert (second.id, second.beat) == (first.id, "forge_fails_mldsa")


def test_a_shadow_mode_allow_is_never_allow_after_fix(tmp_path):
    """2026-11-25 m2 keeper: a deny of the tool in an earlier run, then module 2's shadow send. The gateway forwards
    every call in shadow mode, so the send's allow follows no fix and read 'Allow after the fix' wrongly."""
    logs = LabLogs(tmp_path)
    step(logs, "finmail__send_email", "deny", reason_codes=["external_recipient"])
    req = step(logs, "finmail__send_email", "allow", session_id=SESSION_B)
    applied(logs, req, "shadow_decision", "allow", "allow")
    assert "allow_after_fix" not in painted(logs)
