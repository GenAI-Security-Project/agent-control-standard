"""The OPA backend end to end: acs.client signs a step, the real example Guardian asks a stub OPA, and the
signed decision comes back verified.

The OPA input document and verdict shape are a lab convention until issue #531 settles the OPA binding.
"""
from __future__ import annotations

import copy
import os
import uuid

import pytest

from acs.client import Decided, FailPosture, round_trip
from acs.core import request_envelope
from acs.testing.harness import launch_guardian, signing_env, validate_response_envelope
from opa_stub import StubOpa, closed_port_url

SESSION = "44444444-4444-4444-8444-444444444444"
METADATA = {"agent_id": "finbot", "session_id": SESSION, "platform": "lab"}
# The most permissive posture, so a deny or an ask in these tests comes from the Guardian, never from the client.
PROCEED = FailPosture(deny_on_failure=False, timeout_s=5.0)
VENDOR_RESULT = {"tool": {"name": "get_vendor_details"}, "exit_status": "success",
                 "request_id_ref": "33333333-3333-4333-8333-333333333333",
                 "outputs": [{"value": {"name": "Acme", "bank_account_number": "111-222"}},
                             {"value": {"name": "Beta", "bank_account_number": "333-444"}}]}
TRANSFER = {"tool": {"name": "finstripe__create_transfer", "version": "sha256:ab"},
            "arguments": {"amount": {"value": 9000}, "to": {"value": "acct-1"}}}


@pytest.fixture
def guardian(tmp_path, monkeypatch):
    """Start the example Guardian on the OPA backend, pointed at whatever URL the test passes."""
    started = []
    for name, value in {**signing_env(), "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1"}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ACS_HMAC_SECRET_FILE", raising=False)

    def start(opa_url: str) -> str:
        env = {**os.environ, "ACS_GUARDIAN_STATE_DIR": str(tmp_path / "state"),
               "ACS_POLICY_BACKEND": "opa", "ACS_OPA_URL": opa_url, "ACS_OPA_TIMEOUT_MS": "1000"}
        process, port = launch_guardian(env=env)
        started.append(process)
        return f"http://127.0.0.1:{port}/acs"

    yield start
    for process in started:
        process.terminate()
        process.wait(timeout=5)


def _send(url: str, method: str, payload: dict):
    request = request_envelope(method, request_id=str(uuid.uuid4()), metadata=METADATA, payload=payload)
    sent = copy.deepcopy(request)
    outcome = round_trip(request, guardian_url=url, posture=PROCEED, session_id=SESSION, gate=True)
    assert isinstance(outcome, Decided), outcome
    assert validate_response_envelope(outcome.response) == []
    return sent, outcome.response["result"]


def _apply_redactions(payload: dict, redactions: list[dict]) -> dict:
    """What the lab gateway does with a verified MODIFY (BUILD_PLAN A.4). acs.client carries no applier."""
    redacted = copy.deepcopy(payload)
    for redaction in redactions:
        *parents, leaf = [t.replace("~1", "/").replace("~0", "~") for t in redaction["path"][1:].split("/")]
        node = redacted
        for token in parents:
            node = node[int(token)] if isinstance(node, list) else node[token]
        node[leaf] = redaction.get("replacement", "[REDACTED]")
    return redacted


def test_a_modify_redacts_every_output_of_a_tool_result(guardian):
    verdict = {"decision": "modify", "reasoning": "bank account numbers are withheld",
               "reason_codes": ["sensitive_field_redacted"],
               "modifications": {"redactions": [{"path": f"/outputs/{i}/value/bank_account_number"}
                                                for i in range(len(VENDOR_RESULT["outputs"]))]}}
    with StubOpa(verdict) as opa:
        sent, result = _send(guardian(opa.url), "steps/toolCallResult", VENDOR_RESULT)
    assert opa.inputs == [{"input": {"method": "steps/toolCallResult", "payload": VENDOR_RESULT,
                                     "metadata": sent["params"]["metadata"]}}]
    assert (result["decision"], result["reason_codes"]) == ("modify", ["sensitive_field_redacted"])
    redacted = _apply_redactions(sent["params"]["payload"], result["modifications"]["redactions"])
    assert [o["value"] for o in redacted["outputs"]] == [
        {"name": "Acme", "bank_account_number": "[REDACTED]"},
        {"name": "Beta", "bank_account_number": "[REDACTED]"}]
    assert "111-222" not in repr(redacted) and "333-444" not in repr(redacted)


def test_a_modify_that_redacts_only_the_first_output_is_a_deny(guardian):
    # Issue #469: redacting only the first output let the second one through.
    verdict = {"decision": "modify", "reasoning": "r",
               "modifications": {"redactions": [{"path": "/outputs/0/value/bank_account_number"}]}}
    with StubOpa(verdict) as opa:
        _, result = _send(guardian(opa.url), "steps/toolCallResult", VENDOR_RESULT)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["opa_verdict_invalid"])


def test_one_redaction_passes_when_only_one_output_carries_the_field(guardian):
    payload = {**VENDOR_RESULT, "outputs": [VENDOR_RESULT["outputs"][0], {"value": {"name": "Beta"}}]}
    verdict = {"decision": "modify", "reasoning": "r",
               "modifications": {"redactions": [{"path": "/outputs/0/value/bank_account_number"}]}}
    with StubOpa(verdict) as opa:
        _, result = _send(guardian(opa.url), "steps/toolCallResult", payload)
    assert result["decision"] == "modify"


def test_an_ask_comes_back_as_an_ask(guardian):
    ask_details = {"approver": {"type": "human", "id": "lab-approver"},
                   "question": "Approve a transfer of 9000 to acct-1?", "timeout_seconds": 240}
    verdict = {"decision": "ask", "reasoning": "transfer above the approval threshold",
               "reason_codes": ["payment_over_threshold"], "ask_details": ask_details}
    with StubOpa(verdict) as opa:
        _, result = _send(guardian(opa.url), "steps/toolCallRequest", TRANSFER)
    # D-043: the Guardian owns the ASK timeout. Nothing on this path turns the ask into an allow.
    assert (result["decision"], result["ask_details"]) == ("ask", ask_details)


@pytest.mark.parametrize("verdict,decision", [({"decision": "allow"}, "allow"),
                                              ({"decision": "deny", "reasoning": "no",
                                                "reason_codes": ["external_recipient"]}, "deny")])
def test_allow_and_deny_pass_through(guardian, verdict, decision):
    with StubOpa(verdict) as opa:
        _, result = _send(guardian(opa.url), "steps/toolCallRequest", TRANSFER)
    assert result["decision"] == decision


def test_opa_down_is_a_signed_deny(guardian):
    _, result = _send(guardian(closed_port_url()), "steps/toolCallResult", VENDOR_RESULT)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["opa_unreachable"])


@pytest.mark.parametrize("body", [
    b'{"result": ' + b"[" * 100_000 + b"]" * 100_000 + b"}",
    b'{"result": {"decision": "allow", "policy_data": ' + b'{"n": ' * 900 + b"{}" + b"}" * 900 + b"}}",
])
def test_a_deeply_nested_opa_answer_is_a_signed_deny(guardian, body):
    with StubOpa(body=body) as opa:
        _, result = _send(guardian(opa.url), "steps/toolCallRequest", TRANSFER)
    assert result["decision"] == "deny"
    assert result["reason_codes"][0] in ("opa_response_malformed", "opa_verdict_invalid")
