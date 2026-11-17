"""The OPA backend end to end: acs.client signs a step, the real example Guardian asks a stub OPA, and the
signed decision comes back verified.

The OPA input document and verdict shape are a lab convention until issue #531 settles the OPA binding.
"""
from __future__ import annotations

import os

import pytest

from acs.testing.harness import launch_guardian, signing_env
from opa_stub import StubOpa, closed_port_url
from round_trip_helpers import TRANSFER, VENDOR_RESULT, apply_redactions, send_step


def test_a_modify_redacts_every_output_of_a_tool_result(guardian):
    verdict = {"decision": "modify", "reasoning": "bank account numbers are withheld",
               "reason_codes": ["sensitive_field_redacted"],
               "modifications": {"redactions": [{"path": f"/outputs/{i}/value/bank_account_number"}
                                                for i in range(len(VENDOR_RESULT["outputs"]))]}}
    with StubOpa(verdict) as opa:
        sent, result = send_step(guardian(opa.url), "steps/toolCallResult", VENDOR_RESULT)
    assert opa.inputs == [{"input": {"method": "steps/toolCallResult", "payload": VENDOR_RESULT,
                                     "metadata": sent["params"]["metadata"]}}]
    assert (result["decision"], result["reason_codes"]) == ("modify", ["sensitive_field_redacted"])
    redacted = apply_redactions(sent["params"]["payload"], result["modifications"]["redactions"])
    assert [o["value"] for o in redacted["outputs"]] == [
        {"name": "Acme", "bank_account_number": "[REDACTED]"},
        {"name": "Beta", "bank_account_number": "[REDACTED]"}]
    assert "111-222" not in repr(redacted) and "333-444" not in repr(redacted)


def test_a_modify_that_redacts_only_the_first_output_is_a_deny(guardian):
    # Issue #469: redacting only the first output let the second one through.
    verdict = {"decision": "modify", "reasoning": "r",
               "modifications": {"redactions": [{"path": "/outputs/0/value/bank_account_number"}]}}
    with StubOpa(verdict) as opa:
        _, result = send_step(guardian(opa.url), "steps/toolCallResult", VENDOR_RESULT)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["opa_verdict_invalid"])


def test_one_redaction_passes_when_only_one_output_carries_the_field(guardian):
    payload = {**VENDOR_RESULT, "outputs": [VENDOR_RESULT["outputs"][0], {"value": {"name": "Beta"}}]}
    verdict = {"decision": "modify", "reasoning": "r",
               "modifications": {"redactions": [{"path": "/outputs/0/value/bank_account_number"}]}}
    with StubOpa(verdict) as opa:
        _, result = send_step(guardian(opa.url), "steps/toolCallResult", payload)
    assert result["decision"] == "modify"


def test_an_ask_comes_back_as_an_ask(guardian):
    ask_details = {"approver": {"type": "human", "id": "lab-approver"},
                   "question": "Approve a transfer of 9000 to acct-1?", "timeout_seconds": 240}
    verdict = {"decision": "ask", "reasoning": "transfer above the approval threshold",
               "reason_codes": ["payment_over_threshold"], "ask_details": ask_details}
    with StubOpa(verdict) as opa:
        _, result = send_step(guardian(opa.url), "steps/toolCallRequest", TRANSFER)
    # D-043: the Guardian owns the ASK timeout. Nothing on this path turns the ask into an allow.
    assert (result["decision"], result["ask_details"]) == ("ask", ask_details)


@pytest.mark.parametrize("verdict,decision", [({"decision": "allow"}, "allow"),
                                              ({"decision": "deny", "reasoning": "no",
                                                "reason_codes": ["external_recipient"]}, "deny")])
def test_allow_and_deny_pass_through(guardian, verdict, decision):
    with StubOpa(verdict) as opa:
        _, result = send_step(guardian(opa.url), "steps/toolCallRequest", TRANSFER)
    assert result["decision"] == decision


def test_opa_down_is_a_signed_deny(guardian):
    _, result = send_step(guardian(closed_port_url()), "steps/toolCallResult", VENDOR_RESULT)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["opa_unreachable"])


@pytest.mark.parametrize("body", [
    b'{"result": ' + b"[" * 100_000 + b"]" * 100_000 + b"}",
    b'{"result": {"decision": "allow", "policy_data": ' + b'{"n": ' * 900 + b"{}" + b"}" * 900 + b"}}",
])
def test_a_deeply_nested_opa_answer_is_a_signed_deny(guardian, body):
    with StubOpa(body=body) as opa:
        _, result = send_step(guardian(opa.url), "steps/toolCallRequest", TRANSFER)
    assert result["decision"] == "deny"
    assert result["reason_codes"][0] in ("opa_response_malformed", "opa_verdict_invalid")


def test_the_startup_log_never_prints_url_userinfo(tmp_path, monkeypatch):
    env = {**os.environ, **signing_env(), "ACS_GUARDIAN_STATE_DIR": str(tmp_path / "state"),
           "ACS_POLICY_BACKEND": "opa", "ACS_OPA_URL": "http://lab:secret-pw@127.0.0.1:1/v1/data/lab/verdict"}
    env.pop("ACS_HMAC_SECRET_FILE", None)
    process, _ = launch_guardian(env=env)
    process.terminate()
    _, stderr = process.communicate(timeout=5)
    assert "127.0.0.1:1/v1/data/lab/verdict" in stderr
    assert "secret-pw" not in stderr


@pytest.mark.parametrize("body", [
    b'{"result": {"decision": "allow", "policy_data": {"n": 9007199254740993}}}',
    b'{"result": {"decision": "allow", "policy_data": {"n": NaN}}}',
])
def test_an_unsignable_number_is_a_signed_deny(guardian, body):
    with StubOpa(body=body) as opa:
        _, result = send_step(guardian(opa.url), "steps/toolCallRequest", TRANSFER)
    assert result["decision"] == "deny"
    assert result["reason_codes"][0] in ("opa_response_malformed", "response_not_signable")
