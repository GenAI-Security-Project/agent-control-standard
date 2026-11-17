"""evaluate_step hands the two tool methods to OPA only when ACS_POLICY_BACKEND=opa, and nothing changes otherwise.

The OPA input document and verdict shape are a lab convention until issue #531 settles the OPA binding.
"""
from __future__ import annotations

import sys
import threading

import pytest

from acs.guardian import example_guardian
from opa_stub import StubOpa

REQUEST_ID = "11111111-1111-4111-8111-111111111111"
CHAIN = "c" * 64
METADATA = {"agent_id": "lab", "session_id": "22222222-2222-4222-8222-222222222222", "platform": "lab"}
RESULT = {"tool": {"name": "get_vendor_details"}, "exit_status": "success",
          "outputs": [{"value": {"bank_account_number": "111"}}]}
BASH = {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "rm -rf /"}}}
DENY = {"decision": "deny", "reasoning": "secret in output", "reason_codes": ["sensitive_field_redacted"]}
ALLOW = {"decision": "allow"}


def _step(method: str, payload: dict) -> dict:
    params = {"request_id": REQUEST_ID, "metadata": METADATA, "payload": payload}
    return example_guardian.evaluate_step(method, params, REQUEST_ID, CHAIN)


@pytest.fixture
def no_backend(monkeypatch):
    for name in ("ACS_POLICY_BACKEND", "ACS_OPA_URL", "ACS_OPA_TIMEOUT_MS"):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_without_a_backend_a_tool_result_is_informational_and_opa_is_never_called(no_backend):
    with StubOpa(DENY) as opa:
        no_backend.setenv("ACS_OPA_URL", opa.url)
        assert _step("steps/toolCallResult", RESULT)["decision"] == "allow"
        assert _step("steps/toolCallRequest", BASH)["reason_codes"] == ["destructive_command"]
    assert opa.inputs == []
    assert "steps/toolCallResult" in example_guardian.INFORMATIONAL_METHODS


def test_under_opa_a_tool_result_is_judged(no_backend):
    with StubOpa(DENY) as opa:
        no_backend.setenv("ACS_POLICY_BACKEND", "opa")
        no_backend.setenv("ACS_OPA_URL", opa.url)
        result = _step("steps/toolCallResult", RESULT)
    assert result == {"type": "final", "acs_version": example_guardian.ACS_VERSION, "request_id": REQUEST_ID,
                      "chain_hash": CHAIN, **DENY}
    assert [doc["input"]["method"] for doc in opa.inputs] == ["steps/toolCallResult"]


def test_under_opa_the_policy_decides_a_tool_call_instead_of_the_built_in_rules(no_backend):
    with StubOpa(ALLOW) as opa:
        no_backend.setenv("ACS_POLICY_BACKEND", "opa")
        no_backend.setenv("ACS_OPA_URL", opa.url)
        assert _step("steps/toolCallRequest", BASH)["decision"] == "allow"
    assert opa.inputs[0]["input"]["payload"] == BASH


@pytest.mark.parametrize("method", ["steps/sessionStart", "steps/userMessage", "steps/subagentStart"])
def test_under_opa_other_methods_keep_todays_handling(no_backend, method):
    with StubOpa(DENY) as opa:
        no_backend.setenv("ACS_POLICY_BACKEND", "opa")
        no_backend.setenv("ACS_OPA_URL", opa.url)
        no_backend.delenv("ACS_ALLOW_SUBAGENT", raising=False)
        expected = "deny" if method == "steps/subagentStart" else "allow"
        assert _step(method, {})["decision"] == expected
    assert opa.inputs == []


@pytest.mark.parametrize("env", [{"ACS_POLICY_BACKEND": "opa"},
                                 {"ACS_POLICY_BACKEND": "opa", "ACS_OPA_URL": "file:///etc/passwd"},
                                 {"ACS_POLICY_BACKEND": "rego", "ACS_OPA_URL": "http://127.0.0.1:1/x"}])
def test_a_misconfigured_backend_denies_both_tool_methods(no_backend, env):
    for name, value in env.items():
        no_backend.setenv(name, value)
    for method, payload in (("steps/toolCallRequest", {"tool": {"name": "ls"}}), ("steps/toolCallResult", RESULT)):
        result = _step(method, payload)
        assert (result["decision"], result["reason_codes"]) == ("deny", ["policy_backend_misconfigured"])


def test_the_guardian_refuses_to_start_with_a_misconfigured_backend(no_backend, capsys):
    no_backend.setenv("ACS_HMAC_SECRET", "guardian-opa-test-secret-32-bytes-long")
    no_backend.setenv("ACS_HMAC_KEY_ID", "test-key")
    no_backend.delenv("ACS_HMAC_SECRET_FILE", raising=False)
    no_backend.setenv("ACS_POLICY_BACKEND", "opa")
    no_backend.setattr(sys, "argv", ["acs-example-guardian", "--port", "0"])
    # A Guardian that starts anyway serves forever, so main runs on a daemon thread with a deadline.
    box: list[int] = []
    runner = threading.Thread(target=lambda: box.append(example_guardian.main()), daemon=True)
    runner.start()
    runner.join(5.0)
    assert box == [1], "the Guardian started with a misconfigured policy backend"
    assert "ACS_OPA_URL" in capsys.readouterr().err
