"""evaluate_step hands the two tool methods to OPA only when ACS_POLICY_BACKEND=opa, and nothing changes otherwise.

main() loads the OPA settings once, into example_guardian.OPA_CONFIG. The OPA input document and verdict shape
are a lab convention until issue #531 settles the OPA binding.
"""
from __future__ import annotations

import subprocess
import sys
import threading

import pytest

from acs.guardian import example_guardian, opa_backend
from acs.guardian.opa_backend import OpaConfig
from opa_stub import StubOpa

REQUEST_ID = "11111111-1111-4111-8111-111111111111"
CHAIN = "c" * 64
METADATA = {"agent_id": "lab", "session_id": "22222222-2222-4222-8222-222222222222", "platform": "lab"}
RESULT = {"tool": {"name": "get_vendor_details"}, "exit_status": "success",
          "outputs": [{"value": {"bank_account_number": "111"}}]}
LISTING = {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls -la"}}}
DENY = {"decision": "deny", "reasoning": "secret in output", "reason_codes": ["sensitive_field_redacted"]}
ALLOW = {"decision": "allow"}


def _step(method: str, payload: dict) -> dict:
    params = {"request_id": REQUEST_ID, "metadata": METADATA, "payload": payload}
    return example_guardian.evaluate_step(method, params, REQUEST_ID, CHAIN)


@pytest.fixture
def no_backend(monkeypatch):
    for name in ("ACS_POLICY_BACKEND", "ACS_OPA_URL", "ACS_OPA_TIMEOUT_MS", "ACS_ALLOW_SUBAGENT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(example_guardian, "OPA_CONFIG", None)
    return monkeypatch


@pytest.fixture
def opa_on(no_backend):
    """Point the Guardian at a stub OPA, as main() does after loading the settings once."""
    def start(opa: StubOpa) -> None:
        no_backend.setenv("ACS_POLICY_BACKEND", "opa")
        no_backend.setattr(example_guardian, "OPA_CONFIG", OpaConfig(url=opa.url, timeout_s=0.5))
    return start


@pytest.mark.parametrize("value,requested", [(None, False), ("", False), ("  ", False), ("opa", True),
                                             (" OPA ", True), ("rego", True)])
def test_one_function_decides_whether_a_policy_backend_is_requested(value, requested):
    # main() and every step use this one rule. An unknown name counts as requested, so it fails closed.
    env = {} if value is None else {"ACS_POLICY_BACKEND": value}
    assert example_guardian.policy_backend_requested(env) is requested


def test_without_a_backend_a_tool_result_is_informational_and_opa_is_never_called(no_backend):
    with StubOpa(DENY) as opa:
        no_backend.setenv("ACS_OPA_URL", opa.url)
        assert _step("steps/toolCallResult", RESULT)["decision"] == "allow"
        assert _step("steps/toolCallRequest", LISTING)["decision"] == "allow"
    assert opa.inputs == []
    assert "steps/toolCallResult" in example_guardian.INFORMATIONAL_METHODS


def test_the_default_path_never_imports_the_opa_backend():
    code = ("import sys; import acs.guardian.example_guardian; "
            "print('acs.guardian.opa_backend' in sys.modules)")
    env = {"PATH": "", "ACS_GUARDIAN_STATE_DIR": ""}
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, check=True)
    assert out.stdout.strip() == "False"


def test_under_opa_a_tool_result_is_judged(opa_on):
    with StubOpa(DENY) as opa:
        opa_on(opa)
        result = _step("steps/toolCallResult", RESULT)
    assert result == {"type": "final", "acs_version": example_guardian.ACS_VERSION, "request_id": REQUEST_ID,
                      "chain_hash": CHAIN, **DENY}
    assert [doc["input"]["method"] for doc in opa.inputs] == ["steps/toolCallResult"]


def test_under_opa_the_policy_decides_a_tool_call_the_built_in_rules_allow(opa_on):
    with StubOpa(DENY) as opa:
        opa_on(opa)
        assert _step("steps/toolCallRequest", LISTING)["decision"] == "deny"
    assert opa.inputs[0]["input"]["payload"] == LISTING


def test_steps_never_reparse_the_settings(opa_on, monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("load_config ran during a step")
    monkeypatch.setattr(opa_backend, "load_config", fail)
    monkeypatch.setattr(opa_backend, "backend_problem", fail)
    with StubOpa(ALLOW) as opa:
        opa_on(opa)
        for _ in range(3):
            assert _step("steps/toolCallResult", RESULT)["decision"] == "allow"


@pytest.mark.parametrize("method", ["steps/sessionStart", "steps/userMessage", "steps/subagentStart"])
def test_under_opa_other_methods_keep_todays_handling(opa_on, method):
    with StubOpa(DENY) as opa:
        opa_on(opa)
        expected = "deny" if method == "steps/subagentStart" else "allow"
        assert _step(method, {})["decision"] == expected
    assert opa.inputs == []


@pytest.mark.parametrize("name", ["opa", "rego"])
def test_a_backend_named_but_never_loaded_denies_both_tool_methods(no_backend, name):
    # main() refuses to start on a bad setting. This backstop covers a caller that skipped main().
    no_backend.setenv("ACS_POLICY_BACKEND", name)
    for method, payload in (("steps/toolCallRequest", LISTING), ("steps/toolCallResult", RESULT)):
        result = _step(method, payload)
        assert (result["decision"], result["reason_codes"]) == ("deny", ["policy_backend_misconfigured"])


def _run_main(monkeypatch) -> list[int]:
    monkeypatch.setenv("ACS_HMAC_SECRET", "guardian-opa-test-secret-32-bytes-long")
    monkeypatch.setenv("ACS_HMAC_KEY_ID", "test-key")
    monkeypatch.delenv("ACS_HMAC_SECRET_FILE", raising=False)
    monkeypatch.setattr(sys, "argv", ["acs-example-guardian", "--port", "0"])
    # A Guardian that starts anyway serves forever, so main runs on a daemon thread with a deadline.
    box: list[int] = []
    runner = threading.Thread(target=lambda: box.append(example_guardian.main()), daemon=True)
    runner.start()
    runner.join(5.0)
    return box


@pytest.mark.parametrize("env", [{"ACS_POLICY_BACKEND": "opa"},
                                 {"ACS_POLICY_BACKEND": "opa", "ACS_OPA_URL": "file:///etc/passwd"},
                                 {"ACS_POLICY_BACKEND": "opa", "ACS_OPA_URL": "http://[::1/x"},
                                 {"ACS_POLICY_BACKEND": "rego", "ACS_OPA_URL": "http://127.0.0.1:1/x"}])
def test_the_guardian_refuses_to_start_with_a_misconfigured_backend(no_backend, capsys, env):
    for name, value in env.items():
        no_backend.setenv(name, value)
    assert _run_main(no_backend) == [1], "the Guardian started with a misconfigured policy backend"
    assert "REFUSING TO START" in capsys.readouterr().err
    assert example_guardian.OPA_CONFIG is None


@pytest.mark.parametrize("payload,code", [
    ({"tool": {"name": "Bash"}, "arguments": {"command": {"value": "rm -rf /"}}}, "destructive_command"),
    ({"tool": {"name": "shell"}, "arguments": {"command": {"value": "echo " + "a" * 9000}}}, "input_too_large"),
    ({"tool": {"name": "Task"}, "arguments": {}}, "subagent_gated"),
    ({"tool": {"name": "Write"}, "arguments": {"file_path": {"value": "/etc/passwd"}}}, "protected_path"),
])
def test_built_in_hard_denies_hold_under_opa_even_when_the_policy_allows(opa_on, payload, code):
    with StubOpa(ALLOW) as opa:
        opa_on(opa)
        result = _step("steps/toolCallRequest", payload)
    assert (result["decision"], result["reason_codes"]) == ("deny", [code])
    assert opa.inputs == [], "OPA decides only what the built-in rules allow"
