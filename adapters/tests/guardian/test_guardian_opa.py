"""evaluate_step hands the two tool methods to OPA only when settings were loaded, and nothing changes otherwise.

The backend name is read once, at import, into example_guardian.POLICY_BACKEND_NAME, and main() loads its settings
into example_guardian.OPA_CONFIG. Steps follow those two, never the live environment. The built-in hard denies run
first under every backend. The OPA input document and verdict shape are a lab convention until issue #531 settles
the OPA binding.
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
    monkeypatch.setattr(example_guardian, "POLICY_BACKEND_NAME", "")
    return monkeypatch


@pytest.fixture
def opa_on(no_backend):
    """Point the Guardian at a stub OPA, as main() does after loading the settings once."""
    def start(opa: StubOpa) -> None:
        no_backend.setattr(example_guardian, "OPA_CONFIG", OpaConfig(url=opa.url, timeout_s=0.5))
    return start


@pytest.mark.parametrize("value,requested", [(None, False), ("", False), ("  ", False), ("opa", True),
                                             (" OPA ", True), ("rego", True)])
def test_one_function_decides_whether_a_policy_backend_is_requested(value, requested):
    # main() and every step use this one rule. An unknown name counts as requested, so it fails closed.
    env = {} if value is None else {"ACS_POLICY_BACKEND": value}
    assert bool(example_guardian.policy_backend_name(env)) is requested


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


def test_clearing_the_variable_after_startup_changes_nothing(opa_on, no_backend):
    # The loaded configuration decides. A later change to the environment must not switch OPA off.
    with StubOpa(DENY) as opa:
        opa_on(opa)
        no_backend.delenv("ACS_POLICY_BACKEND", raising=False)
        assert _step("steps/toolCallResult", RESULT)["decision"] == "deny"
    assert len(opa.inputs) == 1


def test_setting_the_variable_after_startup_changes_nothing(no_backend):
    with StubOpa(DENY) as opa:
        no_backend.setenv("ACS_POLICY_BACKEND", "opa")
        no_backend.setenv("ACS_OPA_URL", opa.url)
        assert _step("steps/toolCallResult", RESULT)["decision"] == "allow"
    assert opa.inputs == []


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
    # The backend name is read once, at import. The test stands in for a Guardian imported with this environment.
    no_backend.setattr(example_guardian, "POLICY_BACKEND_NAME", env["ACS_POLICY_BACKEND"])
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


TYPE_ERRORS = [
    {"tool": {"name": "Bash"}, "arguments": {"command": {"value": ["rm", "-rf", "/"]}}},
    {"tool": {"name": "shell"}, "arguments": {"command": {"value": {"cmd": "ls"}}}},
    {"tool": {"name": "Write"}, "arguments": {"file_path": {"value": 42}}},
    {"tool": {"name": "Bash"}, "arguments": {"command": {"value": 0}}},
    {"tool": {"name": "Bash"}, "arguments": {"command": {"value": False}}},
    {"tool": {"name": 42}, "arguments": {}},
    {"tool": {"name": ["Bash"]}, "arguments": {}},
    {"tool": "Bash", "arguments": {}},
    {"tool": {"name": "Bash"}, "arguments": ["rm", "-rf", "/"]},
    {"tool": {"name": "Bash"}, "arguments": "rm -rf /"},
]


@pytest.mark.parametrize("payload", [
    {"tool": {"name": "Bash"}, "arguments": {"command": {"value": None}}},
    {"tool": {"name": "Write"}, "arguments": {"file_path": {"value": None}}},
    {"tool": {"name": "Write"}, "arguments": {}},
])
def test_a_null_argument_reads_as_absent(no_backend, payload):
    # The same answer as a missing argument, for every argument a hard deny reads.
    assert _step("steps/toolCallRequest", payload)["decision"] == "allow"


@pytest.mark.parametrize("payload", TYPE_ERRORS)
def test_a_non_string_argument_a_hard_deny_reads_denies_under_opa(opa_on, payload):
    with StubOpa(ALLOW) as opa:
        opa_on(opa)
        result = _step("steps/toolCallRequest", payload)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["argument_type_invalid"])
    assert opa.inputs == []


@pytest.mark.parametrize("payload", TYPE_ERRORS)
def test_a_non_string_argument_a_hard_deny_reads_denies_without_a_backend(no_backend, payload):
    result = _step("steps/toolCallRequest", payload)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["argument_type_invalid"])


WRITE_TMP = {"tool": {"name": "Write"}, "arguments": {"file_path": {"value": "/tmp/notes.txt"},
                                                      "content": {"value": "x"}}}


def _modify(**modifications) -> dict:
    return {"decision": "modify", "reasoning": "rewritten by policy", "modifications": modifications}


@pytest.mark.parametrize("payload,verdict,code", [
    (LISTING, _modify(parameter_overrides={"command": "rm -rf /"}), "destructive_command"),
    # Overrides are raw tool values, as the Claude Code and Cursor adapters apply them. A dict is not a command.
    (LISTING, _modify(parameter_overrides={"command": {"value": "ls"}}), "argument_type_invalid"),
    (LISTING, _modify(parameter_overrides={"command": ["rm", "-rf", "/"]}), "argument_type_invalid"),
    (WRITE_TMP, _modify(parameter_overrides={"file_path": "/etc/passwd"}), "protected_path"),
    (LISTING, _modify(redactions=[{"path": "/arguments/command/value", "replacement": "rm -rf /"}]),
     "destructive_command"),
])
def test_a_modify_that_rewrites_arguments_is_checked_against_the_hard_denies(opa_on, payload, verdict, code):
    with StubOpa(verdict) as opa:
        opa_on(opa)
        result = _step("steps/toolCallRequest", payload)
    assert (result["decision"], result["reason_codes"]) == ("deny", [code])


def test_a_harmless_rewrite_stays_a_modify(opa_on):
    verdict = _modify(parameter_overrides={"command": "ls -l"})
    with StubOpa(verdict) as opa:
        opa_on(opa)
        result = _step("steps/toolCallRequest", LISTING)
    assert (result["decision"], result["modifications"]) == ("modify", verdict["modifications"])



def _handle(monkeypatch, payload: dict) -> tuple[dict, str]:
    """One step through handle_request with the request-side checks stubbed, so only the Guardian's own answer can
    fail to sign. A signed request can't carry a lone surrogate, so this is the only way to put one in a decision."""
    from acs.testing.harness import make_envelope
    monkeypatch.setenv("ACS_HMAC_SECRET", "guardian-opa-test-secret-32-bytes-long")
    monkeypatch.setenv("ACS_HMAC_KEY_ID", "test-key")
    monkeypatch.delenv("ACS_HMAC_SECRET_FILE", raising=False)
    for name in ("check_signature", "check_skew", "check_replay", "check_nonce"):
        monkeypatch.setattr(example_guardian, name, lambda *args, **kwargs: None)
    monkeypatch.setattr(example_guardian, "append_to_chain", lambda *args, **kwargs: CHAIN)
    # The request's own canonical form feeds the chain. A signed request always has one, so it is stubbed too.
    monkeypatch.setattr(example_guardian, "jcs_canonicalize", lambda value: b"{}")
    monkeypatch.setattr(example_guardian, "_SPEC_VALIDATION_AVAILABLE", False)
    request = make_envelope("steps/toolCallRequest", payload)
    return example_guardian.handle_request(request), request["params"]["metadata"]["session_id"]


def _assert_signed_unsignable_deny(response: dict, session_id: str) -> None:
    from acs.client import verify_signature
    result = response["result"]
    assert (result["decision"], result["reason_codes"]) == ("deny", ["response_not_signable"])
    assert result["reasoning"].isascii()
    assert verify_signature(response, session_id=session_id)


def test_a_lone_surrogate_in_a_file_path_is_a_signed_deny(no_backend):
    payload = {"tool": {"name": "Write"}, "arguments": {"file_path": {"value": "/etc/x\ud800"}}}
    _assert_signed_unsignable_deny(*_handle(no_backend, payload))


@pytest.mark.parametrize("number", [b"9007199254740993", b"-9007199254740993", b"1e400"])
def test_an_opa_number_the_guardian_cannot_sign_is_a_signed_deny(opa_on, no_backend, number):
    body = b'{"result": {"decision": "allow", "policy_data": {"n": ' + number + b"}}}"
    with StubOpa(body=body) as opa:
        opa_on(opa)
        _assert_signed_unsignable_deny(*_handle(no_backend, LISTING))



def test_a_modify_cannot_rename_the_tool_after_the_hard_denies_ran(opa_on):
    payload = {"tool": {"name": "noop"}, "arguments": {"command": {"value": "rm -rf /"}}}
    verdict = _modify(redactions=[{"path": "/tool/name", "replacement": "Bash"}])
    with StubOpa(verdict) as opa:
        opa_on(opa)
        result = _step("steps/toolCallRequest", payload)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["opa_verdict_invalid"])




def test_the_recheck_copies_only_the_arguments(opa_on, monkeypatch):
    copied = []
    real_deepcopy = example_guardian.copy.deepcopy

    def recording_deepcopy(value, *args, **kwargs):
        copied.append(value)
        return real_deepcopy(value, *args, **kwargs)
    monkeypatch.setattr(example_guardian.copy, "deepcopy", recording_deepcopy)
    payload = {**LISTING, "context": {"history": ["x"] * 1000}}
    verdict = _modify(parameter_overrides={"command": "ls -l"})
    with StubOpa(verdict) as opa:
        opa_on(opa)
        assert _step("steps/toolCallRequest", payload)["decision"] == "modify"
    assert copied == [LISTING["arguments"]]



def _write(path: str) -> dict:
    return {"tool": {"name": "Write"}, "arguments": {"file_path": {"value": path}}}


SPELLINGS = [("/tmp/../etc/passwd", "protected_path"), ("//etc/passwd", "protected_path"),
             ("///etc/passwd", "protected_path"), ("/etc/./passwd", "protected_path"),
             ("/usr//bin/x", "protected_path"), ("../../etc/passwd", "path_traversal"), ("..", "path_traversal")]


@pytest.mark.parametrize("path,code", SPELLINGS)
def test_a_protected_path_is_caught_in_every_spelling_without_a_backend(no_backend, path, code):
    result = _step("steps/toolCallRequest", _write(path))
    assert (result["decision"], result["reason_codes"]) == ("deny", [code])


@pytest.mark.parametrize("path,code", SPELLINGS)
def test_a_protected_path_is_caught_in_every_spelling_under_opa(opa_on, path, code):
    with StubOpa(ALLOW) as opa:
        opa_on(opa)
        result = _step("steps/toolCallRequest", _write(path))
    assert (result["decision"], result["reason_codes"]) == ("deny", [code])
    assert opa.inputs == []


@pytest.mark.parametrize("path,code", SPELLINGS)
def test_a_rewrite_to_a_protected_path_is_caught_in_every_spelling(opa_on, path, code):
    with StubOpa(_modify(parameter_overrides={"file_path": path})) as opa:
        opa_on(opa)
        result = _step("steps/toolCallRequest", WRITE_TMP)
    assert (result["decision"], result["reason_codes"]) == ("deny", [code])


@pytest.mark.parametrize("path", ["/tmp/notes.txt", "notes/../todo.txt", "./notes.txt", "/tmp/etc/passwd"])
def test_an_ordinary_path_still_writes(no_backend, path):
    assert _step("steps/toolCallRequest", _write(path))["decision"] == "allow"



WRITE_CAPABLE = [
    ("Write", "file_path"), ("Edit", "file_path"), ("MultiEdit", "file_path"),
    ("NotebookEdit", "notebook_path"), ("edit", "file_path"), ("write", "file_path"),
    ("Delete", "file_path"), ("delete", "path"), ("Remove", "path"), ("Move", "target_file"),
    ("Rename", "path"), ("Write", "path"), ("Edit", "target_file"),
]


@pytest.mark.parametrize("tool,argument", WRITE_CAPABLE)
@pytest.mark.parametrize("path,code", [("/etc/passwd", "protected_path"), ("../../etc/passwd", "path_traversal")])
def test_every_write_capable_tool_meets_the_path_denies_without_a_backend(no_backend, tool, argument, path, code):
    payload = {"tool": {"name": tool}, "arguments": {argument: {"value": path}}}
    result = _step("steps/toolCallRequest", payload)
    assert (result["decision"], result["reason_codes"]) == ("deny", [code])


@pytest.mark.parametrize("tool,argument", WRITE_CAPABLE)
def test_every_write_capable_tool_meets_the_path_denies_under_opa(opa_on, tool, argument):
    payload = {"tool": {"name": tool}, "arguments": {argument: {"value": "/etc/passwd"}}}
    with StubOpa(ALLOW) as opa:
        opa_on(opa)
        result = _step("steps/toolCallRequest", payload)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["protected_path"])
    assert opa.inputs == []


def test_a_notebook_path_of_the_wrong_type_denies(no_backend):
    payload = {"tool": {"name": "NotebookEdit"}, "arguments": {"notebook_path": {"value": 7}}}
    result = _step("steps/toolCallRequest", payload)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["argument_type_invalid"])



ALIASES = ["/private/etc/passwd", "/ETC/passwd", "/Etc/hosts", "/USR/bin/x", "/proc/self/root/etc/passwd",
           "/proc/1/mem", "/private/../private/etc/sudoers", "/System/Volumes/Data/private/etc/passwd",
           "/System/Volumes/Data/usr/local/bin/x", "/system/volumes/data/etc/hosts"]


@pytest.mark.parametrize("path", ALIASES)
def test_a_protected_path_is_caught_under_its_aliases_without_a_backend(no_backend, path):
    result = _step("steps/toolCallRequest", _write(path))
    assert (result["decision"], result["reason_codes"]) == ("deny", ["protected_path"])


@pytest.mark.parametrize("path", ALIASES)
def test_a_protected_path_is_caught_under_its_aliases_under_opa(opa_on, path):
    with StubOpa(ALLOW) as opa:
        opa_on(opa)
        result = _step("steps/toolCallRequest", _write(path))
    assert (result["decision"], result["reason_codes"]) == ("deny", ["protected_path"])



@pytest.mark.parametrize("field", ["tool", "arguments"])
@pytest.mark.parametrize("value", [[], "", 0, False, None])
def test_a_present_falsy_tool_or_arguments_denies(no_backend, field, value):
    payload = {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls"}}, field: value}
    result = _step("steps/toolCallRequest", payload)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["argument_type_invalid"])


def test_absent_tool_and_arguments_keep_todays_answer(no_backend):
    assert _step("steps/toolCallRequest", {})["decision"] == "allow"



@pytest.mark.parametrize("name", ["opa", "rego"])
def test_a_backend_named_at_import_without_a_loaded_config_denies(no_backend, name):
    # A Guardian served without main() must not fail open when the environment asked for a policy backend.
    no_backend.setattr(example_guardian, "POLICY_BACKEND_NAME", name)
    for method, payload in (("steps/toolCallRequest", LISTING), ("steps/toolCallResult", RESULT)):
        result = _step(method, payload)
        assert (result["decision"], result["reason_codes"]) == ("deny", ["policy_backend_misconfigured"])


def test_the_backend_name_is_read_once_at_import():
    code = ("import os; os.environ['ACS_POLICY_BACKEND'] = 'opa'; "
            "from acs.guardian import example_guardian as g; "
            "del os.environ['ACS_POLICY_BACKEND']; "
            "p = {'request_id': 'r', 'metadata': {}, 'payload': {'tool': {'name': 'ls'}, 'arguments': {}}}; "
            "print(g.evaluate_step('steps/toolCallRequest', p, 'r', 'c' * 64)['reason_codes'])")
    env = {"PATH": "", "ACS_GUARDIAN_STATE_DIR": ""}
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, check=True)
    assert out.stdout.strip() == "['policy_backend_misconfigured']"



def test_a_signing_failure_other_than_canonicalization_is_not_relabeled(no_backend, monkeypatch):
    # Only an encoding failure becomes response_not_signable. Anything else is a bug and propagates as before.
    calls = []
    real_sign = example_guardian.sign_envelope

    def first_call_breaks(envelope, **kwargs):
        # The first call fails with a non-encoding error, and a retry would succeed, so a relabel would show.
        calls.append(1)
        if len(calls) == 1:
            raise KeyError("signing key")
        return real_sign(envelope, **kwargs)
    monkeypatch.setattr(example_guardian, "sign_envelope", first_call_breaks)
    with pytest.raises(KeyError):
        _handle(no_backend, LISTING)



def test_a_result_nested_past_the_recursion_limit_is_a_signed_deny(no_backend, monkeypatch):
    # JCS recurses, so a result this deep raises RecursionError at signing. It must not drop the connection.
    deep: dict = {}
    for _ in range(sys.getrecursionlimit() + 100):
        deep = {"n": deep}

    def nested_allow(method, params, request_id, chain_hash):
        return {"type": "final", "acs_version": example_guardian.ACS_VERSION, "request_id": request_id,
                "chain_hash": chain_hash, "decision": "allow", "policy_data": deep}
    monkeypatch.setattr(example_guardian, "evaluate_step", nested_allow)
    _assert_signed_unsignable_deny(*_handle(no_backend, LISTING))


def test_the_canonicalization_errors_cover_every_jcs_failure():
    from acs.core import jcs_canonicalize
    from acs.core._canonical import CANONICALIZATION_ERRORS
    assert RecursionError in CANONICALIZATION_ERRORS and UnicodeEncodeError in CANONICALIZATION_ERRORS
    for value in (2**53 + 1, float("nan"), "x\ud800"):
        with pytest.raises(CANONICALIZATION_ERRORS):
            jcs_canonicalize({"v": value})




@pytest.mark.parametrize("at_import,live", [("", "opa"), ("opa", ""), ("opa", "rego")])
def test_the_guardian_refuses_to_start_when_the_backend_changed_after_import(no_backend, capsys, at_import, live):
    no_backend.setattr(example_guardian, "POLICY_BACKEND_NAME", at_import)
    if live:
        no_backend.setenv("ACS_POLICY_BACKEND", live)
    assert _run_main(no_backend) == [1], "the Guardian started with a backend that changed after import"
    assert "changed after import" in capsys.readouterr().err



def _nested_request(depth: int, monkeypatch) -> dict:
    """A request the test client signs for real, with a value nested depth levels inside its arguments."""
    from acs.testing.harness import make_envelope, signing_env
    for name, value in signing_env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ACS_HMAC_SECRET_FILE", raising=False)
    deep: list = []
    for _ in range(depth):
        deep = [deep]
    return make_envelope("steps/toolCallRequest", {"tool": {"name": "ls"}, "arguments": {"x": {"value": deep}}},
                         sign_with_secret=signing_env()["ACS_HMAC_SECRET"])


def test_a_signed_request_past_the_depth_bound_is_refused_before_any_state_changes(no_backend):
    # The client signs 900 levels, well past the bound, so this request is genuine and only the bound refuses it.
    # Errors are signed per spec section 10 (fix round 10, which reverses round 9's unsigned answer).
    from acs.client import verify_signature
    request = _nested_request(example_guardian.MAX_REQUEST_DEPTH + 50, no_backend)
    session_id = request["params"]["metadata"]["session_id"]
    response = example_guardian.handle_request(request)
    assert response["error"]["code"] == -32600
    assert "deeper than" in response["error"]["message"]
    assert verify_signature(response, session_id=session_id)
    state = example_guardian.STATE.get(session_id)
    assert (state.previous_hash, state.seen_request_ids, state.seen_nonces) == (None, {}, {})


def test_a_signed_request_under_the_depth_bound_gets_a_decision(no_backend):
    request = _nested_request(example_guardian.MAX_REQUEST_DEPTH - 20, no_backend)
    assert example_guardian.handle_request(request)["result"]["decision"] == "allow"


@pytest.mark.parametrize("error,word", [(RecursionError("deep"), "recursion"), (UnicodeEncodeError("utf-8", "x", 0, 1, "bad"), None)])
def test_the_last_resort_guard_names_the_cause_accurately(no_backend, monkeypatch, error, word):
    request = _nested_request(3, no_backend)

    def fail(value):
        raise error
    monkeypatch.setattr(example_guardian, "jcs_canonicalize", fail)
    message = example_guardian.handle_request(request)["error"]["message"]
    assert "could not be canonicalized" in message and "nested" not in message
    assert (word in message) if word else ("recursion" not in message)


def test_the_last_resort_guard_answers_signed(no_backend, monkeypatch):
    # Signed per spec section 10 (fix round 10). If even this error couldn't be signed, do_POST's floor answers.
    from acs.client import verify_signature
    request = _nested_request(3, no_backend)
    monkeypatch.setattr(example_guardian, "jcs_canonicalize", lambda value: (_ for _ in ()).throw(RecursionError()))
    response = example_guardian.handle_request(request)
    assert response["error"]["code"] == -32600 and response["id"] == request["id"]
    assert verify_signature(response, session_id=request["params"]["metadata"]["session_id"])



@pytest.mark.parametrize("tool,arguments", [
    ("Move", {"source": "/tmp/payload", "destination": "/etc/cron.d/x"}),
    ("Rename", {"path": "/tmp/payload", "new_path": "/etc/sudoers"}),
    ("move", {"path": "/tmp/payload", "target": "/usr/bin/ls"}),
    ("Rename", {"from": "/tmp/payload", "to": "/etc/passwd"}),
])
def test_a_move_or_rename_into_a_protected_path_denies(no_backend, tool, arguments):
    payload = {"tool": {"name": tool}, "arguments": {k: {"value": v} for k, v in arguments.items()}}
    result = _step("steps/toolCallRequest", payload)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["protected_path"])



@pytest.mark.parametrize("derivation", [["fresh"], {"x": 1}, 7, True])
def test_a_non_string_intent_derivation_denies(no_backend, derivation):
    result = _step("steps/subagentStart", {"intent_derivation": derivation})
    assert (result["decision"], result["reason_codes"]) == ("deny", ["argument_type_invalid"])


def test_an_absent_or_null_intent_derivation_keeps_todays_answer(no_backend):
    for payload in ({}, {"intent_derivation": None}):
        assert _step("steps/subagentStart", payload)["reason_codes"] == ["subagent_gated"]



@pytest.mark.parametrize("path", ["/private/tmp/x", "/var/tmp/x", "/processes.txt",
                                  "/System/Volumes/Data/private/tmp/x", "/etcetera/notes.txt"])
def test_an_unprotected_path_beside_a_protected_one_still_writes(no_backend, path):
    # Prefixes end at a path separator, and only /private/etc is an alias, so these neighbours stay writable.
    assert _step("steps/toolCallRequest", _write(path))["decision"] == "allow"



def _string_literals(source: str) -> list[tuple[str, int]]:
    """String constants in source, docstrings left out, with their line numbers."""
    import ast
    tree = ast.parse(source)
    docstrings = {id(node.body[0].value) for node in ast.walk(tree)
                  if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)) and node.body
                  and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant)}
    return [(node.value, node.lineno) for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings]


def test_the_backend_variable_name_is_defined_once():
    # Every message uses the one constant, so the literal appears only where it is defined.
    from pathlib import Path
    found = [path.name for path in sorted(Path(example_guardian.__file__).parent.glob("*.py"))
             for value, _ in _string_literals(path.read_text(encoding="utf-8")) if "ACS_POLICY_BACKEND" in value]
    assert found == ["_policy_backend.py"]



@pytest.mark.parametrize("path", ["/Volumes/Macintosh HD/etc/passwd", "/tmp/link-to-etc/passwd"])
def test_known_limit_a_symlink_or_firmlink_spelling_passes_the_lexical_check(no_backend, path):
    # Known limit, documented in docs/guardian/README.md: the built-in path denies compare spellings, not files.
    # The Guardian may not share the agent's filesystem, so it can't resolve links, and a policy is the control.
    assert _step("steps/toolCallRequest", _write(path))["decision"] == "allow"



def _file_call(tool: str, **arguments) -> dict:
    return {"tool": {"name": tool}, "arguments": {k: {"value": v} for k, v in arguments.items()}}


@pytest.mark.parametrize("payload", [
    _file_call("Move", source="/etc/passwd", destination="/tmp/x"),
    _file_call("Rename", **{"from": "/etc/hosts", "to": "/tmp/h"}),
    _file_call("rename", old_path="/usr/bin/ls", new_path="/tmp/ls"),
    _file_call("Move", src="/etc/shadow", target="/tmp/s"),
    _file_call("Delete", paths=["/tmp/a", "/etc/passwd"]),
    _file_call("Remove", paths=["/proc/1/mem"]),
])
def test_a_move_out_of_or_a_list_naming_a_protected_path_denies(no_backend, payload):
    result = _step("steps/toolCallRequest", payload)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["protected_path"])


@pytest.mark.parametrize("paths", [["/tmp/a", 3], [None], ["/tmp/a", ["/etc/passwd"]]])
def test_a_path_list_with_a_non_string_item_denies(no_backend, paths):
    result = _step("steps/toolCallRequest", _file_call("Delete", paths=paths))
    assert (result["decision"], result["reason_codes"]) == ("deny", ["argument_type_invalid"])


@pytest.mark.parametrize("payload", [
    _file_call("Delete", target="/etc/passwd"),
    _file_call("Delete", destination="/etc/cron.d/x"),
    _file_call("Remove", source="/usr/bin/ls"),
    _file_call("Write", file_path="/tmp/notes.txt", to="/etc/hosts"),
    # Known over-deny, documented in docs/guardian/README.md: on Edit, target can be ordinary text, and text that
    # names a protected path still denies. That fails closed.
    _file_call("Edit", file_path="/tmp/notes.txt", target="/etc/passwd is the file I mean"),
])
def test_every_path_name_counts_on_every_file_tool(no_backend, payload):
    result = _step("steps/toolCallRequest", payload)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["protected_path"])


@pytest.mark.parametrize("arguments", [{"file_path": []}, {"file_path": ["/tmp/a"]}, {"paths": []},
                                       {"paths": "/tmp/a"}, {"target": ["/tmp/a"]}])
def test_only_paths_takes_a_list_and_it_must_not_be_empty(no_backend, arguments):
    result = _step("steps/toolCallRequest", _file_call("Delete", **arguments))
    assert (result["decision"], result["reason_codes"]) == ("deny", ["argument_type_invalid"])


def test_a_paths_list_of_ordinary_files_still_deletes(no_backend):
    assert _step("steps/toolCallRequest", _file_call("Delete", paths=["/tmp/a", "/tmp/b"]))["decision"] == "allow"

@pytest.mark.parametrize("method", ["steps/toolCallRequest", "steps/toolCallResult", "steps/sessionStart"])
@pytest.mark.parametrize("payload", [[], "", "x", 0, None])
def test_evaluate_step_denies_a_payload_that_is_not_an_object(no_backend, method, payload):
    # Direct callers, such as acs.testing's real_policy_handler and custom deployments, skip read_request.
    params = {"request_id": REQUEST_ID, "metadata": METADATA, "payload": payload}
    result = example_guardian.evaluate_step(method, params, REQUEST_ID, CHAIN)
    assert (result["decision"], result["reason_codes"]) == ("deny", ["argument_type_invalid"])


@pytest.mark.parametrize("payload", [None, []])
def test_real_policy_handler_gets_a_deny_for_a_payload_that_is_not_an_object(no_backend, payload):
    from acs.testing.e2e_report import real_policy_handler
    handler = real_policy_handler(example_guardian.evaluate_step)
    result = handler({"method": "steps/toolCallRequest",
                      "params": {"request_id": REQUEST_ID, "metadata": METADATA, "payload": payload}})
    assert (result["decision"], result["reason_codes"]) == ("deny", ["argument_type_invalid"])
