"""With ACS_RESPONSE_SIGNING=ML-DSA-65 the example Guardian signs every response with its decision key (issue #576).

Requests stay on HMAC. The ServerHello and every error carry ML-DSA-65 signatures too (D-039), except the two
unsigned answers section 10 and the floor leave: -32004 for an unknown request key_id, and do_POST's -32603. A
ClientHello that doesn't offer ML-DSA-65 is refused with -32000 and data.reason unsupported_signature_algorithm.
The handshake fields and the refusal reason are lab conventions until issue #316.
"""
from __future__ import annotations

import json
import os

import pytest

from decision_signing_helpers import KEY_ID, configure_in_process, mldsa_env, require_pqc, signed_hello, signed_step

require_pqc()

from acs.core import REQUEST_DIGEST_FIELD, request_sha256, verify_with_keyring  # noqa: E402
from acs.guardian import example_guardian  # noqa: E402
from acs.testing.harness import launch_guardian, signing_env  # noqa: E402

DENIED = {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "rm -rf /"}}}
ALLOWED = {"tool": {"name": "Bash"}, "arguments": {"command": {"value": "ls -la"}}}
REFUSAL_DATA = {"reason": "unsupported_signature_algorithm"}


@pytest.fixture
def signer(monkeypatch, tmp_path):
    return configure_in_process(monkeypatch, tmp_path)


def assert_ml_dsa(response: dict, request: dict, signer) -> None:
    container = response.get("result") or response.get("error")
    assert container["signature"]["algorithm"] == "ML-DSA-65"
    assert container["signature"]["key_id"] == KEY_ID
    # Lab convention: every ML-DSA-signed response names its request by hash, inside the signed bytes.
    holder = response["result"] if "result" in response else response["error"]["data"]
    assert holder[REQUEST_DIGEST_FIELD] == request_sha256(request)
    assert verify_with_keyring(response, signer.keys.keyring, expected_key_id=KEY_ID, request=request,
                               require_request_digest=True)


def test_server_hello_and_errors_carry_ml_dsa(signer, capsys):
    hello = signed_hello()
    server_hello = example_guardian.handle_request(hello)
    assert "result" in server_hello
    assert_ml_dsa(server_hello, hello, signer)

    invalid = {"jsonrpc": "2.0", "id": "schema-1", "method": "steps/toolCallRequest",
               "params": {"request_id": 5, "metadata": {"session_id": hello["params"]["metadata"]["session_id"]}}}
    schema_error = example_guardian.handle_request(invalid)
    assert schema_error["error"]["code"] == -32600
    assert_ml_dsa(schema_error, invalid, signer)

    step = signed_step("steps/toolCallRequest", ALLOWED)
    example_guardian.handle_request(step)
    replay = example_guardian.handle_request(step)
    assert replay["error"]["code"] == -32005
    assert_ml_dsa(replay, step, signer)

    refused_hello = signed_hello(offered=None)
    refusal = example_guardian.handle_request(refused_hello)
    assert refusal["error"]["code"] == -32000
    assert_ml_dsa(refusal, refused_hello, signer)


def test_decisions_carry_ml_dsa(signer):
    for payload, decision in ((ALLOWED, "allow"), (DENIED, "deny")):
        request = signed_step("steps/toolCallRequest", payload)
        response = example_guardian.handle_request(request)
        assert response["result"]["decision"] == decision
        assert_ml_dsa(response, request, signer)


def test_an_unsignable_decision_falls_back_to_a_signed_deny(signer):
    request = signed_step("steps/toolCallRequest", ALLOWED)
    result = {"type": "final", "acs_version": "0.1.0", "request_id": request["params"]["request_id"],
              "decision": "allow", "reasoning": "lone surrogate \ud800"}
    response = example_guardian._signed_step_response(request["id"], "session", result, request=request)
    assert response["result"]["reason_codes"] == ["response_not_signable"]
    assert_ml_dsa(response, request, signer)


def test_unknown_key_id_stays_unsigned(signer):
    request = signed_step("steps/toolCallRequest", ALLOWED)
    request["params"]["signature"]["key_id"] = "someone-else"
    response = example_guardian.handle_request(request)
    assert response["error"]["code"] == -32004
    assert "signature" not in response["error"]


def test_a_signed_answer_never_carries_another_requests_digest(signer):
    # The digest is set per request, so concurrent or later requests never see an earlier one's.
    first, second = (signed_step("steps/toolCallRequest", ALLOWED) for _ in range(2))
    assert example_guardian.handle_request(first)["result"][REQUEST_DIGEST_FIELD] == request_sha256(first)
    assert example_guardian.handle_request(second)["result"][REQUEST_DIGEST_FIELD] == request_sha256(second)


def test_signing_without_the_request_raises(signer):
    # The hash comes from the request passed in, never from ambient state, so a caller that forgets it fails loudly
    # instead of sending an answer without the hash (review CR4).
    request = signed_step("steps/toolCallRequest", ALLOWED)
    result = {"type": "final", "acs_version": "0.1.0", "request_id": request["params"]["request_id"],
              "decision": "allow"}
    with pytest.raises(example_guardian.SigningUnavailable):
        example_guardian._signed_step_response(request["id"], "session", result)
    with pytest.raises(example_guardian.SigningUnavailable):
        example_guardian._error_envelope(request["id"], "session", -32600, "Invalid Request")
    signed = example_guardian._error_envelope(request["id"], "session", -32600, "Invalid Request", request=request)
    assert_ml_dsa(signed, request, signer)


def test_ping_stays_unsigned(signer):
    ping = {"jsonrpc": "2.0", "id": "p", "method": "system/ping",
            "params": {"request_id": "p", "metadata": {}, "payload": {"echo": "x"}}}
    response = example_guardian.handle_request(ping)
    assert "signature" not in response["result"]


@pytest.mark.parametrize("offered", [None, ["HMAC-SHA256"], "ML-DSA-65", [], ["ml-dsa-65"], [["ML-DSA-65"]]],
                         ids=["absent", "HMAC only", "a string", "empty", "wrong case", "nested"])
def test_hmac_only_client_hello_is_refused(signer, capsys, offered):
    hello = signed_hello(offered=offered)
    response = example_guardian.handle_request(hello)
    assert response["error"]["code"] == -32000
    assert response["error"]["message"] == "SESSION_REFUSED: unsupported_signature_algorithm"
    assert response["error"]["data"] == {**REFUSAL_DATA, REQUEST_DIGEST_FIELD: request_sha256(hello)}
    assert_ml_dsa(response, hello, signer)
    line = capsys.readouterr().err
    assert "[guardian] handshake refused: unsupported_signature_algorithm offered=" in line


def test_an_unauthenticated_client_hello_gets_signature_invalid_first(signer):
    hello = signed_hello(offered=None)
    hello["params"]["signature"]["value"] = "AAAA"
    response = example_guardian.handle_request(hello)
    assert response["error"]["code"] == -32004
    # The signed -32004 names its request, and never states a refusal reason.
    assert set(response["error"]["data"]) == {REQUEST_DIGEST_FIELD}


def test_server_hello_names_the_algorithm(signer):
    response = example_guardian.handle_request(signed_hello(offered=["HMAC-SHA256", "ML-DSA-65"]))
    assert response["result"]["x_acs_lab_response_algorithm"] == "ML-DSA-65"
    assert response["result"]["signature_algorithms_supported"] == ["HMAC-SHA256"]


def assert_floor(response: dict, request: dict) -> None:
    assert response == {"jsonrpc": "2.0", "id": request["id"],
                        "error": {"code": -32603, "message": example_guardian.INTERNAL_ERROR_MESSAGE}}


def test_served_without_main_answers_the_floor(signer, monkeypatch, capsys):
    # Never an HMAC fallback, and never an exception out of handle_request (review CR5).
    monkeypatch.setattr(example_guardian, "DECISION_SIGNER", None)
    request = signed_step("steps/toolCallRequest", ALLOWED)
    assert_floor(example_guardian.handle_request(request), request)
    assert "[guardian] internal error: SigningUnavailable" in capsys.readouterr().err


@pytest.mark.parametrize("moment", ["not_after", "before", "revoked"])
def test_a_key_outside_its_window_never_signs(signer, monkeypatch, capsys, moment):
    # The window and revocation are checked at every signature, not only at startup (review R-I1).
    import dataclasses
    import datetime
    keys = signer.keys
    if moment == "revoked":
        revoked_at = keys.not_before + datetime.timedelta(seconds=1)
        monkeypatch.setattr(example_guardian, "DECISION_SIGNER",
                            dataclasses.replace(signer, keys=dataclasses.replace(keys, revoked_at=revoked_at)))
        now = revoked_at
    else:
        now = keys.not_after if moment == "not_after" else keys.not_before - datetime.timedelta(seconds=1)
    from acs.client import _key_document
    monkeypatch.setattr(_key_document, "utcnow", lambda: now)
    request = signed_step("steps/toolCallRequest", ALLOWED)
    assert_floor(example_guardian.handle_request(request), request)
    err = capsys.readouterr().err
    assert f"[guardian] decision key {KEY_ID} is not live" in err


def test_default_guardian_is_unchanged(monkeypatch):
    for name, value in signing_env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ACS_HMAC_SECRET_FILE", raising=False)
    monkeypatch.setattr(example_guardian, "RESPONSE_SIGNING_NAME", "")
    monkeypatch.setattr(example_guardian, "DECISION_SIGNER", None)
    monkeypatch.setattr(example_guardian, "PERSIST_ENABLED", False)
    response = example_guardian.handle_request(signed_hello())
    assert "x_acs_lab_response_algorithm" not in response["result"]
    assert response["result"]["signature"]["algorithm"] == "HMAC-SHA256"
    step = signed_step("steps/toolCallRequest", ALLOWED)
    example_guardian.handle_request(step)
    replay = example_guardian.handle_request(step)
    assert replay["error"]["signature"]["algorithm"] == "HMAC-SHA256"
    assert "data" not in replay["error"]
    assert REQUEST_DIGEST_FIELD not in response["result"]


def _launch(env: dict) -> tuple:
    return launch_guardian(env={**{k: v for k, v in os.environ.items() if not k.startswith("ACS_")}, **env})


def test_startup_prints_the_fingerprint(tmp_path):
    env = {**mldsa_env(tmp_path), "ACS_GUARDIAN_STATE_DIR": str(tmp_path / "state")}
    process, _ = _launch(env)
    process.terminate()
    _, stderr = process.communicate(timeout=5)
    document = json.loads(open(env["ACS_GUARDIAN_KEYS"], encoding="utf-8").read())
    fingerprint = document["keys"][0]["fingerprint"]
    assert (f"[guardian] decision signing ML-DSA-65 key_id={KEY_ID} fingerprint={fingerprint} "
            "(lab convention, issue #460)") in stderr


@pytest.mark.parametrize("value", ["hybrid", "ML-DSA-65+ECDSA-P256", "ml-dsa-65", "ECDSA-P256"])
def test_unknown_signing_value_refuses_to_start(tmp_path, value):
    env = {**mldsa_env(tmp_path), "ACS_RESPONSE_SIGNING": value, "ACS_GUARDIAN_STATE_DIR": str(tmp_path / "s")}
    with pytest.raises(RuntimeError, match="ACS_RESPONSE_SIGNING"):
        _launch(env)


@pytest.mark.parametrize("name", ["ACS_GUARDIAN_SIGNING_KEY_FILE", "ACS_GUARDIAN_KEY_ID", "ACS_GUARDIAN_KEYS"])
def test_missing_key_settings_refuse_to_start(tmp_path, name):
    env = {**mldsa_env(tmp_path), "ACS_GUARDIAN_STATE_DIR": str(tmp_path / "s")}
    del env[name]
    with pytest.raises(RuntimeError, match=name):
        _launch(env)


@pytest.mark.parametrize("value", ["", "HMAC-SHA256"])
def test_the_off_values_start_an_hmac_guardian(tmp_path, value):
    env = {**signing_env(), "ACS_RESPONSE_SIGNING": value, "ACS_GUARDIAN_STATE_DIR": str(tmp_path / "s")}
    process, _ = _launch(env)
    process.terminate()
    _, stderr = process.communicate(timeout=5)
    assert "decision signing" not in stderr


def test_sign_envelope_is_not_called_with_the_mode_on(signer, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("an HMAC signature on a response with the mode on")
    monkeypatch.setattr(example_guardian, "sign_envelope", refuse)
    example_guardian.handle_request(signed_hello())
    request = signed_step("steps/toolCallRequest", DENIED)
    assert example_guardian.handle_request(request)["result"]["decision"] == "deny"


@pytest.mark.parametrize("params", [[], "params", 5, None], ids=["list", "string", "int", "null"])
def test_a_request_that_cannot_be_hashed_gets_an_unsigned_answer(signer, params):
    # Review CR3-1: no hash can name this request, so the answer is the unsigned one the README lists for a request
    # with no readable session, and handle_request never raises.
    request = {"jsonrpc": "2.0", "id": "p-1", "method": "steps/toolCallRequest", "params": params}
    response = example_guardian.handle_request(request)
    assert response["id"] == "p-1"
    assert response["error"]["code"] == -32600
    assert "signature" not in response["error"]
    assert request_sha256(request) is None


def test_a_non_object_metadata_still_gets_a_signed_answer(signer):
    # params is an object, so the request has a hash, and the refusal names it under ML-DSA-65.
    request = {"jsonrpc": "2.0", "id": "m-1", "method": "steps/toolCallRequest",
               "params": {"request_id": "r", "metadata": ["not", "an", "object"]}}
    response = example_guardian.handle_request(request)
    assert response["error"]["code"] == -32600
    assert_ml_dsa(response, request, signer)
