"""The gateway verifies ML-DSA-65 decisions by the key document's key_id when the signing settings ask for it.

Lab convention until issue #316 settles verifier rules (issue #576). With the settings unset, nothing changes.
"""
import importlib.util

import pytest

from conftest import NEUTRAL, call_item, finbot_request, response_body, transcript_lines

KEY_ID = "lab-guardian-1"


def has_pqc() -> bool:
    try:
        return importlib.util.find_spec("cryptography.hazmat.primitives.asymmetric.mldsa") is not None
    except ModuleNotFoundError:
        return False


needs_pqc = pytest.mark.skipif(not has_pqc(), reason="the pqc extra is not installed (uv sync --extra pqc)")


def config(**env):
    from acs_gateway.config import GatewayConfig

    return GatewayConfig.from_env(env)


def test_signing_env_unset_means_no_response_keys():
    assert config(ACS_LAB_MODE="enforce").response_keys is None
    assert config(ACS_LAB_MODE="enforce", ACS_RESPONSE_ALGORITHMS="HMAC-SHA256").response_keys is None


def test_off_mode_reads_no_signing_setting():
    assert config(ACS_LAB_MODE="off", ACS_RESPONSE_ALGORITHMS="ML-DSA-65").response_keys is None


@pytest.mark.parametrize("env", [{"ACS_RESPONSE_ALGORITHMS": "ECDSA-P256"},
                                 {"ACS_RESPONSE_ALGORITHMS": "ML-DSA-65"},
                                 {"ACS_RESPONSE_ALGORITHMS": "ML-DSA-65", "ACS_GUARDIAN_KEYS": "/nonexistent/keys.json"}])
def test_a_bad_signing_setting_refuses_startup(env):
    with pytest.raises(ValueError):
        config(ACS_LAB_MODE="shadow", **env)


def test_the_client_hello_offers_no_lab_field_with_signing_unset(gateway, guardian, upstream, tmp_path):
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=guardian).post("/v1/responses", json=finbot_request())
    hello = transcript_lines(tmp_path)[0]["envelope"]
    assert hello["method"] == "handshake/hello"
    assert "x_acs_lab_response_algorithms" not in hello["params"]["payload"]


@pytest.fixture
def mldsa(tmp_path):
    """A fresh decision key and its key document: the Guardian's settings and the gateway's."""
    from acs.guardian.decision_keys import write_key_files

    directory = tmp_path / "decision-keys"
    directory.mkdir(mode=0o700)
    key_path, doc_path = write_key_files(directory, key_id=KEY_ID, guardian_id="lab-guardian")
    guardian_env = {"ACS_RESPONSE_SIGNING": "ML-DSA-65", "ACS_GUARDIAN_SIGNING_KEY_FILE": str(key_path),
                    "ACS_GUARDIAN_KEY_ID": KEY_ID, "ACS_GUARDIAN_KEYS": str(doc_path)}
    gateway_env = {"ACS_RESPONSE_ALGORITHMS": "ML-DSA-65", "ACS_GUARDIAN_KEYS": str(doc_path),
                   "ACS_GUARDIAN_KEY_ID": KEY_ID}
    return guardian_env, gateway_env


@needs_pqc
@pytest.mark.parametrize("mode", ["shadow", "enforce"])
def test_mldsa_answers_verify_by_the_key_document(gateway, harness_guardian, upstream, audit, tmp_path, mldsa, mode):
    guardian_env, gateway_env = mldsa
    reply = response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1"))
    upstream.reply(reply)
    client = gateway(ACS_LAB_MODE=mode, ACS_GUARDIAN_URL=harness_guardian(**guardian_env), **gateway_env)
    assert client.post("/v1/responses", json=finbot_request()).json() == reply
    lines = transcript_lines(tmp_path)
    assert lines[0]["envelope"]["params"]["payload"]["x_acs_lab_response_algorithms"] == ["ML-DSA-65"]
    answers = [line["envelope"] for line in lines if line["dir"] == "resp"]
    assert len(answers) == 3
    for answer in answers:
        assert answer["result"]["signature"]["algorithm"] == "ML-DSA-65"
        assert answer["result"]["signature"]["key_id"] == KEY_ID
    name = "decision_applied" if mode == "enforce" else "shadow_decision"
    applied = [e for e in audit() if e["acs_audit_event"] == name][0]
    assert (applied["guardian_decision"], applied["cause"]) == ("allow", None)


@needs_pqc
def test_a_tampered_mldsa_answer_is_denied_and_kept_verbatim(gateway, harness_guardian, upstream, audit, tmp_path,
                                                            mldsa):
    guardian_env, gateway_env = mldsa
    upstream.reply(response_body(call_item("tampered_tool", {}, "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(**guardian_env), **gateway_env)
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    applied = [e for e in audit() if e["acs_audit_event"] == "decision_applied"][0]
    assert applied["cause"] == "response_signature_invalid"
    assert transcript_lines(tmp_path)[-1]["envelope"]["result"]["signature"]["algorithm"] == "ML-DSA-65"


@needs_pqc
def test_a_gateway_without_keys_denies_behind_an_mldsa_guardian(gateway, harness_guardian, upstream, audit, mldsa):
    guardian_env, _ = mldsa
    upstream.reply(response_body(call_item("get_vendor_details", {"vendor_id": 7}, "call_1")))
    client = gateway(ACS_LAB_MODE="enforce", ACS_GUARDIAN_URL=harness_guardian(**guardian_env))
    output = client.post("/v1/responses", json=finbot_request()).json()["output"]
    assert output[0]["content"][0]["text"] == NEUTRAL
    applied = [e for e in audit() if e["acs_audit_event"] == "decision_applied"][0]
    assert applied["decision"] == "deny" and applied["guardian_decision"] is None


def test_the_entry_point_refuses_a_signing_setting_it_cannot_use(tmp_path):
    import os
    import subprocess
    import sys

    env = {**os.environ, "ACS_LAB_MODE": "enforce", "ACS_RESPONSE_ALGORITHMS": "ML-DSA-65",
           "ACS_GUARDIAN_URL": "http://127.0.0.1:9/", "ACS_GUARDIAN_READY_TIMEOUT_S": "1",
           "ACS_GATEWAY_STATE_DIR": str(tmp_path / "state")}
    env.pop("ACS_GUARDIAN_KEYS", None)
    proc = subprocess.run([sys.executable, "-m", "acs_gateway"], env=env, capture_output=True, text=True, timeout=30)
    assert proc.returncode == 2
    assert "ACS_GUARDIAN_KEYS" in proc.stderr
