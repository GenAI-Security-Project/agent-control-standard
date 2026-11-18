"""The verify mark: each answer checked by acs-verify's own logic against the key document (issue #586).

ML-DSA-65 response signing, the key document, and the request hash are lab conventions (issues #316, #460, #13).
"""
from __future__ import annotations

import json
import sys

import pytest

pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa",
                    reason="the pqc extra is not installed: uv run --extra pqc")

from lab_lines import (  # noqa: E402
    LabLogs,
    answer,
    decision_key,
    error_answer,
    sign_hmac,
    tool_request,
)
from model import Model  # noqa: E402
from verify import VERIFY_MARKS, load_keys, make_verifier, verify_mark  # noqa: E402


@pytest.fixture
def key(tmp_path):
    return decision_key(tmp_path / "decision-keys")


@pytest.fixture
def keys(key):
    loaded = load_keys({"ACS_GUARDIAN_KEYS": str(key.document_path)})
    assert loaded is not None
    return loaded


def test_marks_are_the_five_words():
    assert VERIFY_MARKS == ("verified", "failed", "not_checked", "unsigned", "no_answer")


def test_genuine_mldsa_response_verifies(key, keys):
    req = tool_request("echo")
    assert verify_mark(req, key.sign(answer(req, "deny"), req), keys) == ("verified", "ML-DSA-65")


def test_flipped_decision_fails(key, keys):
    req = tool_request("rm")
    signed = key.sign(answer(req, "deny", reason_codes=["destructive_command"]), req)
    signed["result"]["decision"] = "allow"
    assert verify_mark(req, signed, keys) == ("failed", "ML-DSA-65")


def test_response_bound_to_another_request_fails(key, keys):
    req, other = tool_request("echo"), tool_request("echo")
    signed = key.sign(answer(other, "allow"), other)
    assert verify_mark(req, signed, keys) == ("failed", "ML-DSA-65")
    # The same ids copied over still fail: the signed request hash names the other request.
    relayed = key.sign(answer(other, "allow"), other)
    relayed["id"], relayed["result"]["request_id"] = req["id"], req["params"]["request_id"]
    assert verify_mark(req, relayed, keys)[0] == "failed"


def test_hmac_response_is_never_verified(keys):
    req = tool_request("echo")
    signed = sign_hmac(answer(req, "allow"))
    assert verify_mark(req, signed, keys) == ("not_checked", "HMAC-SHA256")
    assert verify_mark(req, signed, None) == ("not_checked", "HMAC-SHA256")


def test_hmac_answer_inside_a_session_that_negotiated_mldsa_fails(keys):
    # The ServerHello verified under ML-DSA-65, so an HMAC answer later in the session is a downgrade. Anyone holding
    # the shared secret can write one, the agent side included (specification section 8.6).
    req = tool_request("echo")
    signed = sign_hmac(answer(req, "allow"))
    assert verify_mark(req, signed, keys, mldsa_session=True) == ("failed", "HMAC-SHA256")


def test_no_keys_reads_not_checked(key):
    req = tool_request("echo")
    assert verify_mark(req, key.sign(answer(req, "allow"), req), None) == ("not_checked", "ML-DSA-65")
    assert load_keys({}) is None


def test_unreadable_key_document_reads_as_no_keys(tmp_path):
    bad = tmp_path / "keys.json"
    bad.write_text("{}", encoding="utf-8")
    assert load_keys({"ACS_GUARDIAN_KEYS": str(bad)}) is None
    assert load_keys({"ACS_GUARDIAN_KEYS": str(tmp_path / "missing.json")}) is None


def test_key_pin_from_the_gateways_settings_is_honored(key):
    pinned = load_keys({"ACS_GUARDIAN_KEYS": str(key.document_path), "ACS_GUARDIAN_KEY_ID": "lab-guardian-1"})
    req = tool_request("echo")
    assert verify_mark(req, key.sign(answer(req, "allow"), req), pinned)[0] == "verified"
    wrong = load_keys({"ACS_GUARDIAN_KEYS": str(key.document_path),
                       "ACS_GUARDIAN_KEY_FINGERPRINT": "sha256:" + "0" * 64})
    assert verify_mark(req, key.sign(answer(req, "allow"), req), wrong)[0] == "failed"


def test_unsigned_error_reads_unsigned(keys):
    req = tool_request("echo")
    assert verify_mark(req, error_answer(req, -32004, "SIGNATURE_INVALID"), keys) == ("unsigned", None)


def test_unanswered_reads_no_answer(keys):
    assert verify_mark(tool_request("echo"), None, keys) == ("no_answer", None)


def test_model_marks_rows_with_the_verifier(tmp_path, key, keys):
    logs = LabLogs(tmp_path)
    good, bad = tool_request("echo"), tool_request("rm")
    logs.pair(good, key.sign(answer(good, "allow"), good))
    flipped = key.sign(answer(bad, "deny"), bad)
    flipped["result"]["decision"] = "allow"
    logs.pair(bad, flipped)
    model = Model(logs.transcript_dir, None, make_verifier(keys))
    model.refresh()
    assert [(r.verify, r.algorithm) for r in model.rows_after(0)] == [("verified", "ML-DSA-65"),
                                                                       ("failed", "ML-DSA-65")]


def test_a_session_the_real_example_guardian_signed_verifies_row_by_row(tmp_path, monkeypatch):
    """Pins the viewer to the Guardian's real signing path and acs-verify's real verdicts, not to these fixtures."""
    from conftest import REPO_ROOT
    sys.path.insert(0, str(REPO_ROOT / "adapters" / "tests" / "guardian"))
    from acs_verify_helpers import record_session, start_guardian, stop_guardian

    run = start_guardian(tmp_path, monkeypatch, mldsa=True)
    try:
        transcript = record_session(run)
    finally:
        stop_guardian(run)
    logs = LabLogs(tmp_path / "lab")
    logs.transcript_dir.mkdir(parents=True)
    logs.transcript(run.session_id).write_text("\n".join(transcript) + "\n", encoding="utf-8")
    keys = load_keys({"ACS_GUARDIAN_KEYS": str(run.key_document_path)})
    model = Model(logs.transcript_dir, None, make_verifier(keys))
    model.refresh()
    got = [(r.method, r.decision, r.verify, r.algorithm) for r in model.rows_after(0)]
    assert got == [("handshake/hello", None, "verified", "ML-DSA-65"),
                   ("steps/sessionStart", "allow", "verified", "ML-DSA-65"),
                   ("steps/toolCallRequest", "allow", "verified", "ML-DSA-65"),
                   ("steps/toolCallRequest", "deny", "verified", "ML-DSA-65"),
                   ("steps/sessionEnd", "allow", "verified", "ML-DSA-65")], got
    # The same deny flipped to allow, with its signature kept, fails on its own row and nowhere else.
    records = [json.loads(line) for line in transcript]
    deny = next(i for i, r in enumerate(records) if r["dir"] == "resp" and r["envelope"].get("result", {})
                .get("decision") == "deny")
    records[deny]["envelope"]["result"]["decision"] = "allow"
    tampered = LabLogs(tmp_path / "tampered")
    tampered.transcript_dir.mkdir(parents=True)
    tampered.transcript(run.session_id).write_text("\n".join(json.dumps(r) for r in records) + "\n",
                                                   encoding="utf-8")
    model = Model(tampered.transcript_dir, None, make_verifier(keys))
    model.refresh()
    assert [r.verify for r in model.rows_after(0)] == ["verified", "verified", "verified", "failed", "verified"]

    # An HMAC-signed allow in place of the deny, correct under the session key the agent side holds. The ServerHello
    # verified under ML-DSA-65, so the HMAC answer is a downgrade and fails (specification section 8.6).
    from acs.core import derive_session_key, sign_with_key
    records = [json.loads(line) for line in transcript]
    forged = records[deny]["envelope"]
    forged["result"].pop("signature")
    forged["result"]["decision"] = "allow"
    sign_with_key(forged, derive_session_key(run.hmac_secret, run.session_id), key_id="lab-guardian-1")
    downgraded = LabLogs(tmp_path / "downgraded")
    downgraded.transcript_dir.mkdir(parents=True)
    downgraded.transcript(run.session_id).write_text("\n".join(json.dumps(r) for r in records) + "\n",
                                                     encoding="utf-8")
    model = Model(downgraded.transcript_dir, None, make_verifier(keys))
    model.refresh()
    assert [(r.verify, r.algorithm) for r in model.rows_after(0)][3] == ("failed", "HMAC-SHA256")
