"""
ACS §10 message authentication: RFC 8785 (JCS) canonicalization, RFC 5869 (HKDF-SHA256)
key derivation, and HMAC-SHA256 signing/verification, per OWASP ACS v0.1.0 Specification §10.

Standard library only. Implemented to the normative text, not assumed:
  - key = HKDF-SHA256(IKM=secret, salt=none, info=UTF-8(metadata.session_id), L=32)
  - signing input = RFC 8785 (JCS) of the envelope with the `signature` field removed, UTF-8
  - signature value = base64(HMAC-SHA256(key, signing_input))   (HMAC baseline, non-hybrid)
  - §10.3 / §17.1 error codes: SIGNATURE_INVALID -32004, REPLAY_DETECTED -32005,
    TIMESTAMP_OUT_OF_WINDOW -32006

The HKDF derivation is checked against the spec's own §10 test vector in test_vector_ok()
(re-run by verify.py), so this implementation is tied to the normative text, not to itself.

JCS scope: the ACS envelope value domain is objects, arrays, strings, integers, booleans
and null (no floats; keys are ASCII). Integers serialize as decimal; a float raises rather
than silently emitting a non-canonical form. That covers every ACS envelope this suite sends.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

# §10.3 / §17.1 error codes
SIGNATURE_INVALID = -32004
REPLAY_DETECTED = -32005
TIMESTAMP_OUT_OF_WINDOW = -32006

# A fixed test key shared by the bundled mocks and the conformance harness, so the §10
# checks can sign requests the mock can verify. It is the spec's §10 HKDF test-vector secret
# (bytes 0x00..0x1f). A real external Guardian uses its own deployment key material instead.
TEST_KEY_ID = "acs-conformance-hmac-test"
TEST_SECRET = bytes(range(32))


def _jcs_string(s: str) -> str:
    # RFC 8785 string form is JSON with the minimal escape set and non-ASCII emitted as-is,
    # which is exactly json.dumps(..., ensure_ascii=False).
    return json.dumps(s, ensure_ascii=False)


def _jcs(value) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, bool):          # unreachable (handled above), explicit for safety
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError("JCS float serialization is out of scope for ACS envelopes")
    if isinstance(value, list):
        return "[" + ",".join(_jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        # keys sorted by UTF-16 code unit; for ASCII keys (all ACS envelope keys) this is
        # identical to Python's code-point sort.
        return "{" + ",".join(_jcs_string(k) + ":" + _jcs(value[k]) for k in sorted(value.keys())) + "}"
    raise TypeError(f"JCS: unsupported type {type(value).__name__}")


def jcs(value) -> bytes:
    """RFC 8785 (JCS) canonicalization for the ACS envelope value domain, as UTF-8 bytes."""
    return _jcs(value).encode("utf-8")


def hkdf_sha256(ikm: bytes, length: int = 32, salt: bytes = b"", info: bytes = b"") -> bytes:
    """RFC 5869 HKDF with SHA-256. An empty salt becomes HashLen zero bytes (RFC 5869 default)."""
    if salt == b"":
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def session_key(secret: bytes, session_id: str) -> bytes:
    """§10 baseline: HKDF-SHA256(secret, no salt, info = UTF-8(session_id), 32 bytes)."""
    return hkdf_sha256(secret, 32, salt=b"", info=session_id.encode("utf-8"))


def _signing_input(envelope: dict) -> bytes:
    params = dict(envelope.get("params") or {})
    params.pop("signature", None)              # the only field excluded (§10)
    env = dict(envelope)
    env["params"] = params
    return jcs(env)


def sign_envelope(envelope: dict, secret: bytes, key_id: str) -> dict:
    """Return a deep copy of `envelope` with params.signature set per §10 (HMAC-SHA256 baseline)."""
    sid = ((envelope.get("params") or {}).get("metadata") or {}).get("session_id", "")
    mac = hmac.new(session_key(secret, sid), _signing_input(envelope), hashlib.sha256).digest()
    signed = json.loads(json.dumps(envelope))
    signed["params"]["signature"] = {"algorithm": "HMAC-SHA256",
                                     "value": base64.b64encode(mac).decode("ascii"),
                                     "key_id": key_id}
    return signed


def verify_envelope(envelope: dict, secret: bytes) -> bool:
    """True iff params.signature is a valid HMAC-SHA256 over the JCS of the envelope (minus the
    signature field) under the HKDF session key. The caller checks key_id is known first."""
    sig = ((envelope.get("params") or {}).get("signature")) or {}
    if sig.get("algorithm") != "HMAC-SHA256" or "value" not in sig:
        return False
    sid = ((envelope.get("params") or {}).get("metadata") or {}).get("session_id", "")
    expected = hmac.new(session_key(secret, sid), _signing_input(envelope), hashlib.sha256).digest()
    try:
        given = base64.b64decode(sig["value"], validate=True)
    except Exception:
        return False
    return hmac.compare_digest(expected, given)


# The spec's §10 HKDF test vector. Reproducing it proves this HKDF matches ACS-Core.
_TV_SECRET = bytes(range(32))
_TV_SESSION = "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36"
_TV_KEY = "80f0dc8c611279bfc2af2d5f374c5cb685888192ce1af5c3e0673d8fa748e8a4"


def test_vector_ok() -> bool:
    """Does our HKDF reproduce the ACS §10 published key for the published secret/session?"""
    return session_key(_TV_SECRET, _TV_SESSION).hex() == _TV_KEY


def _selftest():
    assert test_vector_ok(), "HKDF does not reproduce the ACS §10 test vector"
    env = {"jsonrpc": "2.0", "id": "x", "method": "steps/toolCallRequest",
           "params": {"acs_version": "0.1.0", "request_id": "r", "timestamp": "t",
                      "metadata": {"agent_id": "a", "session_id": _TV_SESSION},
                      "payload": {"amount": 40}}}
    signed = sign_envelope(env, _TV_SECRET, TEST_KEY_ID)
    assert verify_envelope(signed, _TV_SECRET), "sign/verify round-trip failed"
    tampered = json.loads(json.dumps(signed))
    tampered["params"]["payload"]["amount"] = 41
    assert not verify_envelope(tampered, _TV_SECRET), "tamper was not detected"
    print("acs_sig selftest OK: §10 HKDF test vector reproduced; sign/verify and tamper-detect pass")


if __name__ == "__main__":
    _selftest()
