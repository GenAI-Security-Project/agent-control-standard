"""
Self-tests for the emission oracle (CaptureGuardian).

A validator that never rejects makes the emission suite vacuous, so
these tests feed deliberately-broken envelopes and assert each defect
class is flagged — envelope schema, payload schema, every invariant.
"""
from __future__ import annotations

import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import acs_common  # noqa: E402
from capture_guardian import CaptureGuardian  # noqa: E402

SESSION = "11111111-1111-4111-8111-111111111111"


def _signed_tool_call(secret: str, **overrides) -> dict:
    env = {
        "jsonrpc": "2.0", "id": str(uuid.uuid4()),
        "method": "steps/toolCallRequest",
        "params": {
            "acs_version": "0.1.0",
            "request_id": str(uuid.uuid4()),
            "timestamp": acs_common.iso8601_now(),
            "metadata": {"agent_id": "a", "session_id": SESSION,
                         "platform": "test"},
            "payload": {"tool": {"name": "Bash"},
                        "arguments": {"command": {"value": "ls"}}},
        },
    }
    env["params"].update(overrides.get("params", {}))
    if overrides.get("payload") is not None:
        env["params"]["payload"] = overrides["payload"]
    if overrides.get("metadata") is not None:
        env["params"]["metadata"] = overrides["metadata"]
    key = acs_common.derive_session_key(secret.encode(),
                                        env["params"]["metadata"].get("session_id", ""))
    acs_common.sign_envelope(env, key=key,
                             session_id=env["params"]["metadata"].get("session_id", ""))
    return env


class IndependentVerifierKnownAnswer(unittest.TestCase):
    """A frozen known-answer vector pins the oracle's independent
    HKDF+HMAC+JCS implementation (it must not share acs_common's code,
    where a shared bug would pass both sides)."""

    SECRET = b"known-answer-test-secret"
    SID = "00000000-0000-4000-8000-00000000abcd"
    KEY_HEX = "9721459baad0df9ba42d9ad8612aae96f8168b50873685ab643f0facac11a45c"
    SIG_B64 = "mjNGChQDhC70VyXlGXEbYOXSTLHRg+9ZoTNjP3otx9s="

    def _envelope(self):
        return {"jsonrpc": "2.0", "id": "kat-1", "method": "steps/sessionStart",
                "params": {"acs_version": "0.1.0",
                           "request_id": "11111111-1111-4111-8111-111111111111",
                           "timestamp": "2026-01-01T00:00:00.000Z",
                           "metadata": {"agent_id": "kat", "session_id": self.SID,
                                        "platform": "test"},
                           "payload": {}}}

    def test_session_key_matches_frozen_vector(self):
        from capture_guardian import independent_session_key
        self.assertEqual(
            independent_session_key(self.SECRET, self.SID).hex(), self.KEY_HEX,
            "HKDF changed or broke — frozen key vector no longer matches")

    def test_verify_accepts_known_good_signature(self):
        from capture_guardian import independent_verify
        env = self._envelope()
        env["params"]["signature"] = {"algorithm": "HMAC-SHA256",
                                      "value": self.SIG_B64, "key_id": "default"}
        self.assertTrue(independent_verify(env, self.SECRET, self.SID),
            "independent verifier rejected a known-GOOD signature")

    def test_verify_rejects_tampered_payload(self):
        from capture_guardian import independent_verify
        env = self._envelope()
        env["params"]["signature"] = {"algorithm": "HMAC-SHA256",
                                      "value": self.SIG_B64, "key_id": "default"}
        env["params"]["payload"] = {"tampered": True}  # signature no longer covers this
        self.assertFalse(independent_verify(env, self.SECRET, self.SID),
            "independent verifier accepted a TAMPERED envelope")

    def test_verify_rejects_wrong_key(self):
        from capture_guardian import independent_verify
        env = self._envelope()
        env["params"]["signature"] = {"algorithm": "HMAC-SHA256",
                                      "value": self.SIG_B64, "key_id": "default"}
        self.assertFalse(independent_verify(env, b"wrong-secret", self.SID))

    def test_independent_of_acs_common(self):
        """The verifier must not delegate to acs_common — that's the
        whole point. Cross-check: it AGREES with acs_common on a valid
        envelope (two implementations, same answer) but is a distinct
        code path."""
        import acs_common
        from capture_guardian import independent_verify
        env = self._envelope()
        key = acs_common.derive_session_key(self.SECRET, self.SID)
        acs_common.sign_envelope(env, key=key, session_id=self.SID)
        self.assertTrue(independent_verify(env, self.SECRET, self.SID),
            "independent verifier and acs_common disagree on a valid envelope")


class OracleIsNotVacuous(unittest.TestCase):
    def setUp(self) -> None:
        self.g = CaptureGuardian()

    def _errors(self, env: dict) -> list[str]:
        self.g._capture(b"{}", env)
        return self.g.captures[-1].errors

    def test_accepts_a_well_formed_signed_envelope(self) -> None:
        errs = self._errors(_signed_tool_call(self.g.hmac_secret))
        self.assertEqual(errs, [], f"a valid envelope was rejected: {errs}")

    def test_flags_bad_request_id(self) -> None:
        env = _signed_tool_call(self.g.hmac_secret,
                                params={"request_id": "NOT-A-UUID"})
        errs = self._errors(env)
        self.assertTrue(any("request_id" in e for e in errs), errs)

    def test_flags_bad_timestamp(self) -> None:
        env = _signed_tool_call(self.g.hmac_secret, params={"timestamp": "nope"})
        self.assertTrue(any("timestamp" in e for e in self._errors(env)))

    def test_flags_missing_metadata_fields(self) -> None:
        env = _signed_tool_call(self.g.hmac_secret,
                                metadata={"agent_id": "a"})  # no session_id/platform
        errs = self._errors(env)
        self.assertTrue(any("session_id" in e for e in errs), errs)
        self.assertTrue(any("platform" in e for e in errs), errs)

    def test_flags_unwrapped_tool_arguments(self) -> None:
        env = _signed_tool_call(
            self.g.hmac_secret,
            payload={"tool": {"name": "Bash"}, "arguments": {"command": "ls"}})
        self.assertTrue(any("not wrapped" in e for e in self._errors(env)))

    def test_flags_broken_signature(self) -> None:
        env = _signed_tool_call(self.g.hmac_secret)
        env["params"]["signature"]["value"] = "AAAA" + env["params"]["signature"]["value"][4:]
        self.assertTrue(
            any("signature" in e for e in self._errors(env)),
            "tampered signature must be flagged")

    def test_flags_unknown_method(self) -> None:
        env = _signed_tool_call(self.g.hmac_secret)
        env["method"] = "steps/notARealHook"
        errs = self._errors(env)
        self.assertTrue(any("no canonical schema" in e or "method" in e
                            for e in errs), errs)

    def test_flags_payload_schema_violation(self) -> None:
        # toolCallRequest requires `arguments`; omit it.
        env = _signed_tool_call(self.g.hmac_secret,
                                payload={"tool": {"name": "Bash"}})
        self.assertTrue(any("payload" in e for e in self._errors(env)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
