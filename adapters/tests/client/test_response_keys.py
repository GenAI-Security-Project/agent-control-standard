"""acs.client verifies every Guardian response with the key document's key, by key_id (issue #576).

The key comes from the document by key_id (RFC 8725 section 3.1, issue #308), never from the
envelope's signature.algorithm. A response binds to the request it answers (D-029). Any failure
blocks the step whatever the posture (D-040) and carries failure class signature_invalid (D-025).
"""
from __future__ import annotations

import datetime
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from tests.pqc_extra import require_pqc

require_pqc()

from acs.client import (  # noqa: E402
    Config,
    Decided,
    Negotiated,
    Resolution,
    SessionRefused,
    open_session,
    parse_key_document,
    round_trip,
    sign_envelope,
)
from acs.client import _exchange, _handshake  # noqa: E402
from acs.core import ACS_VERSION, MLDSA65SigningKey, sign_with_signing_key  # noqa: E402
from acs.testing.harness import signing_env  # noqa: E402
from tests.client.test_key_document import KEY_ID, _document, _entry  # noqa: E402
from tests.client.test_on_wire import HELLO, PROCEED, SESSION, URL, Recorder, decision_for, step_request  # noqa: E402

UTC = datetime.timezone.utc


def _window() -> dict:
    now = datetime.datetime.now(UTC)
    return {"not_before": now - datetime.timedelta(days=1), "not_after": now + datetime.timedelta(days=1)}


def _flip(text: str) -> str:
    """One character changed in the middle, so the change is never in base64 padding."""
    i = len(text) // 2
    return text[:i] + ("B" if text[i] != "B" else "C") + text[i + 1:]


class ResponseKeysTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.signer = MLDSA65SigningKey.generate(KEY_ID)
        cls.keys = parse_key_document(_document(_entry(cls.signer, **_window())), key_id=KEY_ID,
                                      now=datetime.datetime.now(UTC))

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="acs-response-keys-")
        self.addCleanup(temporary.cleanup)
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        for patcher in (mock.patch.dict(os.environ, {**env, **signing_env()}, clear=True),
                        mock.patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", Path(temporary.name))):
            patcher.start()
            self.addCleanup(patcher.stop)
        mock.patch.object(_exchange, "audit_event").start()
        mock.patch.object(_handshake, "audit_event").start()
        self.addCleanup(mock.patch.stopall)

    # Signed answers.

    def ml_decision(self, request: dict, decision: str = "deny", signer: MLDSA65SigningKey | None = None) -> dict:
        result = {"type": "final", "acs_version": ACS_VERSION, "request_id": request["params"]["request_id"],
                  "decision": decision, "reasoning": "destructive Bash pattern in: rm -rf /"}
        return sign_with_signing_key({"jsonrpc": "2.0", "id": request["id"], "result": result},
                                     signer or self.signer)

    def ml_error(self, request: dict, code: int = -32005, data: dict | None = None) -> dict:
        error: dict[str, Any] = {"code": code, "message": "REPLAY_DETECTED: request_id already seen"}
        if data is not None:
            error["data"] = data
        return sign_with_signing_key({"jsonrpc": "2.0", "id": request["id"], "error": error}, self.signer)

    def ml_hello(self, hello: dict, **extra: Any) -> dict:
        result = {**HELLO, "x_acs_lab_response_algorithm": "ML-DSA-65", **extra}
        return sign_with_signing_key({"jsonrpc": "2.0", "id": hello["id"], "result": result}, self.signer)

    # Calls.

    def step(self, answer: Any, *, keys: Any = "default", request: dict | None = None) -> Any:
        request = request or step_request()
        with mock.patch.object(_exchange, "post", side_effect=lambda r, **_: answer(r)):
            return round_trip(request, guardian_url=URL, posture=PROCEED, session_id=SESSION,
                              response_keys=self.keys if keys == "default" else keys)

    def hello(self, answer: Any, *, keys: Any = "default", session_id: str = SESSION,
              recorder: Recorder | None = None) -> Any:
        config = Config.from_env({"ACS_GUARDIAN_URL": URL})
        with mock.patch.object(_handshake, "post", side_effect=lambda h, **_: answer(h)):
            return open_session(config=config, session_id=session_id, agent_id="test", platform="test",
                                methods_implemented=["steps/toolCallRequest"],
                                response_keys=self.keys if keys == "default" else keys, on_wire=recorder)

    def assert_blocked(self, outcome: Any, cause: str) -> None:
        self.assertIsInstance(outcome, Resolution)
        self.assertFalse(outcome.proceed)
        self.assertEqual(outcome.cause, cause)
        self.assertEqual(outcome.fields["failure_class"], "signature_invalid")

    # Step exchange.

    def test_a_signed_decision_is_decided(self) -> None:
        outcome = self.step(self.ml_decision)
        self.assertIsInstance(outcome, Decided)
        self.assertEqual(outcome.response["result"]["decision"], "deny")

    def test_a_flipped_byte_in_the_signature_value(self) -> None:
        def answer(request: dict) -> dict:
            response = self.ml_decision(request)
            signature = response["result"]["signature"]
            signature["value"] = _flip(signature["value"])
            return response
        self.assert_blocked(self.step(answer), "response_signature_invalid")

    def test_a_flipped_byte_in_the_result(self) -> None:
        def answer(request: dict) -> dict:
            response = self.ml_decision(request)
            response["result"]["reasoning"] = _flip(response["result"]["reasoning"])
            return response
        self.assert_blocked(self.step(answer), "response_signature_invalid")

    def test_a_flipped_byte_in_a_signed_error(self) -> None:
        def answer(request: dict) -> dict:
            response = self.ml_error(request)
            response["error"]["message"] = _flip(response["error"]["message"])
            return response
        self.assert_blocked(self.step(answer), "error_signature_invalid")

    def test_a_signed_error_is_honored(self) -> None:
        outcome = self.step(self.ml_error)
        self.assertIsInstance(outcome, Resolution)
        self.assertFalse(outcome.proceed)
        self.assertEqual(outcome.cause, "replay_detected_response")

    def test_an_hmac_signed_decision_is_refused_under_keys(self) -> None:
        self.assert_blocked(self.step(decision_for), "response_signature_invalid")

    def test_an_ml_dsa_decision_is_refused_without_keys(self) -> None:
        self.assert_blocked(self.step(self.ml_decision, keys=None), "response_signature_invalid")

    def test_a_decision_under_another_key_id_is_refused(self) -> None:
        other = MLDSA65SigningKey.generate("lab-guardian-2")
        self.assert_blocked(self.step(lambda r: self.ml_decision(r, signer=other)), "response_signature_invalid")

    def test_a_signed_error_replayed_onto_another_request_fails(self) -> None:
        captured = self.ml_error(step_request())
        outcome = self.step(lambda r: captured)
        self.assertIsInstance(outcome, Resolution)
        self.assertFalse(outcome.proceed)
        self.assertEqual(outcome.cause, "response_binding_mismatch")

    def test_a_signed_decision_replayed_onto_another_request_fails(self) -> None:
        captured = self.ml_decision(step_request())
        outcome = self.step(lambda r: {**captured, "id": r["id"]})
        self.assertIsInstance(outcome, Resolution)
        self.assertFalse(outcome.proceed)
        self.assertEqual(outcome.cause, "response_binding_mismatch")

    def test_an_unsigned_minus_32004_is_key_id_rejected(self) -> None:
        outcome = self.step(lambda r: {"jsonrpc": "2.0", "id": r["id"],
                                       "error": {"code": -32004, "message": "SIGNATURE_INVALID: unknown key_id"}})
        self.assertIsInstance(outcome, Resolution)
        self.assertFalse(outcome.proceed)
        self.assertEqual(outcome.cause, "key_id_rejected")

    # Handshake.

    def test_the_client_hello_offers_the_lab_list(self) -> None:
        recorder = Recorder()
        self.hello(self.ml_hello, recorder=recorder)
        payload = recorder.calls[0][1]["params"]["payload"]
        self.assertEqual(payload["x_acs_lab_response_algorithms"], ["ML-DSA-65"])
        self.assertEqual(payload["signature_algorithms_supported"], ["HMAC-SHA256"])

    def test_a_signed_server_hello_negotiates(self) -> None:
        decision = self.hello(self.ml_hello)
        self.assertIsInstance(decision, Negotiated)
        self.assertEqual(decision.server_hello["x_acs_lab_response_algorithm"], "ML-DSA-65")

    def test_a_flipped_byte_in_the_server_hello(self) -> None:
        def answer(hello: dict) -> dict:
            response = self.ml_hello(hello)
            response["result"]["on_decision_failure"] = "deny"
            return response
        decision = self.hello(answer)
        self.assertIsInstance(decision, SessionRefused)
        self.assertEqual(decision.cause, "server_hello_signature_invalid")

    def test_a_server_hello_without_the_lab_field_is_refused(self) -> None:
        for name, value in (("absent", None), ("HMAC", "HMAC-SHA256"), ("a list", ["ML-DSA-65"])):
            with self.subTest(name):
                def answer(hello: dict) -> dict:
                    result = {**HELLO} if value is None else {**HELLO, "x_acs_lab_response_algorithm": value}
                    return sign_with_signing_key({"jsonrpc": "2.0", "id": hello["id"], "result": result},
                                                 self.signer)
                decision = self.hello(answer, session_id=f"no-field-{name}")
                self.assertIsInstance(decision, SessionRefused)
                self.assertEqual(decision.cause, "response_algorithm_not_negotiated")
                self.assertEqual(decision.fields["offered"], ["ML-DSA-65"])
                self.assertEqual(decision.fields["selected"], value)

    def test_an_hmac_server_hello_is_refused(self) -> None:
        def answer(hello: dict) -> dict:
            result = {**HELLO, "x_acs_lab_response_algorithm": "ML-DSA-65"}
            return sign_envelope({"jsonrpc": "2.0", "id": hello["id"], "result": result}, session_id=SESSION)
        decision = self.hello(answer)
        self.assertIsInstance(decision, SessionRefused)
        self.assertEqual(decision.cause, "server_hello_signature_invalid")

    def test_a_verified_refusal_keeps_its_reason(self) -> None:
        reason = {"reason": "unsupported_signature_algorithm"}
        decision = self.hello(lambda h: self.ml_error(h, -32000, reason))
        self.assertIsInstance(decision, SessionRefused)
        self.assertEqual(decision.cause, "session_refused_response")
        self.assertEqual(decision.fields["reason"], "unsupported_signature_algorithm")
        self.assertEqual(decision.fields["error_code"], -32000)

    def test_a_stored_hmac_session_fails_closed_under_keys(self) -> None:
        def hmac_hello(hello: dict) -> dict:
            return sign_envelope({"jsonrpc": "2.0", "id": hello["id"], "result": dict(HELLO)}, session_id=SESSION)
        self.assertIsInstance(self.hello(hmac_hello, keys=None), Negotiated)
        # The stored record is reused with keys set. The first step's HMAC-signed decision never verifies.
        self.assertIsInstance(self.hello(hmac_hello), Negotiated)
        self.assert_blocked(self.step(decision_for), "response_signature_invalid")

    def test_a_stored_ml_dsa_session_fails_closed_without_keys(self) -> None:
        self.assertIsInstance(self.hello(self.ml_hello, session_id="ml-first"), Negotiated)
        self.assert_blocked(self.step(self.ml_decision, keys=None), "response_signature_invalid")


if __name__ == "__main__":
    unittest.main()
