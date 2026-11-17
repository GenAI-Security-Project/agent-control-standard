"""acs.client verifies every Guardian response with the key document's key, by key_id (issue #576).

The key comes from the document by key_id (RFC 8725 section 3.1, issue #308), never from the
envelope's signature.algorithm. A response binds to the request it answers (D-029). Any failure
blocks the step whatever the posture (D-040) and carries failure class signature_invalid (D-025).
"""
from __future__ import annotations

import copy
import datetime
import hashlib
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
from acs.client import _exchange, _handshake, _key_document  # noqa: E402
from acs.core import (  # noqa: E402
    ACS_VERSION,
    Keyring,
    MLDSA65SigningKey,
    sign_with_signing_key,
    signing_input,
    verify_with_keyring,
)
from acs.testing.harness import signing_env  # noqa: E402
from tests.client.test_key_document import KEY_ID, _document, _entry  # noqa: E402
from tests.client.test_on_wire import (  # noqa: E402
    HELLO,
    PROCEED,
    SESSION,
    URL,
    Recorder,
    decision_for,
    decoded,
    step_request,
)

UTC = datetime.timezone.utc
# Lab convention: an ML-DSA-signed response names the request it answers by this hash. Section 10 gives a response
# no session_id, and issue #13 is the closest tracking issue.
DIGEST = "x_acs_lab_request_sha256"
ATTACKER_SESSION = "77777777-7777-4777-8777-777777777777"


def _digest(request: dict) -> str:
    return hashlib.sha256(signing_input(request)).hexdigest()


def _window() -> dict:
    now = datetime.datetime.now(UTC)
    return {"not_before": now - datetime.timedelta(days=1), "not_after": now + datetime.timedelta(days=1)}


def _flip(text: str) -> str:
    """One character changed in the middle, so the change is never in base64 padding."""
    i = len(text) // 2
    return text[:i] + ("B" if text[i] != "B" else "C") + text[i + 1:]


class _ResponseKeysBase(unittest.TestCase):
    """Keys, signed answers, and calls the tests below share. It holds no tests itself."""

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

    def ml_decision(self, request: dict, decision: str = "deny", signer: MLDSA65SigningKey | None = None,
                    digest: bool = True) -> dict:
        result = {"type": "final", "acs_version": ACS_VERSION, "request_id": request["params"]["request_id"],
                  "decision": decision, "reasoning": "destructive Bash pattern in: rm -rf /"}
        if digest:
            result[DIGEST] = _digest(request)
        return sign_with_signing_key({"jsonrpc": "2.0", "id": request["id"], "result": result},
                                     signer or self.signer)

    def ml_error(self, request: dict, code: int = -32005, data: dict | None = None, digest: bool = True) -> dict:
        error: dict[str, Any] = {"code": code, "message": "REPLAY_DETECTED: request_id already seen"}
        data = {**(data or {}), **({DIGEST: _digest(request)} if digest else {})}
        if data:
            error["data"] = data
        return sign_with_signing_key({"jsonrpc": "2.0", "id": request["id"], "error": error}, self.signer)

    def ml_hello(self, hello: dict, digest: bool = True, **extra: Any) -> dict:
        result = {**HELLO, "x_acs_lab_response_algorithm": "ML-DSA-65", **extra}
        if digest:
            result[DIGEST] = _digest(hello)
        return sign_with_signing_key({"jsonrpc": "2.0", "id": hello["id"], "result": result}, self.signer)

    # Calls.

    def step(self, answer: Any, *, keys: Any = "default", request: dict | None = None) -> Any:
        request = request or step_request()
        with mock.patch.object(_exchange, "post", side_effect=decoded(lambda r, **_: answer(r))):
            return round_trip(request, guardian_url=URL, posture=PROCEED, session_id=SESSION,
                              response_keys=self.keys if keys == "default" else keys)

    def hello(self, answer: Any, *, keys: Any = "default", session_id: str = SESSION,
              recorder: Recorder | None = None) -> Any:
        config = Config.from_env({"ACS_GUARDIAN_URL": URL})
        with mock.patch.object(_handshake, "post", side_effect=decoded(lambda h, **_: answer(h))):
            return open_session(config=config, session_id=session_id, agent_id="test", platform="test",
                                methods_implemented=["steps/toolCallRequest"],
                                response_keys=self.keys if keys == "default" else keys, on_wire=recorder)

    def assert_blocked(self, outcome: Any, cause: str) -> None:
        self.assertIsInstance(outcome, Resolution)
        self.assertFalse(outcome.proceed)
        self.assertEqual(outcome.cause, cause)
        self.assertEqual(outcome.fields["failure_class"], "signature_invalid")



class ResponseKeysTest(_ResponseKeysBase):
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
                    result[DIGEST] = _digest(hello)
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

    def test_a_signed_step_decision_offered_as_a_server_hello_is_no_answer(self) -> None:
        # Review round 4 L1: LAB-01 drops the binding rule's request_id refusal, so a signed decision whose JSON-RPC id
        # collides with the ClientHello's verifies by keyring alone. The required-field check must still refuse it,
        # with or without the request_id, on the key document path as on the HMAC path.
        from acs.client import NoAnswer
        for name, with_request_id in (("with request_id", True), ("without request_id", False)):
            with self.subTest(name):
                def answer(hello: dict) -> dict:
                    result = {"type": "final", "acs_version": ACS_VERSION, "decision": "allow",
                              DIGEST: _digest(hello)}
                    if with_request_id:
                        result["request_id"] = hello["params"]["request_id"]
                    return sign_with_signing_key({"jsonrpc": "2.0", "id": hello["id"], "result": result},
                                                 self.signer)
                with mock.patch.object(_handshake, "server_hello_problem",
                                       wraps=_handshake.server_hello_problem) as checked:
                    decision = self.hello(answer, session_id=f"decision-as-hello-{with_request_id}")
                self.assertNotIsInstance(decision, Negotiated)
                if with_request_id and isinstance(decision, SessionRefused):
                    # Today's base still refuses a handshake result that carries request_id inside the binding rule,
                    # so the signature never verifies. After LAB-01 drops that rule, this case reaches the
                    # required-field check below like the other one.
                    self.assertEqual(decision.cause, "server_hello_signature_invalid")
                    continue
                self.assertIsInstance(decision, NoAnswer)
                self.assertEqual(decision.cause, "invalid_server_hello")
                # It lacks negotiated_version, which the classifier checks before server_hello_problem runs.
                self.assertEqual(checked.call_count, 0)

    def test_a_verified_server_hello_goes_through_server_hello_problem(self) -> None:
        with mock.patch.object(_handshake, "server_hello_problem", wraps=_handshake.server_hello_problem) as checked:
            self.assertIsInstance(self.hello(self.ml_hello, session_id="checked-hello"), Negotiated)
        checked.assert_called_once()

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


class RequestDigestBinding(_ResponseKeysBase):
    """One ML-DSA key signs every session, so a response names its request by hash (lab convention, issue #13)."""

    def test_the_relay_attack_is_refused(self) -> None:
        # An authenticated client of the same Guardian copies the victim's ids into its own request, gets an honest
        # signed allow for it, and relays that allow to the victim. Ids and request_id all match.
        def relay(sent: dict) -> dict:
            attacker = copy.deepcopy(sent)
            del attacker["params"]["signature"]
            attacker["params"]["metadata"]["session_id"] = ATTACKER_SESSION
            attacker["params"]["payload"] = {"tool": {"name": "ls"}, "arguments": {}}
            sign_envelope(attacker, session_id=ATTACKER_SESSION)
            return self.ml_decision(attacker, decision="allow")
        self.assert_blocked(self.step(relay), "response_signature_invalid")

    def test_a_missing_request_digest_is_refused(self) -> None:
        self.assert_blocked(self.step(lambda r: self.ml_decision(r, digest=False)), "response_signature_invalid")
        self.assert_blocked(self.step(lambda r: self.ml_error(r, digest=False)), "error_signature_invalid")
        decision = self.hello(lambda h: self.ml_hello(h, digest=False))
        self.assertEqual(decision, SessionRefused("server_hello_signature_invalid"))

    def test_a_relayed_refusal_is_refused(self) -> None:
        def relay(hello: dict) -> dict:
            other = copy.deepcopy(hello)
            other["params"]["timestamp"] = "2026-01-01T00:00:00.000Z"
            return self.ml_error(other, -32000, {"reason": "unsupported_signature_algorithm"})
        decision = self.hello(relay)
        self.assertIsInstance(decision, SessionRefused)
        self.assertEqual(decision.cause, "error_signature_invalid")

    def test_a_matching_digest_verifies(self) -> None:
        self.assertIsInstance(self.step(self.ml_decision), Decided)
        self.assertIsInstance(self.hello(self.ml_hello), Negotiated)

    def test_core_checks_the_digest_only_when_asked(self) -> None:
        request = step_request()
        keyring = Keyring([self.signer.verification_key()])
        bare = self.ml_decision(request, digest=False)
        named = self.ml_decision(request)
        self.assertTrue(verify_with_keyring(bare, keyring, expected_key_id=KEY_ID, request=request))
        self.assertFalse(verify_with_keyring(bare, keyring, expected_key_id=KEY_ID, request=request,
                                             require_request_digest=True))
        self.assertTrue(verify_with_keyring(named, keyring, expected_key_id=KEY_ID, request=request,
                                            require_request_digest=True))
        # Anything but 64 lowercase hex characters fails, a non-ASCII value included, which compare_digest would
        # otherwise raise on (review R-M1).
        for wrong in ("0" * 64, _digest(request).upper(), 7, None, "\u00e9" * 64, _digest(request)[:63],
                      _digest(request) + "0", " " + _digest(request)[1:]):
            with self.subTest(wrong=wrong):
                forged = copy.deepcopy(named)
                forged["result"][DIGEST] = wrong
                del forged["result"]["signature"]
                sign_with_signing_key(forged, self.signer)
                self.assertFalse(verify_with_keyring(forged, keyring, expected_key_id=KEY_ID, request=request,
                                                     require_request_digest=True))


class KeyValidity(_ResponseKeysBase):
    """The key's window and revocation are checked on every response, not only at load (review R-I1)."""

    def at(self, moment: datetime.datetime) -> None:
        # The one clock the client and the Guardian both read (review CR3-8).
        patcher = mock.patch.object(_key_document, "utcnow", return_value=moment)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_parsed_keys_carry_their_window(self) -> None:
        self.assertLess(self.keys.not_before, self.keys.not_after)
        self.assertIsNone(self.keys.revoked_at)
        self.assertTrue(self.keys.is_live(self.keys.not_before))
        self.assertFalse(self.keys.is_live(self.keys.not_after))
        self.assertFalse(self.keys.is_live(self.keys.not_before - datetime.timedelta(seconds=1)))

    def test_a_key_that_expires_while_running_fails_every_response(self) -> None:
        self.at(self.keys.not_after)
        self.assert_blocked(self.step(self.ml_decision), "response_signature_invalid")
        self.assert_blocked(self.step(self.ml_error), "error_signature_invalid")
        decision = self.hello(self.ml_hello)
        self.assertEqual(decision, SessionRefused("server_hello_signature_invalid"))

    def test_a_key_not_yet_valid_fails(self) -> None:
        self.at(self.keys.not_before - datetime.timedelta(seconds=1))
        self.assert_blocked(self.step(self.ml_decision), "response_signature_invalid")

    def test_a_key_revoked_after_load_fails_from_its_revocation(self) -> None:
        now = datetime.datetime.now(UTC)
        revoked = [{"key_id": KEY_ID, "revoked_at": (now + datetime.timedelta(hours=1)).isoformat().replace(
            "+00:00", "Z")}]
        keys = parse_key_document(_document(_entry(self.signer, **_window()), revoked=revoked), key_id=KEY_ID,
                                  now=now)
        self.assertIsNotNone(keys.revoked_at)
        self.at(now + datetime.timedelta(minutes=59))
        self.assertIsInstance(self.step(self.ml_decision, keys=keys), Decided)
        self.at(now + datetime.timedelta(hours=1))
        self.assert_blocked(self.step(self.ml_decision, keys=keys), "response_signature_invalid")


if __name__ == "__main__":
    unittest.main()
