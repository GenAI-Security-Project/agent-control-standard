"""A signed answer altered into a shape the binding rule rejects is refused, as a failed signature is, never left to the fail posture."""
from __future__ import annotations

from acs.client import Config, _handshake
from acs.client._exchange import classify_response
from acs.client._outcome import Refused, SessionRefused
from acs.core import HANDSHAKE_METHOD

from tests.client.test_session import HELLO, _SessionTest, _signed

SESSION_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
REQUEST = {"jsonrpc": "2.0", "id": "rpc-1", "method": "steps/toolCallRequest",
           "params": {"acs_version": "0.1.0", "request_id": "req-1",
                      "metadata": {"session_id": SESSION_ID}, "payload": {}}}
CLIENT_HELLO = {"jsonrpc": "2.0", "id": "hello-1", "method": HANDSHAKE_METHOD,
                "params": {"acs_version": "0.1.0", "request_id": "hello-request-1",
                           "metadata": {"session_id": SESSION_ID}, "payload": {}}}
DENY = {"type": "final", "acs_version": "0.1.0", "request_id": "req-1", "decision": "deny",
        "reasoning": "blocked", "chain_hash": "0" * 64}
TAMPERINGS = {
    "an added method": lambda r: {**r, "method": "steps/toolCallRequest"},
    "the other member added": lambda r: {**r, **({"error": {"code": -32603, "message": "x"}} if "result" in r
                                                 else {"result": dict(HELLO)})},
}


class TamperedStepAnswers(_SessionTest):
    def test_a_signed_deny_altered_into_a_rejected_shape_is_refused_under_proceed(self) -> None:
        deny = _signed({"jsonrpc": "2.0", "id": "rpc-1", "result": dict(DENY)}, SESSION_ID)
        proceed = Config.from_env({"ACS_DEFAULT_DENY": "0"}).posture
        for name, tamper in TAMPERINGS.items():
            with self.subTest(name):
                outcome = classify_response(REQUEST, tamper(deny), session_id=SESSION_ID)
                self.assertIsInstance(outcome, Refused)
                self.assertFalse(proceed.resolve(outcome).proceed)

    def test_a_body_that_is_not_json_rpc_still_follows_the_posture(self) -> None:
        for body in ({"jsonrpc": "1.0", "result": dict(DENY)}, {"jsonrpc": "2.0", "result": "deny"}):
            with self.subTest(body=body):
                outcome = classify_response(REQUEST, {**body, "id": "rpc-1"}, session_id=SESSION_ID)
                self.assertEqual(outcome.cause, "malformed_response")


class TamperedHandshakeAnswers(_SessionTest):
    def test_a_signed_handshake_answer_altered_into_a_rejected_shape_refuses_the_session(self) -> None:
        answers = {
            "server hello": _signed({"jsonrpc": "2.0", "id": "hello-1", "result": dict(HELLO)}, SESSION_ID),
            "refusal": _signed({"jsonrpc": "2.0", "id": "hello-1",
                                "error": {"code": -32000, "message": "refused"}}, SESSION_ID),
        }
        for answer_name, answer in answers.items():
            for name, tamper in TAMPERINGS.items():
                with self.subTest(answer_name, tampering=name):
                    outcome = _handshake._classify_hello(CLIENT_HELLO, tamper(answer), SESSION_ID)
                    self.assertIsInstance(outcome, SessionRefused)
