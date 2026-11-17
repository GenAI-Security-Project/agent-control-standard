"""round_trip and open_session hand each envelope sent and received to an on_wire callback (issue #576, PREMORTEM P6)."""
from __future__ import annotations

import os
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any
from unittest import mock

from acs.client import (
    Config,
    Decided,
    FailPosture,
    GuardianHTTPError,
    Negotiated,
    Resolution,
    SessionRefused,
    open_session,
    round_trip,
    sign_envelope,
)
from acs.client import _exchange, _handshake
from acs.core import ACS_VERSION, request_envelope
from acs.testing.harness import signing_env

URL = "http://127.0.0.1:8787/acs"
SESSION = "55555555-5555-4555-8555-555555555555"
METADATA = {"agent_id": "test", "session_id": SESSION, "platform": "test"}
PROCEED = FailPosture(deny_on_failure=False, timeout_s=5.0)
HELLO = {"negotiated_version": ACS_VERSION, "methods_evaluated": ["steps/toolCallRequest"],
         "selected_transport": "http", "signature_algorithms_supported": ["HMAC-SHA256"],
         "timeout_config": {"default_ms": 5000}, "on_decision_failure": "proceed",
         "profiles_accepted": ["acs-core"]}


def step_request() -> dict:
    return request_envelope("steps/toolCallRequest", request_id=str(uuid.uuid4()), metadata=METADATA,
                            payload={"tool": {"name": "ls"}, "arguments": {}})


def decision_for(request: dict, decision: str = "allow") -> dict:
    result = {"type": "final", "acs_version": ACS_VERSION, "request_id": request["params"]["request_id"],
              "decision": decision}
    return sign_envelope({"jsonrpc": "2.0", "id": request["id"], "result": result}, session_id=SESSION)


def server_hello_for(hello: dict) -> dict:
    session_id = hello["params"]["metadata"]["session_id"]
    return sign_envelope({"jsonrpc": "2.0", "id": hello["id"], "result": dict(HELLO)}, session_id=session_id)


class Recorder:
    def __init__(self, fail_on: str | None = None) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.fail_on = fail_on

    def __call__(self, direction: str, envelope: Any) -> None:
        self.calls.append((direction, envelope))
        if direction == self.fail_on:
            raise RuntimeError(f"recorder failed on {direction}")


class OnWireTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="acs-on-wire-")
        self.addCleanup(temporary.cleanup)
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        for patcher in (mock.patch.dict(os.environ, {**env, **signing_env()}, clear=True),
                        mock.patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", Path(temporary.name))):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.audit = mock.patch.object(_exchange, "audit_event").start()
        mock.patch.object(_handshake, "audit_event").start()
        self.addCleanup(mock.patch.stopall)

    def _round_trip(self, post: Any, recorder: Recorder, request: dict | None = None,
                    posture: FailPosture = PROCEED) -> tuple[dict, Any, mock.Mock]:
        request = request or step_request()
        with mock.patch.object(_exchange, "post", side_effect=post) as sent:
            outcome = round_trip(request, guardian_url=URL, posture=posture, session_id=SESSION,
                                 on_wire=recorder)
        return request, outcome, sent

    def _open(self, recorder: Recorder, post: Any = None, session_id: str = SESSION) -> Any:
        config = Config.from_env({"ACS_GUARDIAN_URL": URL})
        answer = post or (lambda hello, **_: server_hello_for(hello))
        with mock.patch.object(_handshake, "post", side_effect=answer) as sent:
            decision = open_session(config=config, session_id=session_id, agent_id="test", platform="test",
                                    methods_implemented=["steps/toolCallRequest"], on_wire=recorder)
        return decision, sent

    def test_round_trip_reports_the_signed_request_then_the_answer(self) -> None:
        recorder = Recorder()
        answers = []

        def post(request: dict, **_: Any) -> dict:
            answers.append(decision_for(request))
            return answers[-1]

        request, outcome, _ = self._round_trip(post, recorder)
        self.assertIsInstance(outcome, Decided)
        self.assertEqual([d for d, _ in recorder.calls], ["req", "resp"])
        self.assertEqual(recorder.calls[0][1], request)
        self.assertIn("signature", recorder.calls[0][1]["params"])
        self.assertEqual(recorder.calls[1][1], answers[0])

    def test_on_wire_gets_copies(self) -> None:
        def mutate(direction: str, envelope: Any) -> None:
            envelope.clear()

        request = step_request()
        with mock.patch.object(_exchange, "post", side_effect=lambda r, **_: decision_for(r)):
            outcome = round_trip(request, guardian_url=URL, posture=PROCEED, session_id=SESSION, on_wire=mutate)
        self.assertIsInstance(outcome, Decided)
        self.assertEqual(outcome.response["result"]["decision"], "allow")
        self.assertIn("signature", request["params"])

    def test_no_answer_means_no_resp_call(self) -> None:
        recorder = Recorder()
        _, outcome, _ = self._round_trip(TimeoutError("timed out"), recorder)
        self.assertEqual([d for d, _ in recorder.calls], ["req"])
        self.assertIsInstance(outcome, Resolution)
        self.assertEqual(outcome.cause, "decision_timeout")

    def test_an_http_error_body_is_reported(self) -> None:
        recorder = Recorder()

        def post(request: dict, **_: Any) -> dict:
            body = {"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32603, "message": "Internal error"}}
            raise GuardianHTTPError(500, body)

        self._round_trip(post, recorder)
        self.assertEqual([d for d, _ in recorder.calls], ["req", "resp"])
        self.assertEqual(recorder.calls[1][1]["error"]["code"], -32603)

    def test_a_non_json_rpc_http_error_is_not_reported(self) -> None:
        recorder = Recorder()

        def post(request: dict, **_: Any) -> dict:
            raise GuardianHTTPError(503, None)

        _, outcome, _ = self._round_trip(post, recorder)
        self.assertEqual([d for d, _ in recorder.calls], ["req"])
        self.assertEqual(outcome.cause, "http_503_error")

    def test_a_failing_req_callback_sends_nothing_and_blocks(self) -> None:
        recorder = Recorder(fail_on="req")
        _, outcome, sent = self._round_trip(lambda r, **_: decision_for(r), recorder)
        sent.assert_not_called()
        self.assertIsInstance(outcome, Resolution)
        self.assertFalse(outcome.proceed)
        self.assertEqual(outcome.cause, "on_wire_failed")
        self.assertEqual(outcome.fields["failure_class"], "observed_agent_error")
        self.assertEqual(outcome.fields["dir"], "req")
        self.assertTrue(any(c.args[0] == "on_wire_failed" for c in self.audit.call_args_list))

    def test_a_failing_resp_callback_blocks_a_decision(self) -> None:
        recorder = Recorder(fail_on="resp")
        _, outcome, sent = self._round_trip(lambda r, **_: decision_for(r), recorder)
        sent.assert_called_once()
        self.assertIsInstance(outcome, Resolution)
        self.assertFalse(outcome.proceed)
        self.assertEqual(outcome.cause, "on_wire_failed")
        self.assertEqual(outcome.fields["dir"], "resp")

    def test_open_session_reports_the_client_hello_and_its_answer(self) -> None:
        recorder = Recorder()
        decision, _ = self._open(recorder)
        self.assertIsInstance(decision, Negotiated)
        self.assertEqual([d for d, _ in recorder.calls], ["req", "resp"])
        self.assertEqual(recorder.calls[0][1]["method"], "handshake/hello")
        self.assertIn("signature", recorder.calls[0][1]["params"])
        self.assertEqual(recorder.calls[1][1]["id"], recorder.calls[0][1]["id"])

    def test_a_failing_hello_callback_refuses_the_session(self) -> None:
        for direction in ("req", "resp"):
            with self.subTest(direction=direction):
                decision, sent = self._open(Recorder(fail_on=direction), session_id=f"hello-{direction}")
                self.assertIsInstance(decision, SessionRefused)
                self.assertEqual(decision.cause, "on_wire_failed")
                self.assertEqual(decision.fields["dir"], direction)
                self.assertEqual(sent.call_count, 0 if direction == "req" else 1)

    def test_a_stored_session_reports_nothing(self) -> None:
        self._open(Recorder())
        recorder = Recorder()
        decision, sent = self._open(recorder)
        self.assertIsInstance(decision, Negotiated)
        sent.assert_not_called()
        self.assertEqual(recorder.calls, [])


if __name__ == "__main__":
    unittest.main()
