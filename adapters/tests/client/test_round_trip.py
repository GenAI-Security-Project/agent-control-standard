from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from typing import Any
from unittest import mock

from acs.client import (Decided, FailPosture, Resolution, close_turn, current_turn, open_turn, round_trip,
                        verify_signature)
from acs.client import _exchange, _store
from acs.core import derive_session_key, request_envelope, sign_with_key

SECRET = "round-trip-secret-padded-to-32-bytes"
SESSION = "44444444-4444-4444-8444-444444444444"
URL = "http://127.0.0.1:8787/acs"
PROCEED = FailPosture(deny_on_failure=False, timeout_s=2.0, per_method_timeout_s={"steps/toolCallResult": 0.3})
DENY = FailPosture(deny_on_failure=True, timeout_s=2.0)


def _request(**payload: Any) -> dict:
    return request_envelope("steps/toolCallResult", request_id="55555555-5555-4555-8555-555555555555",
                            metadata={"agent_id": "a", "session_id": SESSION, "platform": "test"},
                            payload=payload)


@mock.patch.dict(os.environ, {"ACS_HMAC_SECRET": SECRET, "ACS_HMAC_KEY_ID": "test-key", "ACS_HMAC_SECRET_FILE": "", "ACS_HMAC_KEY_ID": "test-key"})
class RoundTrip(unittest.TestCase):
    def _send(self, request: dict, answer, posture: FailPosture = PROCEED, gate: bool = False):
        sent: list[tuple[dict, float]] = []

        def urlopen(req: Any, timeout: float):
            body = json.loads(req.data)
            sent.append((body, timeout))
            return answer(body)

        with mock.patch.object(_exchange, "_open", side_effect=urlopen):
            result = round_trip(request, guardian_url=URL, posture=posture, session_id=SESSION, gate=gate)
        return result, sent

    @staticmethod
    def _signed_allow(body: dict):
        response = sign_with_key({"jsonrpc": "2.0", "id": body["id"], "result": {
            "type": "final", "acs_version": "0.1.0", "request_id": body["params"]["request_id"], "decision": "allow"}},
            derive_session_key(SECRET.encode(), SESSION), key_id="test-key")
        return io.BytesIO(json.dumps(response).encode())

    def test_an_edit_after_building_is_covered_by_the_one_signature(self) -> None:
        request = _request(request_id_ref="66666666-6666-4666-8666-666666666666", tool={"name": "x"})
        request["params"]["payload"].pop("request_id_ref")
        result, sent = self._send(request, self._signed_allow)
        self.assertIsInstance(result, Decided)
        wire = sent[0][0]
        self.assertNotIn("request_id_ref", wire["params"]["payload"])
        self.assertTrue(verify_signature(wire, session_id=SESSION), "the signature must cover what was sent")

    def test_each_method_waits_for_its_negotiated_timeout(self) -> None:
        _, sent = self._send(_request(), self._signed_allow)
        self.assertEqual(sent[0][1], 0.3)

    def test_failures_resolve_with_their_message(self) -> None:
        def refused(body: dict):
            raise urllib.error.URLError(ConnectionRefusedError(61, "refused"))
        for posture, proceed, audit in ((PROCEED, True, "fail_open_bypass"),
                                        (DENY, False, "decision_failure_fail_closed")):
            with self.subTest(audit):
                result, _ = self._send(_request(), refused, posture)
                self.assertIsInstance(result, Resolution)
                self.assertEqual((result.proceed, result.audit_type, result.cause), (proceed, audit, "transport_failure"))
                self.assertIn("Guardian unreachable", result.message)

    def test_values_rfc_8785_cannot_encode_are_replaced_and_signed(self) -> None:
        stderr = io.StringIO()
        with mock.patch("sys.stderr", stderr):
            result, sent = self._send(_request(note="a\ud800b", outputs=[{"value": {"id": 2**53, "n": float("nan")}}]),
                                      self._signed_allow)
        self.assertIsInstance(result, Decided)
        [(wire, _)] = sent
        self.assertEqual(wire["params"]["payload"]["note"], "a\ufffdb")
        self.assertEqual(wire["params"]["payload"]["outputs"], [{"value": {"id": "9007199254740992", "n": "nan"}}])
        self.assertTrue(verify_signature(wire, session_id=SESSION))
        [record] = [json.loads(line[len("ACS_AUDIT "):]) for line in stderr.getvalue().splitlines()
                    if line.startswith("ACS_AUDIT ")]
        self.assertEqual((record["acs_audit_event"], record["lone_surrogates"], record["unsafe_integers"],
                          record["non_finite_numbers"]), ("envelope_normalized", 1, 1, 1))

    def test_keys_that_normalize_to_one_key_fail_closed_at_an_enforced_step(self) -> None:
        for gate, proceed in ((False, True), (True, False)):
            with self.subTest(gate=gate):
                request = _request(arguments={"\ud800": {"value": "rm -rf /"}, "\ufffd": {"value": "ls"}})
                result, sent = self._send(request, self._signed_allow, PROCEED, gate=gate)
                self.assertEqual(sent, [], "a signed view that drops one value never goes on the wire")
                self.assertEqual((result.proceed, result.cause), (proceed, "envelope_not_signable"))

    def test_an_allow_with_an_invalid_optional_field_is_a_malformed_response(self) -> None:
        def answer(body: dict):
            response = sign_with_key({"jsonrpc": "2.0", "id": body["id"], "result": {
                "type": "final", "acs_version": "0.1.0", "request_id": body["params"]["request_id"],
                "decision": "allow", "chain_hash": {"x": 1}}}, derive_session_key(SECRET.encode(), SESSION),
                key_id="test-key")
            return io.BytesIO(json.dumps(response).encode())
        for posture, proceed in ((PROCEED, True), (DENY, False)):
            with self.subTest(deny=posture.deny_on_failure):
                result, _ = self._send(_request(), answer, posture)
                self.assertEqual((result.proceed, result.cause, result.fields["failure_class"]),
                                 (proceed, "malformed_response", "malformed_response"))

    def test_a_request_that_still_cannot_be_signed_fails_closed_at_an_enforced_step(self) -> None:
        for gate, proceed in ((False, True), (True, False)):
            with self.subTest(gate=gate):
                result, sent = self._send(_request(note=b"bytes"), self._signed_allow, PROCEED, gate=gate)
                self.assertEqual(sent, [], "nothing unsigned goes on the wire")
                self.assertEqual((result.proceed, result.cause, result.fields["failure_class"]),
                                 (proceed, "envelope_not_signable", "observed_agent_error"))


class ResultProblems(unittest.TestCase):
    """result_problem flags only results response-envelope.json rejects, so it never turns a conformant answer into a failure."""
    REQUEST_ID = "55555555-5555-4555-8555-555555555555"
    ASK = {"approver": {"type": "human", "id": "owner"}, "question": "Run it?", "timeout_seconds": 60}
    DEFER = {"reason": "pending_dependency", "resolution_method": "timeout", "resolution_timeout_ms": 1000}

    def _result(self, **fields: Any) -> dict:
        return {"type": "final", "acs_version": "0.1.0", "request_id": self.REQUEST_ID, **fields}

    def test_conformant_results_pass_and_each_problem_is_also_a_schema_violation(self) -> None:
        from acs.client._exchange import result_problem
        from acs.testing.harness import validate_response_envelope
        conformant = [self._result(decision="allow"), self._result(decision="deny", reasoning="no"),
                      self._result(decision="modify", reasoning="r", modifications={"modified_content": "x"}),
                      self._result(decision="ask", reasoning="r", ask_details=self.ASK),
                      self._result(decision="defer", reasoning="r", defer_details=self.DEFER)]
        malformed = [{"decision": "allow", "request_id": self.REQUEST_ID},
                     self._result(decision="allow", type="progress"),
                     self._result(decision="allow", acs_version="0.1"),
                     {**self._result(decision="allow"), "request_id": 5},
                     self._result(decision="maybe"), self._result(decision=["deny"]), self._result(decision="DENY"),
                     self._result(decision="deny"), self._result(decision="deny", reasoning=5),
                     self._result(decision="modify", reasoning="r"),
                     self._result(decision="ask", reasoning="r"),
                     self._result(decision="ask", reasoning="r", ask_details={"question": "q"}),
                     self._result(decision="defer", reasoning="r", defer_details=[]),
                     self._result(decision="modify", reasoning="r", modifications="x"), "x",
                     self._result(decision="allow", chain_hash={"x": 1}),
                     self._result(decision="allow", reason_codes="pii"),
                     self._result(decision="allow", metadata={"evaluator": "oracle"}),
                     self._result(decision="allow",
                                  modifications={"modified_content": "x", "parameter_overrides": {"a": 1}})]
        for result in conformant:
            with self.subTest(result=result):
                self.assertIsNone(result_problem(result))
                self.assertEqual(validate_response_envelope({"jsonrpc": "2.0", "id": "1", "result": result}), [])
        composition = self._result(decision="modify", reasoning="r",
                                   modifications={"modified_content": "x", "parameter_overrides": {"a": 1}})
        self.assertNotEqual(validate_response_envelope({"jsonrpc": "2.0", "id": "1", "result": composition}), [])
        self.assertIsNone(result_problem(composition), "§6.3 makes it a DENY, not a decision failure")
        for result in malformed:
            with self.subTest(result=result):
                self.assertIsNotNone(result_problem(result))
                self.assertNotEqual(validate_response_envelope({"jsonrpc": "2.0", "id": "1", "result": result}), [])


class Turns(unittest.TestCase):
    def test_open_current_close_per_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as d, mock.patch.object(_store, "_SESSION_STATE_DIR", Path(d)):
            self.assertIsNone(current_turn(SESSION, workspace="/a"))
            open_turn(SESSION, "turn-a", workspace="/a")
            open_turn(SESSION, "turn-b", workspace="/b")
            self.assertEqual((current_turn(SESSION, workspace="/a"), current_turn(SESSION, workspace="/b")),
                             ("turn-a", "turn-b"))
            close_turn(SESSION, workspace="/a")
            self.assertEqual((current_turn(SESSION, workspace="/a"), current_turn(SESSION, workspace="/b")),
                             (None, "turn-b"))
            self.assertIsNone(current_turn(None, workspace="/b"))

    def test_a_turn_id_that_is_not_a_string_is_no_turn(self) -> None:
        with tempfile.TemporaryDirectory() as d, mock.patch.object(_store, "_SESSION_STATE_DIR", Path(d)):
            _store.save_session_state(SESSION, {"turn_id": ["not", "a", "turn"]})
            self.assertIsNone(current_turn(SESSION))


if __name__ == "__main__":
    unittest.main()
