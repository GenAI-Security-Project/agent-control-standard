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
            "request_id": body["params"]["request_id"], "decision": "allow"}},
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

    def test_a_request_that_still_cannot_be_signed_fails_closed_at_an_enforced_step(self) -> None:
        for gate, proceed in ((False, True), (True, False)):
            with self.subTest(gate=gate):
                result, sent = self._send(_request(note=b"bytes"), self._signed_allow, PROCEED, gate=gate)
                self.assertEqual(sent, [], "nothing unsigned goes on the wire")
                self.assertEqual((result.proceed, result.cause, result.fields["failure_class"]),
                                 (proceed, "envelope_not_signable", "observed_agent_error"))


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
