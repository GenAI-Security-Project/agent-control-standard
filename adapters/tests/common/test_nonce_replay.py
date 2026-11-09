"""§10.3 replay protection, the `nonce` half: a duplicate is refused in a sliding window.

`SessionState` has carried `seen_nonces` for a while — written, merged across instances, evicted on
a window — and nothing ever read it back, so a second envelope carrying the same nonce was allowed.
These tests pin the read-back: the repeat is refused with `REPLAY_DETECTED`, a second Guardian
sharing the state directory refuses it too, and envelopes without a nonce are unaffected.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
import urllib.request
import uuid

from acs import core
from acs.testing.harness import launch_guardian, sign_for_test, signing_env

ARGUMENTS = {"file_path": {"value": "report.txt"}, "content": {"value": "line 01: same bytes\n"}}


class NonceReplay(unittest.TestCase):
    def _start(self, statedir: str) -> tuple:
        env = os.environ.copy()
        env.update(signing_env())
        env.pop("ACS_HMAC_SECRET_FILE", None)
        env["ACS_GUARDIAN_STATE_DIR"] = statedir
        return launch_guardian(env=env)

    def _post(self, port: int, body: dict) -> dict:
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/acs",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10.0) as response:
            return json.loads(response.read().decode())

    def _envelope(self, session_id: str, request_id: str, method: str, payload: dict,
                  nonce: str | None = None) -> dict:
        params = {
            "acs_version": "0.1.0",
            "request_id": request_id,
            "timestamp": core.iso8601_now(),
            "metadata": {"agent_id": "nonce-test", "session_id": session_id, "platform": "test"},
            "payload": payload,
        }
        if nonce is not None:
            params["nonce"] = nonce
        return sign_for_test({"jsonrpc": "2.0", "id": str(uuid.uuid4()),
                              "method": method, "params": params})

    def _open_session(self, port: int, session_id: str) -> None:
        response = self._post(port, self._envelope(session_id, str(uuid.uuid4()), "steps/sessionStart", {}))
        self.assertIn("result", response, f"sessionStart refused: {response}")

    def _step(self, port: int, session_id: str, nonce: str | None) -> dict:
        payload = {"tool": {"name": "Write"}, "arguments": ARGUMENTS}
        return self._post(port, self._envelope(session_id, str(uuid.uuid4()),
                                               "steps/toolCallRequest", payload, nonce=nonce))

    def test_duplicate_nonce_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as statedir:
            process, port = self._start(statedir)
            try:
                session_id = str(uuid.uuid4())
                self._open_session(port, session_id)
                nonce = uuid.uuid4().hex
                first = self._step(port, session_id, nonce)
                self.assertIn("result", first, f"first send must be decided: {first}")
                second = self._step(port, session_id, nonce)
                self.assertIn("error", second,
                              f"duplicate nonce was decided instead of refused: {second}")
                self.assertEqual(second["error"]["code"], -32005)
            finally:
                process.terminate()
                process.wait(timeout=10)

    def test_second_instance_refuses_the_same_nonce(self) -> None:
        with tempfile.TemporaryDirectory() as statedir:
            process_a, port_a = self._start(statedir)
            process_b, port_b = self._start(statedir)
            try:
                session_id = str(uuid.uuid4())
                self._open_session(port_a, session_id)
                nonce = uuid.uuid4().hex
                self.assertIn("result", self._step(port_a, session_id, nonce))
                refused = self._step(port_b, session_id, nonce)
                self.assertIn("error", refused,
                              f"second Guardian accepted a nonce the first had seen: {refused}")
                self.assertEqual(refused["error"]["code"], -32005)
            finally:
                for process in (process_a, process_b):
                    process.terminate()
                    process.wait(timeout=10)

    def test_envelopes_without_a_nonce_are_unaffected(self) -> None:
        with tempfile.TemporaryDirectory() as statedir:
            process, port = self._start(statedir)
            try:
                session_id = str(uuid.uuid4())
                self._open_session(port, session_id)
                for _ in range(2):
                    response = self._step(port, session_id, None)
                    self.assertIn("result", response,
                                  f"a step without a nonce must still be decided: {response}")
            finally:
                process.terminate()
                process.wait(timeout=10)
