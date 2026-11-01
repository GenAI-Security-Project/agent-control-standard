"""Handshake result-shape regressions; use real shared signing and schemas.

These tests do not claim TypeScript Guardian interoperability. They exercise
Python's shared helper, its signed fixture, and the shipped Python Guardian.
"""
from __future__ import annotations

import copy
from contextlib import ExitStack
import io
import json
import os
import stat
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from acs import client
from acs import core
from acs.client import Config, Negotiated, NoAnswer, SessionRefused
from acs.client import _exchange
from acs.client import _handshake as client_handshake
from acs.testing.harness import (
    ProgrammableGuardian,
    build_local_resolver,
    launch_guardian,
    validate_response_envelope,
)
from jsonschema import Draft202012Validator


class ServerHelloContract(unittest.TestCase):
    """Fresh and stored decisions use the direct ServerHello result, without losing trust checks."""

    SECRET = "serverhello-regression-test-secret-not-for-production"
    SESSION = "77777777-7777-4777-8777-777777777777"
    URL = "http://127.0.0.1:8787/acs"

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="acs-serverhello-")
        self.addCleanup(temporary.cleanup)
        self._stack = ExitStack()
        self.addCleanup(self._stack.close)
        self.directory = Path(temporary.name)
        self.cache_directory = self.directory / "cache"
        clean_environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith("ACS_")
        }
        clean_environment["ACS_HMAC_SECRET"] = self.SECRET
        clean_environment["ACS_HMAC_KEY_ID"] = "test-key"
        self._stack.enter_context(mock.patch.dict(os.environ, clean_environment, clear=True))
        self._stack.enter_context(mock.patch.object(client_handshake, "_HANDSHAKE_CACHE_DIR", self.cache_directory))
        self.audit = self._stack.enter_context(mock.patch.object(client_handshake, "audit_event"))
        self.requests: list[dict] = []
        self.responses: list[dict] = []
        self.hello = {
            "negotiated_version": "0.1.0",
            "methods_evaluated": ["steps/toolCallRequest"],
            "selected_transport": "http",
            "timeout_config": {"default_ms": 5000},
            "on_decision_failure": "deny",
        }

    def _run(self, url: str | None = None):
        return client.open_session(
            config=Config.from_env({"ACS_GUARDIAN_URL": url or self.URL}),
            session_id=self.SESSION, agent_id="serverhello-regression", platform="test",
            methods_implemented=["steps/toolCallRequest"],
            profiles_supported=[], transports_supported=["http"], timeout=2,
        )

    def _sign(self, response: dict) -> dict:
        return client.sign_envelope(
            response, session_id=self.SESSION,
            key=core.derive_session_key(self.SECRET.encode(), self.SESSION), key_id="test-key",
        )

    def _respond(self, request, timeout=None):
        incoming = json.loads(request.data)
        self.requests.append(incoming)
        response = self._sign({
            "jsonrpc": "2.0", "id": incoming["id"],
            "result": copy.deepcopy(self.hello),
        })
        self.responses.append(copy.deepcopy(response))
        return io.BytesIO(json.dumps(response).encode())

    def _record(self, url: str | None = None) -> Path:
        return client_handshake._handshake_cache_path(self.SESSION, url or self.URL)

    def _assert_hello_schema(self, result) -> None:
        schema, resolver = build_local_resolver("handshake.json")
        Draft202012Validator(
            schema["$defs"]["ServerHello"], resolver=resolver,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        ).validate(dict(result))

    def _assert_audit(self, event: str, cause: str | None = None) -> None:
        matches = [call for call in self.audit.call_args_list
                   if call.args and call.args[0] == event
                   and (cause is None or call.kwargs.get("cause") == cause)]
        self.assertTrue(matches, self.audit.call_args_list)

    def test_fresh_direct_result_is_negotiated_and_stored(self):
        with mock.patch.object(_exchange, "_open", side_effect=self._respond):
            session = self._run()
        self.assertIsInstance(session, Negotiated)
        self._assert_hello_schema(session.server_hello)
        self.assertNotIn("decision", session.server_hello)
        self.assertEqual(validate_response_envelope(self.responses[0]), [])
        record = json.loads(self._record().read_text())
        self.assertEqual(record["decision"], "negotiated")
        self.assertEqual(record["server_hello"], dict(session.server_hello))
        self.assertTrue(record["mac"])
        self.assertEqual(stat.S_IMODE(self._record().stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.cache_directory.stat().st_mode), 0o700)

    def test_a_stored_decision_is_read_without_network(self):
        with mock.patch.object(_exchange, "_open", side_effect=self._respond):
            first = self._run()
        with mock.patch.object(_exchange, "_open") as network:
            second = self._run()
        network.assert_not_called()
        self.assertEqual(first, second)

    def test_two_calls_perform_one_handshake(self):
        with mock.patch.object(_exchange, "_open",
                               side_effect=self._respond) as network:
            first = self._run()
            second = self._run()
        self.assertIsInstance(first, Negotiated)
        self.assertEqual(first, second)
        self.assertEqual(network.call_count, 1)

    def test_a_modified_record_refuses_the_session_without_network(self):
        with mock.patch.object(_exchange, "_open", side_effect=self._respond):
            self._run()
        record = json.loads(self._record().read_text())
        record["server_hello"]["on_decision_failure"] = "proceed"
        self._record().write_text(json.dumps(record))
        with mock.patch.object(_exchange, "_open") as network:
            session = self._run()
        network.assert_not_called()
        self.assertEqual(session, SessionRefused("session_record_invalid", {"record": str(self._record())}))

    def test_fresh_response_with_invalid_signature_refuses_the_session(self):
        def respond(request, timeout=None):
            response = json.loads(self._respond(request).read())
            response["result"]["on_decision_failure"] = "proceed"
            return io.BytesIO(json.dumps(response).encode())
        with mock.patch.object(_exchange, "_open", side_effect=respond):
            session = self._run()
        self.assertEqual(session, SessionRefused("server_hello_signature_invalid"))
        self.assertEqual(json.loads(self._record().read_text())["decision"], "refused")
        self._assert_audit("session_refused", "server_hello_signature_invalid")

    def test_unsigned_response_refuses_the_session_when_a_key_is_configured(self):
        def respond(request, timeout=None):
            response = json.loads(self._respond(request).read())
            response["result"].pop("signature")
            return io.BytesIO(json.dumps(response).encode())
        with mock.patch.object(_exchange, "_open", side_effect=respond):
            session = self._run()
        self.assertEqual(session, SessionRefused("server_hello_signature_invalid"))

    def test_signed_response_for_a_different_rpc_id_refuses_the_session(self):
        def respond(request, timeout=None):
            response = json.loads(self._respond(request).read())
            response["id"] = "a-different-request"
            self._sign(response)
            return io.BytesIO(json.dumps(response).encode())
        with mock.patch.object(_exchange, "_open", side_effect=respond):
            session = self._run()
        self.assertEqual(session, SessionRefused("response_binding_mismatch"))

    def test_signed_legacy_result_wrapper_is_no_answer(self):
        self.hello = {
            "type": "final", "acs_version": "0.1.0",
            "request_id": str(uuid.uuid4()), "decision": "allow",
            "payload": copy.deepcopy(self.hello),
        }
        with mock.patch.object(_exchange, "_open", side_effect=self._respond):
            session = self._run()
        self.assertEqual(session, NoAnswer("invalid_server_hello"))
        self._assert_audit("session_without_negotiated_guardian", "invalid_server_hello")

    def test_an_earlier_adapter_cache_refuses_the_session(self):
        # The earlier cache held the signed JSON-RPC envelope, bound to no Guardian URL.
        self.cache_directory.mkdir(parents=True)
        self._record().write_text(json.dumps(self._sign({
            "jsonrpc": "2.0", "id": "previous-handshake", "result": copy.deepcopy(self.hello),
        })))
        with mock.patch.object(_exchange, "_open") as network:
            session = self._run()
        network.assert_not_called()
        self.assertEqual(session, SessionRefused("session_record_legacy", {"record": str(self._record())}))

    def test_unknown_fields_do_not_change_result_extraction(self):
        # The spec ignores unknown fields. Even an extension named payload
        # is not a reason to unwrap a valid direct ServerHello.
        self.hello["payload"] = {"future_extension": True}
        self.hello["another_extension"] = "preserve"
        with mock.patch.object(_exchange, "_open", side_effect=self._respond):
            session = self._run()
        self._assert_hello_schema(session.server_hello)
        self.assertEqual(session.server_hello["payload"], {"future_extension": True})
        self.assertEqual(session.server_hello["another_extension"], "preserve")

    def test_empty_result_is_no_answer(self):
        self.hello = {}
        with mock.patch.object(_exchange, "_open", side_effect=self._respond):
            self.assertEqual(self._run(), NoAnswer("invalid_server_hello"))

    def test_fixture_emits_the_handshake_specific_schema(self):
        guardian = ProgrammableGuardian()
        self.addCleanup(guardian._server.server_close)
        result = guardian._default_handshake({
            "params": {"request_id": str(uuid.uuid4()), "payload": {
                "methods_implemented": ["steps/toolCallRequest"],
            }},
        })
        self._assert_hello_schema(result)
        self.assertNotIn("decision", result)
        self.assertNotIn("payload", result)

    def test_real_python_guardian_answers_with_what_the_client_offered(self):
        env = os.environ.copy()
        env["ACS_GUARDIAN_STATE_DIR"] = str(self.directory / "guardian-state")
        proc, port = launch_guardian(env=env)
        self.addCleanup(proc.wait, 3)
        self.addCleanup(proc.terminate)
        url = f"http://127.0.0.1:{port}/acs"
        for i, (transports, profiles) in enumerate(((["https"], []), (["http"], ["acs-core"]))):
            with self.subTest(transports=transports, profiles=profiles):
                session = client.open_session(
                    config=Config.from_env({"ACS_GUARDIAN_URL": url}), session_id=f"{self.SESSION}-{i}",
                    agent_id="offer-test", platform="test", methods_implemented=["steps/toolCallRequest"],
                    profiles_supported=profiles, transports_supported=transports, timeout=2)
                self.assertIsInstance(session, Negotiated)
                self.assertEqual(session.server_hello["selected_transport"], transports[0])
                self.assertEqual(session.server_hello["profiles_accepted"], profiles)

    def test_real_python_guardian_returns_a_signed_direct_result(self):
        env = os.environ.copy()
        env["ACS_GUARDIAN_STATE_DIR"] = str(self.directory / "guardian-state")
        proc, port = launch_guardian(env=env)
        responses: list[dict] = []

        def recording_post(*args, **kwargs):
            response = _exchange.post(*args, **kwargs)
            responses.append(response)
            return response
        try:
            url = f"http://127.0.0.1:{port}/acs"
            with mock.patch.object(client_handshake, "post", side_effect=recording_post):
                session = self._run(url)
            self.assertIsInstance(session, Negotiated)
            self._assert_hello_schema(session.server_hello)
            self.assertEqual(validate_response_envelope(responses[0]), [])
            self.assertTrue(client.verify_signature(responses[0], session_id=self.SESSION))
            self.assertEqual(responses[0]["result"], dict(session.server_hello))
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
