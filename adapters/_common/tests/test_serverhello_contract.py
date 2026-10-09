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
import sys
import tempfile
import unittest
import urllib.error
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import acs_common
from test_harness import (
    ProgrammableGuardian,
    build_local_resolver,
    launch_guardian,
    validate_response_envelope,
)
from jsonschema import Draft202012Validator


class ServerHelloContract(unittest.TestCase):
    """Fresh and cached responses use result directly, without losing trust checks."""

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
        self._stack.enter_context(mock.patch.dict(os.environ, clean_environment, clear=True))
        self._stack.enter_context(mock.patch.object(
            acs_common, "_HANDSHAKE_CACHE_DIR", self.cache_directory))
        self._stack.enter_context(mock.patch.object(acs_common, "_HANDSHAKE_CACHE_TTL_S", 3600))
        self._stack.enter_context(mock.patch.object(acs_common, "_HANDSHAKE_FAILURE_TTL_S", 30))
        self.audit = self._stack.enter_context(mock.patch.object(acs_common, "audit_event"))
        self.requests: list[dict] = []
        self.responses: list[dict] = []
        self.hello = {
            "negotiated_version": "0.1.0",
            "methods_evaluated": ["steps/toolCallRequest"],
            "selected_transport": "http",
            "timeout_config": {"default_ms": 5000},
            "on_decision_failure": "deny",
        }

    def _run(self, url: str | None = None) -> dict | None:
        return acs_common.ensure_session_handshake(
            guardian_url=url or self.URL, session_id=self.SESSION,
            agent_id="serverhello-regression", platform="test",
            methods_implemented=["steps/toolCallRequest"],
            profiles_supported=[], transports_supported=["http"], timeout=2,
        )

    def _sign(self, response: dict) -> dict:
        return acs_common.sign_envelope(
            response, session_id=self.SESSION,
            key=acs_common.derive_session_key(self.SECRET.encode(), self.SESSION),
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

    def _cache(self, url: str | None = None) -> Path:
        return acs_common._handshake_cache_path(self.SESSION, url or self.URL)

    def _seed(self, result: dict) -> dict:
        response = self._sign({
            "jsonrpc": "2.0", "id": "previous-handshake",
            "result": copy.deepcopy(result),
        })
        self.cache_directory.mkdir(parents=True, exist_ok=True)
        self._cache().write_text(json.dumps(response))
        return response

    def _assert_hello_schema(self, result: dict) -> None:
        schema, resolver = build_local_resolver("handshake.json")
        Draft202012Validator(
            schema["$defs"]["ServerHello"], resolver=resolver,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        ).validate(result)

    def _assert_audit(self, event: str, cause: str | None = None) -> None:
        matches = [call for call in self.audit.call_args_list
                   if call.args and call.args[0] == event
                   and (cause is None or call.kwargs.get("cause") == cause)]
        self.assertTrue(matches, self.audit.call_args_list)

    def test_fresh_direct_result_is_cached_as_the_whole_signed_envelope(self):
        with mock.patch.object(acs_common.urllib.request, "urlopen", side_effect=self._respond):
            result = self._run()
        self.assertIsInstance(result, dict)
        self._assert_hello_schema(result)
        self.assertEqual(result["negotiated_version"], "0.1.0")
        self.assertNotIn("decision", result)
        cached = json.loads(self._cache().read_text())
        self.assertEqual(cached, self.responses[0])
        self.assertEqual(cached["result"], result)
        self.assertIn("signature", cached["result"])
        self.assertTrue(acs_common.verify_signature(cached, session_id=self.SESSION))
        self.assertEqual(stat.S_IMODE(self._cache().stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.cache_directory.stat().st_mode), 0o700)
        self.assertEqual(validate_response_envelope(cached), [])

    def test_preseeded_direct_cache_is_reverified_without_network(self):
        response = self._seed(self.hello)
        with mock.patch.object(acs_common.urllib.request, "urlopen") as network, \
                mock.patch.object(acs_common, "verify_signature",
                                  wraps=acs_common.verify_signature) as verify:
            result = self._run()
        self.assertEqual(result, response["result"])
        network.assert_not_called()
        verify.assert_called_once_with(response, session_id=self.SESSION)

    def test_two_calls_perform_one_handshake_and_verify_both_reads(self):
        with mock.patch.object(acs_common.urllib.request, "urlopen",
                               side_effect=self._respond) as network, \
                mock.patch.object(acs_common, "verify_signature",
                                  wraps=acs_common.verify_signature) as verify:
            first = self._run()
            second = self._run()
        self.assertIsNotNone(first)
        self.assertEqual(first, second)
        self.assertEqual(network.call_count, 1)
        self.assertEqual(verify.call_count, 2)

    def test_tampered_cached_posture_is_detected_and_not_trusted(self):
        response = self._seed(self.hello)
        response["result"]["on_decision_failure"] = "proceed"
        self._cache().write_text(json.dumps(response))
        with mock.patch.object(acs_common.urllib.request, "urlopen",
                               side_effect=self._respond) as network:
            result = self._run()
        self.assertEqual(network.call_count, 1)
        self.assertEqual(result["on_decision_failure"], "deny")
        self._assert_audit("handshake_cache_signature_invalid")

    def test_fresh_response_with_invalid_signature_is_not_cached(self):
        def respond(request, timeout=None):
            response = json.loads(self._respond(request).read())
            response["result"]["on_decision_failure"] = "proceed"
            return io.BytesIO(json.dumps(response).encode())
        with mock.patch.object(acs_common.urllib.request, "urlopen", side_effect=respond):
            self.assertIsNone(self._run())
        self.assertFalse(self._cache().exists())
        self._assert_audit("handshake_failed", "server_hello_signature_invalid")

    def test_unsigned_response_is_refused_when_a_key_is_configured(self):
        def respond(request, timeout=None):
            response = json.loads(self._respond(request).read())
            response["result"].pop("signature")
            return io.BytesIO(json.dumps(response).encode())
        with mock.patch.object(acs_common.urllib.request, "urlopen", side_effect=respond):
            self.assertIsNone(self._run())
        self.assertFalse(self._cache().exists())
        self._assert_audit("handshake_failed", "server_hello_signature_invalid")

    def test_signed_response_for_a_different_rpc_id_is_refused(self):
        def respond(request, timeout=None):
            response = json.loads(self._respond(request).read())
            response["id"] = "a-different-request"
            self._sign(response)
            return io.BytesIO(json.dumps(response).encode())
        with mock.patch.object(acs_common.urllib.request, "urlopen", side_effect=respond):
            self.assertIsNone(self._run())
        self.assertFalse(self._cache().exists())
        self._assert_audit("handshake_failed", "response_id_mismatch")

    def test_signed_legacy_result_wrapper_is_not_a_serverhello(self):
        self.hello = {
            "type": "final", "acs_version": "0.1.0",
            "request_id": str(uuid.uuid4()), "decision": "allow",
            "payload": copy.deepcopy(self.hello),
        }
        with mock.patch.object(acs_common.urllib.request, "urlopen", side_effect=self._respond):
            self.assertIsNone(self._run())
        self.assertFalse(self._cache().exists())
        self._assert_audit("handshake_failed", "invalid_server_hello")

    def test_signed_legacy_wrapped_cache_triggers_a_new_handshake(self):
        self._seed({
            "type": "final", "acs_version": "0.1.0",
            "request_id": str(uuid.uuid4()), "decision": "allow",
            "payload": copy.deepcopy(self.hello),
        })
        with mock.patch.object(acs_common.urllib.request, "urlopen",
                               side_effect=self._respond) as network:
            result = self._run()
        self.assertEqual(network.call_count, 1)
        self._assert_hello_schema(result)
        self.assertEqual(json.loads(self._cache().read_text()), self.responses[0])

    def test_unknown_fields_do_not_change_result_extraction(self):
        # The spec ignores unknown fields. Even an extension named payload
        # is not a reason to unwrap a valid direct ServerHello.
        self.hello["payload"] = {"future_extension": True}
        self.hello["another_extension"] = "preserve"
        with mock.patch.object(acs_common.urllib.request, "urlopen", side_effect=self._respond):
            result = self._run()
        self._assert_hello_schema(result)
        self.assertEqual(result["payload"], {"future_extension": True})
        self.assertEqual(result["another_extension"], "preserve")

    def test_empty_result_is_not_cached(self):
        self.hello = {}
        with mock.patch.object(acs_common.urllib.request, "urlopen", side_effect=self._respond):
            self.assertIsNone(self._run())
        self.assertFalse(self._cache().exists())

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

    def test_real_python_guardian_returns_a_signed_direct_result(self):
        env = os.environ.copy()
        env["ACS_GUARDIAN_STATE_DIR"] = str(self.directory / "guardian-state")
        proc, port = launch_guardian(env=env)
        try:
            url = f"http://127.0.0.1:{port}/acs"
            result = self._run(url)
            self._assert_hello_schema(result)
            cached = json.loads(self._cache(url).read_text())
            self.assertEqual(result, cached["result"])
            self.assertEqual(validate_response_envelope(cached), [])
            self.assertTrue(acs_common.verify_signature(cached, session_id=self.SESSION))
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
