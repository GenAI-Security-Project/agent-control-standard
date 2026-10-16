"""Exercise the production subprocess and independently validate its wire bytes."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ADAPTER = Path(__file__).resolve().parents[1] / "acs_adapter.py"
sys.path.insert(0, str(ADAPTER.parent.parent / "_common"))
from capture_guardian import CaptureGuardian
from acs_common import derive_session_key, sign_envelope
from test_harness import launch_guardian


def event(**changes):
    result = {"hook_event_name": "PreToolUse", "session_id": "thr_test_session",
              "turn_id": "turn_7", "tool_use_id": "call_3", "cwd": "/tmp/acs-test",
              "tool_name": "Bash", "tool_input": {"command": "printf harmless", "timeout_ms": 1000}}
    result.update(changes)
    return result


class WireGuardian(CaptureGuardian):
    """Alter final wire responses after signing, for binding/signature tests."""
    mutate = None
    raw_reply = None
    reply_status = 200

    def _make_handler_cls(self):
        base = super()._make_handler_cls()
        guardian = self

        class Handler(base):
            def _reply(self, reply):
                if guardian.received[-1]["method"] == "steps/toolCallRequest":
                    if guardian.mutate:
                        guardian.mutate(reply)
                    if guardian.raw_reply is not None:
                        raw = guardian.raw_reply
                        self.send_response(guardian.reply_status)
                        self.send_header("Content-Length", str(len(raw)))
                        self.end_headers()
                        try:
                            self.wfile.write(raw)
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                        return
                super()._reply(reply)
        return Handler


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.guardian = WireGuardian()
        self.guardian.start()
        self.addCleanup(self.guardian.stop)
        # Do not let a developer's ACS configuration contaminate assertions.
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("ACS_")}
        self.env.update(ACS_GUARDIAN_URL=self.guardian.url(),
                        ACS_HMAC_SECRET=self.guardian.hmac_secret,
                        ACS_HANDSHAKE_CACHE=self.tmp.name, ACS_DEFAULT_DENY="0")

    def invoke(self, input_event=None, raw=None):
        proc = subprocess.run([sys.executable, str(ADAPTER)],
                              input=raw if raw is not None else json.dumps(input_event or event()),
                              env=self.env, capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        output = json.loads(proc.stdout or "{}")
        return output.get("hookSpecificOutput", {}), proc.stderr

    def verdict(self, decision, **extra):
        self.guardian.handlers["steps/toolCallRequest"] = lambda req: {
            **self.guardian._default_allow(req), "decision": decision, **extra}

    def test_signed_emission_and_honest_capabilities(self):
        out, _ = self.invoke()
        self.assertEqual(out["permissionDecision"], "allow")
        self.assertEqual(self.guardian.methods(), ["handshake/hello", "steps/toolCallRequest"])
        self.guardian.assert_all_valid(self)
        hello = self.guardian.payload_of("handshake/hello")
        self.assertEqual(hello["methods_implemented"], ["steps/toolCallRequest"])
        self.assertEqual(hello["profiles_supported"], [])
        self.assertEqual(hello["transports_supported"], ["http"])
        self.assertEqual(hello["wrapped_protocols"], [])
        req = self.guardian.only("steps/toolCallRequest").parsed
        self.assertEqual(req["params"]["metadata"]["turn_id"], "turn_7")
        self.assertEqual(req["params"]["metadata"]["codex_session_id"], "thr_test_session")
        self.assertEqual(req["params"]["payload"]["arguments"]["command"], {"value": "printf harmless"})

    def test_denial_and_padded_denial(self):
        for decision in ("deny", " DENY "):
            with self.subTest(decision=decision):
                self.verdict(decision, reasoning="policy")
                out, _ = self.invoke()
                self.assertEqual(out["permissionDecision"], "deny")
                self.assertEqual(out["permissionDecisionReason"], "policy")

    def test_nonfinal_or_wrong_version_result_denies(self):
        for changes in ({"type": "progress"}, {"type": None}, {"acs_version": "9.0.0"}):
            with self.subTest(changes=changes):
                self.verdict("allow", **changes)
                out, audit = self.invoke()
                self.assertEqual(out["permissionDecision"], "deny")
                self.assertIn("unsupported_result_type_or_version", audit)

    def test_modify_merges_and_preserves_other_arguments(self):
        self.verdict("modify", modifications={"parameter_overrides": {"command": "printf replacement"}})
        out, _ = self.invoke()
        self.assertEqual(out["permissionDecision"], "allow")
        self.assertEqual(out["updatedInput"], {"command": "printf replacement", "timeout_ms": 1000})

    def test_patch_and_mcp_argument_mapping(self):
        for tool, value in (("apply_patch", {"command": "*** Begin Patch\n*** End Patch"}),
                            ("mcp__local__read", {"path": "sample", "options": {"limit": 2}})):
            with self.subTest(tool=tool):
                self.guardian.captures.clear()
                out, _ = self.invoke(event(tool_name=tool, tool_input=value))
                self.assertEqual(out["permissionDecision"], "allow")
                self.guardian.assert_all_valid(self)
                self.assertEqual(self.guardian.payload_of("steps/toolCallRequest")["arguments"],
                                 {k: {"value": v} for k, v in value.items()})

    def test_mcp_modify_preserves_unmodified_arguments(self):
        self.verdict("modify", modifications={"parameter_overrides": {"path": "safe"}})
        out, _ = self.invoke(event(tool_name="mcp__local__read", tool_input={"path": "old", "limit": 2}))
        self.assertEqual(out["updatedInput"], {"path": "safe", "limit": 2})

    def test_unusable_or_unsupported_decisions_deny_and_audit(self):
        for decision in ("ask", "defer", "future", None, [], 1):
            with self.subTest(decision=decision):
                self.verdict(decision)
                out, audit = self.invoke()
                self.assertEqual(out["permissionDecision"], "deny")
                self.assertIn("codex_denied", audit)

    def test_unrealizable_modify_never_partially_applies(self):
        for modifications in (None, [], {}, {"modified_content": "text"},
                              {"parameter_overrides": []},
                              {"parameter_overrides": {"command": None}},
                              {"parameter_overrides": {"command": 3}},
                              {"parameter_overrides": {"timeout_ms": 20}},
                              {"parameter_overrides": {}, "redactions": []},
                              {"parameter_overrides": {}, "future_operation": {}},
                              {"parameter_overrides": {}, "modified_content": "both"}):
            with self.subTest(modifications=modifications):
                self.verdict("modify", modifications=modifications)
                out, _ = self.invoke()
                self.assertEqual(out["permissionDecision"], "deny")
                self.assertNotIn("updatedInput", out)

    def test_malformed_input_blocks_without_traffic(self):
        for raw in ("", "[]", "null", "{", '{"hook_event_name":"PreToolUse","tool_input":NaN}',
                    '{"hook_event_name":"PreToolUse","hook_event_name":"Stop"}'):
            with self.subTest(raw=raw):
                out, _ = self.invoke(raw=raw)
                self.assertEqual(out["permissionDecision"], "deny")
        self.assertEqual(self.guardian.methods(), [])

    def test_missing_identity_and_invalid_input_block(self):
        for key in ("session_id", "turn_id", "tool_use_id", "tool_name", "tool_input"):
            with self.subTest(key=key):
                out, _ = self.invoke(event(**{key: None}))
                self.assertEqual(out["permissionDecision"], "deny")
        self.assertEqual(self.guardian.methods(), [])

    def test_unmapped_hook_is_audited_without_invented_emission(self):
        out, audit = self.invoke(event(hook_event_name="Stop"))
        self.assertEqual(out, {})
        self.assertIn("unmapped_hook_event", audit)
        self.assertEqual(self.guardian.methods(), [])

    def test_signing_secret_is_required(self):
        self.env.pop("ACS_HMAC_SECRET")
        out, audit = self.invoke()
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("signing_secret_required", audit)
        self.assertEqual(self.guardian.methods(), [])

    def test_secret_file_supported(self):
        secret = Path(self.tmp.name) / "secret"
        secret.write_text(self.guardian.hmac_secret)
        secret.chmod(0o600)
        self.env.pop("ACS_HMAC_SECRET")
        self.env["ACS_HMAC_SECRET_FILE"] = str(secret)
        out, _ = self.invoke()
        self.assertEqual(out["permissionDecision"], "allow")
        self.guardian.assert_all_valid(self)

    def test_dependency_failure_returns_native_deny(self):
        shadow = Path(self.tmp.name) / "shadow"
        shadow.mkdir()
        (shadow / "rfc8785.py").write_text("raise ImportError('test missing dependency')\n")
        self.env["PYTHONPATH"] = str(shadow)
        out, audit = self.invoke()
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("adapter_unavailable", audit)

    def test_unsigned_step_response_denies(self):
        self.guardian.mutate = lambda reply: reply["result"].pop("signature")
        out, audit = self.invoke()
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("response_signature_invalid", audit)

    def test_tampered_response_denies(self):
        self.guardian.mutate = lambda reply: reply["result"].update(reasoning="tampered")
        out, audit = self.invoke()
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("response_signature_invalid", audit)

    def test_signed_response_bound_to_wrong_request_denies(self):
        for field in ("id", "request_id"):
            def mutate(reply):
                (reply if field == "id" else reply["result"])[field] = "other-request"
                sid = self.guardian.received[-1]["params"]["metadata"]["session_id"]
                sign_envelope(reply, key=derive_session_key(self.guardian.hmac_secret.encode(), sid), session_id=sid)
            with self.subTest(field=field):
                self.guardian.mutate = mutate
                out, audit = self.invoke()
                self.assertEqual(out["permissionDecision"], "deny")
                self.assertIn("response_binding_mismatch", audit)

    def test_malformed_and_oversized_response_denies(self):
        for raw in (b"no json", b"[]", b'{"jsonrpc":"2.0","result":[]}', b"x" * 1_000_001):
            with self.subTest(size=len(raw)):
                self.guardian.raw_reply = raw
                out, _ = self.invoke()
                self.assertEqual(out["permissionDecision"], "deny")

    def test_http_refusal_denies_even_in_fail_open_mode(self):
        self.guardian.raw_reply = b"refused"
        self.guardian.reply_status = 403
        out, audit = self.invoke()
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("guardian_http_403", audit)

    def test_handshake_failure_honors_startup_posture(self):
        self.env["ACS_GUARDIAN_URL"] = "http://127.0.0.1:1/acs"
        for posture in ("0", "1"):
            with self.subTest(posture=posture):
                self.env["ACS_DEFAULT_DENY"] = posture
                out, audit = self.invoke()
                self.assertEqual(out.get("permissionDecision"), "deny" if posture == "1" else None)
                self.assertIn("handshake_failed", audit)

    def test_local_deny_cannot_be_weakened_by_server(self):
        self.env["ACS_DEFAULT_DENY"] = "1"
        def slow(req):
            time.sleep(0.15)
            return self.guardian._default_allow(req)
        def hello(req):
            result = self.guardian._default_handshake(req)
            result.update(on_decision_failure="proceed", timeout_config={"default_ms": 50})
            return result
        self.guardian.handlers["handshake/hello"] = hello
        self.guardian.handlers["steps/toolCallRequest"] = slow
        out, audit = self.invoke()
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("decision_failure_fail_closed", audit)

    def test_unsupported_negotiation_denies_before_step(self):
        for change in ({"timeout_config": {"default_ms": 30000}},
                       {"timeout_config": {"default_ms": True}},
                       {"selected_transport": "stdio"},
                       {"methods_evaluated": None},
                       {"methods_evaluated": "steps/toolCallRequest"},
                       {"methods_evaluated": [None]},
                       {"on_decision_failure": "unknown"}, {"negotiated_version": "9.0.0"}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as cache:
                self.env["ACS_HANDSHAKE_CACHE"] = cache
                def hello(req):
                    result = self.guardian._default_handshake(req)
                    result.update(change)
                    return result
                self.guardian.handlers["handshake/hello"] = hello
                out, _ = self.invoke()
                self.assertEqual(out["permissionDecision"], "deny")
        self.assertNotIn("steps/toolCallRequest", self.guardian.methods())

    def test_unevaluated_method_leaves_codex_permission_flow_in_charge(self):
        for local_posture in ("0", "1"):
            for negotiated_posture in ("proceed", "deny"):
                with self.subTest(local_posture=local_posture,
                                  negotiated_posture=negotiated_posture), \
                        tempfile.TemporaryDirectory() as cache:
                    self.env["ACS_HANDSHAKE_CACHE"] = cache
                    self.env["ACS_DEFAULT_DENY"] = local_posture

                    def hello(req):
                        result = self.guardian._default_handshake(req)
                        result.update(methods_evaluated=[],
                                      on_decision_failure=negotiated_posture)
                        return result

                    self.guardian.handlers["handshake/hello"] = hello
                    before = len(self.guardian.received)
                    out, audit = self.invoke()
                    self.assertEqual(out, {})
                    self.assertIn("method_not_evaluated", audit)
                    self.assertNotIn("fail_open_bypass", audit)
                    self.assertNotIn("decision_failure_fail_closed", audit)
                    self.assertEqual(self.guardian.methods()[before:], ["handshake/hello"])

                    before = len(self.guardian.received)
                    cached_out, cached_audit = self.invoke(event(tool_use_id="call_cached"))
                    self.assertEqual(cached_out, {})
                    self.assertIn("method_not_evaluated", cached_audit)
                    self.assertEqual(self.guardian.methods()[before:], [])
        self.guardian.assert_all_valid(self)

    def test_unevaluated_method_does_not_bypass_handshake_verification(self):
        self.env["ACS_DEFAULT_DENY"] = "1"
        self.guardian.sign_responses = False

        def hello(req):
            result = self.guardian._default_handshake(req)
            result["methods_evaluated"] = []
            return result

        self.guardian.handlers["handshake/hello"] = hello
        out, audit = self.invoke()
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("handshake_failed", audit)
        self.assertNotIn("method_not_evaluated", audit)
        self.assertEqual(self.guardian.methods(), ["handshake/hello"])

    def test_negotiated_timeout_and_posture(self):
        for posture in ("proceed", "deny"):
            with self.subTest(posture=posture), tempfile.TemporaryDirectory() as cache:
                self.env["ACS_HANDSHAKE_CACHE"] = cache
                def hello(req):
                    result = self.guardian._default_handshake(req)
                    result.update(on_decision_failure=posture, timeout_config={"default_ms": 50})
                    return result
                def slow(req):
                    time.sleep(0.15)
                    return self.guardian._default_allow(req)
                self.guardian.handlers["handshake/hello"] = hello
                self.guardian.handlers["steps/toolCallRequest"] = slow
                out, audit = self.invoke()
                self.assertEqual(out.get("permissionDecision"), "deny" if posture == "deny" else None)
                self.assertIn("guardian_unreachable_or_timeout", audit)

    def test_signed_guardian_error_posture_and_refusal(self):
        for code in (-32603, -32004):
            for posture in ("0", "1"):
                with self.subTest(code=code, posture=posture):
                    self.env["ACS_DEFAULT_DENY"] = posture
                    def mutate(reply):
                        reply.pop("result")
                        reply["error"] = {"code": code, "message": "fixture"}
                        sid = self.guardian.received[-1]["params"]["metadata"]["session_id"]
                        sign_envelope(reply, key=derive_session_key(self.guardian.hmac_secret.encode(), sid), session_id=sid)
                    self.guardian.mutate = mutate
                    out, _ = self.invoke()
                    self.assertEqual(out.get("permissionDecision"), "deny" if code == -32004 or posture == "1" else None)

    def test_handshake_cached_and_request_ids_session_scoped(self):
        self.invoke()
        self.invoke(event(tool_use_id="call_4"))
        self.assertEqual(self.guardian.methods().count("handshake/hello"), 1)
        self.invoke(event(session_id="thr_other"))
        self.assertEqual(self.guardian.methods().count("handshake/hello"), 2)
        self.assertEqual(self.guardian.duplicate_request_ids(), [])
        self.guardian.assert_all_valid(self)

    def test_example_guardian_allows_denies_and_rejects_replay(self):
        self.env["ACS_GUARDIAN_STATE_DIR"] = str(Path(self.tmp.name) / "guardian-state")
        proc, port = launch_guardian(env=self.env)
        try:
            self.env["ACS_GUARDIAN_URL"] = f"http://127.0.0.1:{port}/acs"
            out, _ = self.invoke()
            self.assertEqual(out["permissionDecision"], "allow")
            out, _ = self.invoke()
            self.assertEqual(out["permissionDecision"], "deny", "same call ID is a replay")
            # Adapter input only: the test never executes this command.
            out, _ = self.invoke(event(tool_use_id="different-call",
                                       tool_input={"command": "rm -rf /acs-test-do-not-execute"}))
            self.assertEqual(out["permissionDecision"], "deny")
        finally:
            proc.terminate()
            proc.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
