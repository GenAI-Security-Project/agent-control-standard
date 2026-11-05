"""Run the Codex adapter as a subprocess and check its output and the bytes it sends."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from acs import client, core
from acs.testing.capture_guardian import CaptureGuardian
from acs.testing.harness import TEST_KEY_ID, launch_guardian, signing_env

ADAPTER = Path(__file__).resolve().parents[3] / "src" / "acs" / "integrations" / "codex" / "adapter.py"
HOOK = Path(sys.executable).parent / "acs-codex-hook"


def event(**changes) -> dict:
    result = {"hook_event_name": "PreToolUse", "session_id": "thr_test_session",
              "turn_id": "turn_7", "tool_use_id": "call_3", "cwd": "/tmp/acs-test",
              "tool_name": "Bash", "tool_input": {"command": "printf harmless", "timeout_ms": 1000}}
    result.update(changes)
    return result


class WireGuardian(CaptureGuardian):
    """Changes a step's response after it is signed, or replaces it with raw bytes."""
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
                        self.send_response(guardian.reply_status)
                        self.send_header("Content-Length", str(len(guardian.raw_reply)))
                        self.end_headers()
                        try:
                            self.wfile.write(guardian.raw_reply)
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                        return
                super()._reply(reply)
        return Handler

    def resign(self, reply: dict) -> None:
        session_id = self.received[-1]["params"]["metadata"]["session_id"]
        key = core.derive_session_key(self.hmac_secret.encode(), session_id)
        reply.pop("signature", None)
        (reply.get("result") or reply.get("error")).pop("signature", None)
        client.sign_envelope(reply, key=key, session_id=session_id, key_id=self.key_id)


class AdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.guardian = WireGuardian()
        self.guardian.start()
        self.addCleanup(self.guardian.stop)
        # A developer's own ACS settings must not reach the adapter.
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        self.env.update(signing_env(), ACS_GUARDIAN_URL=self.guardian.url(), ACS_DEFAULT_DENY="0",
                        ACS_HANDSHAKE_CACHE=str(Path(self.tmp.name) / "handshake"),
                        ACS_SESSION_STATE_DIR=str(Path(self.tmp.name) / "state"))

    def fresh_session_records(self) -> None:
        self.env["ACS_HANDSHAKE_CACHE"] = tempfile.mkdtemp(dir=self.tmp.name)

    def invoke(self, input_event: dict | None = None, raw: str | None = None,
               command: list[str] | None = None) -> tuple[dict, str]:
        proc = subprocess.run(command or [sys.executable, str(ADAPTER)],
                              input=raw if raw is not None else json.dumps(input_event or event()),
                              env=self.env, capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        output = json.loads(proc.stdout or "{}")
        return output.get("hookSpecificOutput", {}), proc.stderr

    def verdict(self, decision, **extra) -> None:
        # response-envelope.json requires reasoning on every decision but allow.
        self.guardian.handlers["steps/toolCallRequest"] = lambda req: {
            **self.guardian._default_allow(req), "decision": decision, "reasoning": "fixture", **extra}

    def hello(self, **changes) -> None:
        def answer(req):
            result = self.guardian._default_handshake(req)
            result.update(changes)
            return result
        self.guardian.handlers["handshake/hello"] = answer

    def test_allow_prints_nothing_and_the_envelopes_declare_one_method(self) -> None:
        out, audit = self.invoke()
        # Nothing printed, so Codex's own approval policy and sandbox still decide.
        self.assertEqual(out, {})
        self.assertNotIn("ACS_AUDIT", audit)
        self.assertEqual(self.guardian.methods(), ["handshake/hello", "steps/toolCallRequest"])
        self.guardian.assert_all_valid(self)
        hello = self.guardian.payload_of("handshake/hello")
        self.assertEqual(hello["methods_implemented"], ["steps/toolCallRequest"])
        self.assertEqual(hello["profiles_supported"], [])
        self.assertEqual(hello["transports_supported"], ["http"])
        self.assertEqual(hello["wrapped_protocols"], [])
        request = self.guardian.only("steps/toolCallRequest").parsed
        metadata = request["params"]["metadata"]
        self.assertEqual(metadata["turn_id"], "turn_7")
        self.assertEqual(metadata["codex_session_id"], "thr_test_session")
        self.assertEqual(metadata["platform"], "codex")
        self.assertEqual(request["params"]["signature"]["key_id"], TEST_KEY_ID)
        self.assertEqual(request["params"]["payload"]["arguments"]["command"], {"value": "printf harmless"})

    def test_deny_carries_the_reasoning(self) -> None:
        self.verdict("deny", reasoning="policy")
        out, _ = self.invoke()
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertEqual(out["permissionDecisionReason"], "policy")

    def test_modify_merges_overrides_and_keeps_other_arguments(self) -> None:
        self.verdict("modify", modifications={"parameter_overrides": {"command": "printf replacement"}})
        out, _ = self.invoke()
        self.assertEqual(out["permissionDecision"], "allow")
        self.assertEqual(out["updatedInput"], {"command": "printf replacement", "timeout_ms": 1000})

    def test_patch_and_mcp_arguments_are_wrapped(self) -> None:
        for tool, value in (("apply_patch", {"command": "*** Begin Patch\n*** End Patch"}),
                            ("mcp__local__read", {"path": "sample", "options": {"limit": 2}})):
            with self.subTest(tool=tool):
                self.guardian.captures.clear()
                out, _ = self.invoke(event(tool_name=tool, tool_input=value))
                self.assertEqual(out, {})
                self.guardian.assert_all_valid(self)
                self.assertEqual(self.guardian.payload_of("steps/toolCallRequest")["arguments"],
                                 {k: {"value": v} for k, v in value.items()})

    def test_mcp_modify_keeps_unmodified_arguments(self) -> None:
        self.verdict("modify", modifications={"parameter_overrides": {"path": "safe"}})
        out, _ = self.invoke(event(tool_name="mcp__local__read", tool_input={"path": "old", "limit": 2}))
        self.assertEqual(out["updatedInput"], {"path": "safe", "limit": 2})

    def test_ask_and_defer_deny_because_codex_cannot_hold_a_call(self) -> None:
        details = {"ask": {"ask_details": {"approver": {"type": "human", "id": "owner"}, "question": "Run it?",
                                           "timeout_seconds": 60}},
                   "defer": {"defer_details": {"reason": "pending_dependency", "resolution_method": "timeout",
                                               "resolution_timeout_ms": 1000, "timeout_decision": "deny"}}}
        for decision in ("ask", "defer"):
            with self.subTest(decision=decision):
                self.verdict(decision, reasoning="needs a person", **details[decision])
                out, audit = self.invoke()
                self.assertEqual(out["permissionDecision"], "deny")
                self.assertIn("needs a person", out["permissionDecisionReason"])
                self.assertIn("unenforceable_decision", audit)

    def test_unusable_decisions_deny(self) -> None:
        for decision in ("future", " DENY ", None, [], 1):
            with self.subTest(decision=decision):
                self.verdict(decision)
                out, _ = self.invoke()
                self.assertEqual(out["permissionDecision"], "deny")

    def test_a_modify_codex_cannot_apply_in_full_denies(self) -> None:
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

    def test_malformed_input_denies_and_sends_nothing(self) -> None:
        for raw in ("", "[]", "null", "{", '{"tool_name":"Bash"}',
                    '{"hook_event_name":"PreToolUse","tool_input":NaN}',
                    '{"hook_event_name":"PreToolUse","hook_event_name":"Stop"}'):
            with self.subTest(raw=raw):
                out, audit = self.invoke(raw=raw)
                self.assertEqual(out["permissionDecision"], "deny")
                self.assertIn("codex_call_refused", audit)
        self.assertEqual(self.guardian.methods(), [])

    def test_missing_identity_or_unusable_input_denies_and_sends_nothing(self) -> None:
        for key, value in (("session_id", None), ("turn_id", ""), ("tool_use_id", None), ("tool_name", None),
                           ("tool_input", None), ("tool_input", {"command": ["printf", "x"]})):
            with self.subTest(key=key, value=value):
                out, _ = self.invoke(event(**{key: value}))
                self.assertEqual(out["permissionDecision"], "deny")
        self.assertEqual(self.guardian.methods(), [])

    def test_another_hook_is_audited_and_sends_nothing(self) -> None:
        out, audit = self.invoke(event(hook_event_name="Stop"))
        self.assertEqual(out, {})
        self.assertIn("unmapped_hook_event", audit)
        self.assertEqual(self.guardian.methods(), [])

    def test_signing_material_is_required_under_either_posture(self) -> None:
        for missing in ("ACS_HMAC_SECRET", "ACS_HMAC_KEY_ID"):
            with self.subTest(missing=missing):
                env = dict(self.env)
                self.env.pop(missing)
                out, audit = self.invoke()
                self.env = env
                self.assertEqual(out["permissionDecision"], "deny")
                self.assertIn("session_refused_fail_closed", audit)
        self.assertEqual(self.guardian.methods(), [])

    def test_secret_file_is_read(self) -> None:
        secret = Path(self.tmp.name) / "secret"
        secret.write_text(self.guardian.hmac_secret)
        secret.chmod(0o600)
        self.env.pop("ACS_HMAC_SECRET")
        self.env["ACS_HMAC_SECRET_FILE"] = str(secret)
        out, _ = self.invoke()
        self.assertEqual(out, {})
        self.guardian.assert_all_valid(self)

    def test_unsigned_or_tampered_response_denies_under_fail_open(self) -> None:
        for mutate in (lambda reply: reply["result"].pop("signature"),
                       lambda reply: reply["result"].update(reasoning="tampered")):
            with self.subTest(mutate=mutate):
                self.guardian.mutate = mutate
                out, audit = self.invoke()
                self.assertEqual(out["permissionDecision"], "deny")
                self.assertIn("response_signature_invalid", audit)

    def test_a_signed_response_bound_to_another_request_denies(self) -> None:
        for field in ("id", "request_id"):
            def mutate(reply, field=field):
                (reply if field == "id" else reply["result"])[field] = "other-request"
                self.guardian.resign(reply)
            with self.subTest(field=field):
                self.guardian.mutate = mutate
                out, audit = self.invoke()
                self.assertEqual(out["permissionDecision"], "deny")
                self.assertIn("response_binding_mismatch", audit)

    def test_an_unreadable_response_follows_the_posture(self) -> None:
        for raw in (b"no json", b"[]", b'{"jsonrpc":"2.0","result":[]}'):
            for posture in ("0", "1"):
                with self.subTest(raw=raw, posture=posture):
                    self.env["ACS_DEFAULT_DENY"] = posture
                    self.guardian.raw_reply = raw
                    out, audit = self.invoke()
                    self.assertEqual(out.get("permissionDecision"), "deny" if posture == "1" else None)
                    self.assertIn("malformed_response", audit)

    def test_an_http_refusal_denies_under_fail_open(self) -> None:
        self.guardian.raw_reply = b"refused"
        self.guardian.reply_status = 400
        out, audit = self.invoke()
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("http_400_refusal", audit)

    def test_an_unanswered_handshake_follows_the_startup_posture(self) -> None:
        """§4.1: a session with no negotiated Guardian denies its calls unless the hook sets ACS_STARTUP_POSTURE=proceed."""
        base = {k: v for k, v in self.env.items() if k not in ("ACS_DEFAULT_DENY", "ACS_STARTUP_POSTURE")}
        base["ACS_GUARDIAN_URL"] = "http://127.0.0.1:1/acs"
        table = [({}, "deny", "session_not_started_fail_closed"),
                 ({"ACS_DEFAULT_DENY": "0"}, "deny", "session_not_started_fail_closed"),
                 ({"ACS_DEFAULT_DENY": "1"}, "deny", "session_not_started_fail_closed"),
                 ({"ACS_STARTUP_POSTURE": "proceed"}, None, "unguarded_session_bypass")]
        for overrides, decision, audit_event in table:
            with self.subTest(env=overrides):
                self.env = {**base, **overrides}
                self.fresh_session_records()
                out, audit = self.invoke()
                self.assertEqual(out.get("permissionDecision"), decision)
                self.assertIn(audit_event, audit)

    def test_a_server_hello_that_does_not_answer_the_client_hello_sends_no_step(self) -> None:
        self.env["ACS_DEFAULT_DENY"] = "1"
        for change in ({"timeout_config": {"default_ms": True}}, {"selected_transport": "stdio"},
                       {"methods_evaluated": "steps/toolCallRequest"}, {"methods_evaluated": [None]},
                       {"on_decision_failure": "unknown"}, {"negotiated_version": "9.0.0"}):
            with self.subTest(change=change):
                self.fresh_session_records()
                self.hello(**change)
                out, audit = self.invoke()
                self.assertEqual(out["permissionDecision"], "deny")
                self.assertIn("invalid_server_hello", audit)
        self.assertNotIn("steps/toolCallRequest", self.guardian.methods())

    def test_a_decision_timeout_past_the_hook_budget_denies_before_the_step(self) -> None:
        self.hello(timeout_config={"default_ms": 30000})
        out, audit = self.invoke()
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("unsupported_decision_timeout", audit)
        self.assertNotIn("steps/toolCallRequest", self.guardian.methods())

    def test_the_local_deny_posture_holds_against_a_server_proceed(self) -> None:
        self.env["ACS_DEFAULT_DENY"] = "1"
        self.hello(on_decision_failure="proceed", timeout_config={"default_ms": 50})

        def slow(req):
            time.sleep(0.15)
            return self.guardian._default_allow(req)
        self.guardian.handlers["steps/toolCallRequest"] = slow
        out, audit = self.invoke()
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("decision_failure_fail_closed", audit)

    def test_the_negotiated_timeout_and_posture_apply(self) -> None:
        for posture in ("proceed", "deny"):
            with self.subTest(posture=posture):
                self.fresh_session_records()
                self.hello(on_decision_failure=posture, timeout_config={"default_ms": 50})

                def slow(req):
                    time.sleep(0.15)
                    return self.guardian._default_allow(req)
                self.guardian.handlers["steps/toolCallRequest"] = slow
                out, audit = self.invoke()
                self.assertEqual(out.get("permissionDecision"), "deny" if posture == "deny" else None)
                self.assertIn("decision_timeout", audit)

    def test_an_unevaluated_method_leaves_codex_in_charge(self) -> None:
        for local in ("0", "1"):
            for negotiated in ("proceed", "deny"):
                with self.subTest(local=local, negotiated=negotiated):
                    self.fresh_session_records()
                    self.env["ACS_DEFAULT_DENY"] = local
                    self.hello(methods_evaluated=[], on_decision_failure=negotiated)
                    before = len(self.guardian.received)
                    out, audit = self.invoke()
                    self.assertEqual(out, {})
                    self.assertIn("method_not_evaluated", audit)
                    self.assertNotIn("fail_open_bypass", audit)
                    self.assertNotIn("decision_failure_fail_closed", audit)
                    self.assertEqual(self.guardian.methods_seen()[before:], ["handshake/hello"])
                    # The stored session decision answers the next call with no traffic.
                    before = len(self.guardian.received)
                    out, audit = self.invoke(event(tool_use_id="call_cached"))
                    self.assertEqual(out, {})
                    self.assertIn("method_not_evaluated", audit)
                    self.assertEqual(self.guardian.methods_seen()[before:], [])
        self.guardian.assert_all_valid(self)

    def test_an_unevaluated_method_does_not_skip_the_server_hello_check(self) -> None:
        self.guardian.sign_responses = False
        self.hello(methods_evaluated=[])
        out, audit = self.invoke()
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("server_hello_signature_invalid", audit)
        self.assertNotIn("method_not_evaluated", audit)
        self.assertEqual(self.guardian.methods(), ["handshake/hello"])

    def test_a_signed_guardian_error_follows_the_posture_unless_it_is_a_refusal(self) -> None:
        for code in (-32603, -32005):
            for posture in ("0", "1"):
                with self.subTest(code=code, posture=posture):
                    self.env["ACS_DEFAULT_DENY"] = posture

                    def mutate(reply, code=code):
                        reply.pop("result")
                        reply["error"] = {"code": code, "message": "fixture"}
                        self.guardian.resign(reply)
                    self.guardian.mutate = mutate
                    out, _ = self.invoke()
                    refused = code == -32005
                    self.assertEqual(out.get("permissionDecision"), "deny" if refused or posture == "1" else None)

    def test_a_session_handshakes_once_and_request_ids_are_session_scoped(self) -> None:
        self.invoke()
        self.invoke(event(tool_use_id="call_4"))
        self.assertEqual(self.guardian.methods().count("handshake/hello"), 1)
        self.invoke(event(session_id="thr_other"))
        self.assertEqual(self.guardian.methods().count("handshake/hello"), 2)
        self.assertEqual(self.guardian.duplicate_request_ids(), [])
        self.guardian.assert_all_valid(self)

    def test_disabled_sends_nothing_and_is_audited(self) -> None:
        self.env["ACS_DISABLED"] = "1"
        out, audit = self.invoke()
        self.assertEqual(out, {})
        self.assertIn("acs_disabled_bypass", audit)
        self.assertEqual(self.guardian.methods(), [])

    def test_the_hook_command_follows_the_posture_when_the_adapter_cannot_load(self) -> None:
        """No Guardian can decide a call the adapter cannot send, so it proceeds only when the hook opts into both postures."""
        shadow = Path(self.tmp.name) / "shadow"
        shadow.mkdir()
        (shadow / "rfc8785.py").write_text("raise ImportError('test missing dependency')\n")
        base = {k: v for k, v in self.env.items() if k not in ("ACS_DEFAULT_DENY", "ACS_STARTUP_POSTURE")}
        base["PYTHONPATH"] = str(shadow)
        table = [({}, "deny"), ({"ACS_DEFAULT_DENY": "0"}, "deny"), ({"ACS_DEFAULT_DENY": "1"}, "deny"),
                 ({"ACS_STARTUP_POSTURE": "proceed"}, "deny"),
                 ({"ACS_STARTUP_POSTURE": "proceed", "ACS_DEFAULT_DENY": "0"}, None)]
        for overrides, decision in table:
            with self.subTest(env=overrides):
                self.env = {**base, **overrides}
                out, audit = self.invoke(command=[str(HOOK)])
                self.assertEqual(out.get("permissionDecision"), decision)
                self.assertIn("adapter_unavailable", audit)
        self.assertEqual(self.guardian.methods(), [])

    def test_the_hook_command_runs_the_adapter(self) -> None:
        out, _ = self.invoke(command=[str(HOOK)])
        self.assertEqual(out, {})
        self.assertEqual(self.guardian.methods(), ["handshake/hello", "steps/toolCallRequest"])

    def test_the_example_guardian_allows_denies_and_rejects_a_replay(self) -> None:
        self.env["ACS_GUARDIAN_STATE_DIR"] = str(Path(self.tmp.name) / "guardian-state")
        proc, port = launch_guardian(env=self.env)
        try:
            self.env["ACS_GUARDIAN_URL"] = f"http://127.0.0.1:{port}/acs"
            out, _ = self.invoke()
            self.assertEqual(out, {})
            out, _ = self.invoke()
            self.assertEqual(out["permissionDecision"], "deny", "the same call id is a replay")
            # Adapter input only: the test never runs this command.
            out, _ = self.invoke(event(tool_use_id="different-call",
                                       tool_input={"command": "rm -rf /acs-test-do-not-execute"}))
            self.assertEqual(out["permissionDecision"], "deny")
        finally:
            proc.terminate()
            proc.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
