"""§4.1 through the installed hooks: the first handshake decides the session for every later hook process."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

from acs.testing.harness import ProgrammableGuardian

BIN = Path(sys.executable).parent
SECRET = "session-gate-hook-secret"


def _audit_records(text: str) -> list[dict]:
    return [json.loads(line[len("ACS_AUDIT "):]) for line in text.splitlines()
            if line.startswith("ACS_AUDIT ")]


class SessionGateThroughHooks(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="acs-session-gate-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def _env(self, url: str, **extra: str) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        env.update(ACS_GUARDIAN_URL=url, ACS_HMAC_SECRET=SECRET,
                   ACS_HANDSHAKE_CACHE=str(self.root / "handshake"),
                   ACS_SESSION_STATE_DIR=str(self.root / "state"),
                   ACS_HANDSHAKE_TIMEOUT_SECONDS="2")
        env.update(extra)
        return env

    def _claude(self, url: str, session: str, **extra: str):
        event = {"session_id": session, "cwd": "/tmp", "hook_event_name": "PreToolUse",
                 "tool_name": "Bash", "tool_input": {"command": "echo hi"}}
        p = subprocess.run([str(BIN / "acs-claude-code-hook")], input=json.dumps(event),
                           capture_output=True, text=True, env=self._env(url, **extra), timeout=30)
        denied = bool(p.stdout.strip()) and \
            json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
        return p, denied, [r["acs_audit_event"] for r in _audit_records(p.stderr)]

    def _cursor(self, url: str, session: str, event_name: str = "preToolUse", **extra: str):
        event = {"conversation_id": session, "workspace_roots": ["/tmp"],
                 "tool_name": "Bash", "tool_input": {"command": "echo hi"}, "prompt": "hello"}
        p = subprocess.run([str(BIN / "acs-cursor-hook"), event_name], input=json.dumps(event),
                           capture_output=True, text=True, env=self._env(url, **extra), timeout=30)
        denied = bool(p.stdout.strip()) and json.loads(p.stdout).get("permission") == "deny"
        return p, denied, [r["acs_audit_event"] for r in _audit_records(p.stderr)]

    def _down(self) -> tuple[int, str]:
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        guardian._server.server_close()
        return guardian.port, guardian.url()

    def _restore(self, port: int) -> ProgrammableGuardian:
        guardian = ProgrammableGuardian(hmac_secret=SECRET, port=port)
        guardian.start()
        self.addCleanup(guardian.stop)
        return guardian

    def _age_records(self) -> None:
        for record in (self.root / "handshake").glob("*.json"):
            os.utime(record, (0, 0))

    def test_an_unguarded_session_never_contacts_a_restored_guardian(self) -> None:
        port, url = self._down()
        hooks = {"claude-code": self._claude, "cursor": self._cursor}
        sessions = {name: str(uuid.uuid4()) for name in hooks}
        for name, run in hooks.items():
            with self.subTest(name, phase="Guardian down"):
                p, denied, audits = run(url, sessions[name])
                self.assertFalse(denied, p.stdout)
                self.assertIn("session_without_negotiated_guardian", audits)
                self.assertIn("unguarded_session_bypass", audits)
                if name == "cursor":
                    self.assertEqual(json.loads(p.stdout), {"permission": "allow"},
                        "failClosed: true reads an empty reply as a failed hook, so proceed needs the allow shape")

        guardian = self._restore(port)
        self._age_records()
        # Settings an older adapter read as cache lifetimes; nothing reads them now.
        expired = {"ACS_HANDSHAKE_CACHE_TTL_SECONDS": "0", "ACS_HANDSHAKE_FAILURE_CACHE_TTL_SECONDS": "0"}
        for name, run in hooks.items():
            with self.subTest(name, phase="Guardian restored, same session"):
                p, denied, audits = run(url, sessions[name], **expired)
                self.assertEqual(guardian.methods_seen(), [],
                    "a session that started unguarded sends the Guardian nothing for its lifetime")
                self.assertFalse(denied, p.stdout)
                self.assertEqual(audits, ["unguarded_session_bypass"])

        for name, run in hooks.items():
            with self.subTest(name, phase="Guardian restored, new session"):
                guardian.reset()
                p, denied, audits = run(url, str(uuid.uuid4()), **expired)
                self.assertEqual(guardian.methods_seen(), ["handshake/hello", "steps/toolCallRequest"])
                self.assertFalse(denied, p.stdout)

    def test_a_refused_session_sends_no_step_in_any_hook_process(self) -> None:
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        guardian.handlers["handshake/hello"] = lambda req: {"code": -32000, "message": "agent not permitted"}
        guardian.start()
        self.addCleanup(guardian.stop)
        for name, run in (("claude-code", self._claude), ("cursor", self._cursor)):
            session = str(uuid.uuid4())
            for attempt in (1, 2):
                with self.subTest(name, process=attempt):
                    guardian.reset()
                    # Fail-open step posture and proceed startup posture: the refusal still holds (§4.1).
                    p, denied, audits = run(guardian.url(), session, ACS_STARTUP_POSTURE="proceed")
                    self.assertTrue(denied, p.stdout)
                    self.assertIn("session refused", p.stdout)
                    self.assertIn("session_refused_fail_closed", audits)
                    self.assertEqual(guardian.methods_seen(), ["handshake/hello"] if attempt == 1 else [])

    def test_a_refused_start_holds_after_the_guardian_returns(self) -> None:
        port, url = self._down()
        session = str(uuid.uuid4())
        p, denied, audits = self._claude(url, session, ACS_STARTUP_POSTURE="refuse")
        self.assertTrue(denied, p.stdout)
        self.assertIn("session_without_negotiated_guardian", audits)
        guardian = self._restore(port)
        self._age_records()
        p, denied, audits = self._claude(url, session, ACS_STARTUP_POSTURE="refuse")
        self.assertTrue(denied, p.stdout)
        self.assertEqual(audits, ["session_not_started_fail_closed"])
        self.assertEqual(guardian.methods_seen(), [])
        p, denied, _ = self._claude(url, str(uuid.uuid4()), ACS_STARTUP_POSTURE="refuse")
        self.assertFalse(denied, p.stdout)
        self.assertEqual(guardian.methods_seen(), ["handshake/hello", "steps/toolCallRequest"])

    def test_a_deeply_nested_record_refuses_through_the_installed_hooks(self) -> None:
        """A record nested past Python's recursion limit must refuse natively, not crash the hook (exit 1 proceeds)."""
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        guardian.handlers["handshake/hello"] = lambda req: {"code": -32000, "message": "agent not permitted"}
        guardian.start()
        self.addCleanup(guardian.stop)
        fail_open = {"ACS_STARTUP_POSTURE": "proceed"}
        for name, run in (("claude-code", self._claude), ("cursor", self._cursor)):
            with self.subTest(name):
                session = str(uuid.uuid4())
                run(guardian.url(), session, **fail_open)
                records = list((self.root / "handshake").glob("*.json"))
                for record in records:
                    record.write_bytes(b"[" * 20000 + b"]" * 20000)
                guardian.reset()
                p, denied, audits = run(guardian.url(), session, **fail_open)
                self.assertEqual(p.returncode, 0, p.stderr[-400:])
                self.assertTrue(denied, f"native denial required; stdout={p.stdout!r}")
                self.assertIn("session_refused_fail_closed", audits)
                self.assertIn('"cause": "session_record_invalid"', p.stderr)
                self.assertEqual(guardian.methods_seen(), [], "a damaged record must not trigger another handshake")

    def test_a_deeply_nested_event_is_denied_in_the_hooks_own_shape(self) -> None:
        """The hook name comes from the top-level object only; tool_input is the agent's and may carry a decoy."""
        deep = "[" * 20000 + "]" * 20000
        decoy = '"hook_event_name": "Stop"'
        orders = {
            "hook name first": '{"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Bash", '
                               '"tool_input": {"x": ' + deep + ", " + decoy + "}}",
            "decoy first": '{"session_id": "s", "tool_name": "Bash", "tool_input": {' + decoy + ', "x": '
                           + deep + '}, "hook_event_name": "PreToolUse"}',
        }
        for name, raw in orders.items():
            with self.subTest(name):
                p = subprocess.run([str(BIN / "acs-claude-code-hook")], input=raw, capture_output=True, text=True,
                                   env=self._env("http://127.0.0.1:1/acs", ACS_DEFAULT_DENY="1"), timeout=30)
                self.assertEqual(p.returncode, 0, p.stderr[-400:])
                self.assertEqual(json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
                audits = _audit_records(p.stderr)
                self.assertEqual([(r["acs_audit_event"], r["hook"]) for r in audits],
                                 [("decision_failure_fail_closed", "PreToolUse")])

    def test_an_adapter_error_keeps_the_negotiated_deny(self) -> None:
        """A step that raises inside the adapter settles with the session's posture, not the local default."""
        from acs.client import Negotiated
        from acs.client._handshake import store_session_decision
        url = "http://127.0.0.1:1/acs"
        hello = {"negotiated_version": "0.1.0", "on_decision_failure": "deny",
                 "timeout_config": {"default_ms": 2000}}
        # Claude Code signs transcript_path into its turnStart; Cursor, with turnStart not
        # evaluated, first touches the workspace root when it opens the turn.
        cases = {
            "claude-code": (self._claude_prompt, hello,
                            lambda p: json.loads(p.stdout).get("decision") == "block"),
            "cursor": (self._cursor_prompt, {**hello, "methods_evaluated": ["steps/userMessage"]},
                       lambda p: p.returncode == 2 and json.loads(p.stdout)["continue"] is False),
        }
        for name, (run, server_hello, blocked) in cases.items():
            for case, text in (("lone surrogate fails inside the step", "\\ud800"), ("control", "/tmp")):
                with self.subTest(name, case=case):
                    session = str(uuid.uuid4())
                    store_session_decision(self.root / "handshake", self._hook_session(name, session), url,
                                           Negotiated(server_hello), SECRET.encode())
                    p = run(url, session, text, ACS_DEFAULT_DENY="0")
                    self.assertTrue(blocked(p), f"stdout={p.stdout!r} stderr={p.stderr[-300:]!r}")
                    audits = [(r["acs_audit_event"], r.get("cause")) for r in _audit_records(p.stderr)
                              if r["acs_audit_event"] != "method_not_evaluated"]
                    cause = "adapter_exception" if case.startswith("lone") else "transport_failure"
                    self.assertEqual(audits, [("decision_failure_fail_closed", cause)],
                        "the surrogate must fail signing inside the step, and the control must reach the transport")

    @staticmethod
    def _hook_session(name: str, session: str) -> str:
        from acs.core import coerce_uuid
        return session if name == "claude-code" else coerce_uuid(session, namespace_prefix="cursor")

    def _claude_prompt(self, url: str, session: str, text: str, **extra: str):
        raw = ('{"session_id": "%s", "cwd": "/tmp", "hook_event_name": "UserPromptSubmit", '
               '"transcript_path": "%s", "prompt": "hi"}' % (session, text))
        return subprocess.run([str(BIN / "acs-claude-code-hook")], input=raw, capture_output=True, text=True,
                              env=self._env(url, **extra), timeout=30)

    def _cursor_prompt(self, url: str, session: str, text: str, **extra: str):
        raw = ('{"conversation_id": "%s", "cwd": "/tmp", "prompt": "hi", '
               '"workspace_roots": ["%s"]}' % (session, text))
        return subprocess.run([str(BIN / "acs-cursor-hook"), "beforeSubmitPrompt"], input=raw,
                              capture_output=True, text=True, env=self._env(url, **extra), timeout=30)

    def test_cursor_startup_proceed_answers_in_each_events_allow_shape(self) -> None:
        port, url = self._down()
        session = str(uuid.uuid4())
        p, _, _ = self._cursor(url, session, "beforeSubmitPrompt")
        self.assertEqual((p.returncode, json.loads(p.stdout)), (0, {"continue": True}))
        for event_name in ("preToolUse", "beforeShellExecution", "subagentStart"):
            with self.subTest(event_name):
                p, _, audits = self._cursor(url, session, event_name)
                self.assertEqual(json.loads(p.stdout), {"permission": "allow"})
                self.assertEqual(audits, ["unguarded_session_bypass"])

    def test_integral_timeouts_written_as_decimals_still_negotiate(self) -> None:
        """5000.0 is a JSON Schema integer: the session negotiates, so the step reaches the Guardian and its deny applies."""
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        hello = guardian._default_handshake
        guardian.handlers["handshake/hello"] = lambda req: {
            **hello(req), "on_decision_failure": "deny",
            "timeout_config": {"default_ms": 5000.0, "per_method_ms": {"steps/toolCallResult": 300.0}}}
        guardian.handlers["steps/toolCallRequest"] = lambda req: {
            "type": "final", "acs_version": "0.1.0", "request_id": req["params"]["request_id"],
            "decision": "deny", "reasoning": "policy", "chain_hash": "0" * 64}
        guardian.start()
        self.addCleanup(guardian.stop)
        p, denied, audits = self._claude(guardian.url(), str(uuid.uuid4()), ACS_STARTUP_POSTURE="proceed")
        self.assertTrue(denied, p.stderr[-300:])
        self.assertEqual(guardian.methods_seen(), ["handshake/hello", "steps/toolCallRequest"])
        self.assertNotIn("session_without_negotiated_guardian", audits)

    def test_a_later_hooks_required_profile_refuses_a_stored_negotiation(self) -> None:
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        hello = guardian._default_handshake
        guardian.handlers["handshake/hello"] = lambda req: {**hello(req), "profiles_accepted": []}
        guardian.start()
        self.addCleanup(guardian.stop)
        for name, run in (("claude-code", self._claude), ("cursor", self._cursor)):
            with self.subTest(name):
                session = str(uuid.uuid4())
                p, denied, _ = run(guardian.url(), session)
                self.assertFalse(denied, p.stdout)
                guardian.reset()
                p, denied, audits = run(guardian.url(), session, ACS_REQUIRE_PROFILES="acs-core")
                self.assertTrue(denied, f"stdout={p.stdout!r}")
                self.assertIn('"cause": "required_profile_not_accepted"', p.stderr)
                self.assertEqual(guardian.methods_seen(), [], "the requirement applies without renegotiating")
                guardian.reset()
                p, denied, _ = run(guardian.url(), str(uuid.uuid4()), ACS_REQUIRE_PROFILES="acs-core")
                self.assertTrue(denied, "control: a fresh session with the requirement is refused too")

    def test_a_denied_turn_start_blocks_the_prompt_and_sends_no_message(self) -> None:
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        guardian.handlers["steps/turnStart"] = lambda req: {
            "type": "final", "acs_version": "0.1.0", "request_id": req["params"]["request_id"],
            "decision": "deny", "reasoning": "policy", "chain_hash": "0" * 64}
        guardian.start()
        self.addCleanup(guardian.stop)
        runs = {"claude-code": ([str(BIN / "acs-claude-code-hook")],
                                {"session_id": str(uuid.uuid4()), "cwd": "/tmp",
                                 "hook_event_name": "UserPromptSubmit", "prompt": "hello"}),
                "cursor": ([str(BIN / "acs-cursor-hook"), "beforeSubmitPrompt"],
                           {"conversation_id": str(uuid.uuid4()), "workspace_roots": ["/tmp"], "prompt": "hello"})}
        for name, (argv, event) in runs.items():
            with self.subTest(name):
                guardian.reset()
                p = subprocess.run(argv, input=json.dumps(event), capture_output=True, text=True,
                                   env=self._env(guardian.url()), timeout=30)
                out = json.loads(p.stdout or "{}")
                blocked = (out.get("decision") == "block" if name == "claude-code"
                           else p.returncode == 2 and out.get("continue") is False)
                self.assertTrue(blocked, (p.returncode, p.stdout, p.stderr[-300:]))
                self.assertIn("turn_start_blocked", [r["acs_audit_event"] for r in _audit_records(p.stderr)])
                self.assertEqual(guardian.methods_seen(), ["handshake/hello", "steps/turnStart"],
                                 "a blocked prompt's userMessage is never sent")

    def test_mcp_use_records_the_degraded_claim_once_per_session(self) -> None:
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        guardian.start()
        self.addCleanup(guardian.stop)
        claude = {"cwd": "/tmp", "hook_event_name": "PreToolUse", "tool_name": "mcp__github__create_issue",
                  "tool_input": {"title": "x"}}
        cursor_mcp = {"workspace_roots": ["/tmp"], "tool_name": "create_issue", "tool_input": "{}", "url": "http://mcp"}
        cursor_tool = {"workspace_roots": ["/tmp"], "tool_name": "MCP:create_issue", "tool_input": {"title": "x"},
                       "tool_use_id": "call-1", "tool_output": "{}"}
        claude_hook, cursor_hook = str(BIN / "acs-claude-code-hook"), str(BIN / "acs-cursor-hook")
        runs = {
            "claude-code": ("session_id", 1, [([claude_hook], claude)] * 2),
            "cursor MCP hooks": ("conversation_id", 1, [([cursor_hook, "beforeMCPExecution"], cursor_mcp)] * 2),
            "cursor tool hooks": ("conversation_id", 1, [([cursor_hook, "preToolUse"], cursor_tool),
                                                         ([cursor_hook, "postToolUse"], cursor_tool)]),
            "cursor Shell": ("conversation_id", 0, [([cursor_hook, "preToolUse"], {**cursor_tool, "tool_name": "Shell"})]),
        }
        for name, (key, expected, calls) in runs.items():
            with self.subTest(name):
                session = str(uuid.uuid4())
                audits = []
                for argv, event in calls:
                    p = subprocess.run(argv, input=json.dumps({**event, key: session}), capture_output=True,
                                       text=True, env=self._env(guardian.url()), timeout=30)
                    audits += [r["acs_audit_event"] for r in _audit_records(p.stderr)]
                self.assertEqual(audits.count("profile_claim_degraded"), expected, audits)

    def test_negotiated_per_method_timeouts_bound_their_own_methods(self) -> None:
        """A 300 ms toolCallRequest timeout ends that wait; toolCallResult waits under the 5 s default and its deny applies."""
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        hello = guardian._default_handshake
        guardian.handlers["handshake/hello"] = lambda req: {
            **hello(req), "timeout_config": {"default_ms": 5000, "per_method_ms": {"steps/toolCallRequest": 300}}}

        def slow_deny(req: dict) -> dict:
            time.sleep(1.0)
            return {"type": "final", "acs_version": "0.1.0", "request_id": req["params"]["request_id"],
                    "decision": "deny", "reasoning": "slow deny", "chain_hash": "0" * 64}

        guardian.handlers["steps/toolCallRequest"] = slow_deny
        guardian.handlers["steps/toolCallResult"] = slow_deny
        guardian.start()
        self.addCleanup(guardian.stop)
        session = str(uuid.uuid4())
        p, denied, audits = self._claude(guardian.url(), session)
        # Under the 5 s default the deny would arrive after 1 s and apply.
        self.assertFalse(denied, p.stdout)
        self.assertIn('"cause": "decision_timeout"', p.stderr)
        event = {"session_id": session, "cwd": "/tmp", "hook_event_name": "PostToolUse", "tool_name": "Bash",
                 "tool_input": {"command": "echo hi"}, "tool_response": {"stdout": "hi"}}
        p = subprocess.run([str(BIN / "acs-claude-code-hook")], input=json.dumps(event), capture_output=True,
                           text=True, env=self._env(guardian.url()), timeout=30)
        self.assertEqual(json.loads(p.stdout).get("decision"), "block", p.stderr[-300:])

    def test_a_step_timeout_in_a_negotiated_session_leaves_later_steps_governed(self) -> None:
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        hello = guardian._default_handshake
        guardian.handlers["handshake/hello"] = lambda req: {**hello(req), "timeout_config": {"default_ms": 300}}
        steps = {"count": 0}
        release = threading.Event()

        def step(req: dict) -> dict:
            steps["count"] += 1
            if steps["count"] == 1:
                release.wait(timeout=5)
            return {"type": "final", "acs_version": "0.1.0", "request_id": req["params"]["request_id"],
                    "decision": "deny", "reasoning": "second step denied", "chain_hash": "0" * 64}

        guardian.handlers["__default__"] = step
        guardian.start()
        self.addCleanup(guardian.stop)
        self.addCleanup(release.set)
        session = str(uuid.uuid4())
        p, denied, audits = self._claude(guardian.url(), session)
        self.assertFalse(denied, p.stdout)
        self.assertIn("fail_open_bypass", audits)
        release.set()
        time.sleep(0.2)
        p, denied, audits = self._claude(guardian.url(), session)
        self.assertTrue(denied, "the second step reached the Guardian and its deny applied")
        self.assertEqual(guardian.methods_seen(),
                         ["handshake/hello", "steps/toolCallRequest", "steps/toolCallRequest"])


if __name__ == "__main__":
    unittest.main()
