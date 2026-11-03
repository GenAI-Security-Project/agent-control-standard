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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from acs.testing.harness import ProgrammableGuardian, validate_hook_payload

BIN = Path(sys.executable).parent
SECRET = "session-gate-hook-secret-padded-to-32-bytes"


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
        env.update(ACS_GUARDIAN_URL=url, ACS_HMAC_SECRET=SECRET, ACS_HMAC_KEY_ID="test-key",
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
                self.assertEqual(guardian.methods_seen(), ["handshake/hello", "steps/sessionStart", "steps/toolCallRequest"])
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
        self.assertEqual(guardian.methods_seen(), ["handshake/hello", "steps/sessionStart", "steps/toolCallRequest"])

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

    def test_a_step_failure_keeps_the_negotiated_deny(self) -> None:
        from acs.client import Negotiated
        from acs.client._handshake import store_session_decision
        url = "http://127.0.0.1:1/acs"
        hello = {"negotiated_version": "0.1.0", "on_decision_failure": "deny",
                 "timeout_config": {"default_ms": 2000}}
        # Neither Guardian evaluates sessionStart, so the prompt's own step fails. Claude Code signs
        # transcript_path into its turnStart; Cursor, with turnStart not evaluated, first touches the
        # workspace root when it opens the turn.
        cases = {
            "claude-code": (self._claude_prompt, {**hello, "methods_evaluated": ["steps/turnStart", "steps/userMessage"]},
                            lambda p: json.loads(p.stdout).get("decision") == "block"),
            "cursor": (self._cursor_prompt, {**hello, "methods_evaluated": ["steps/userMessage"]},
                       lambda p: p.returncode == 0 and json.loads(p.stdout)["continue"] is False),
        }
        for name, (run, server_hello, blocked) in cases.items():
            for case, text in (("lone surrogate", "\\ud800"), ("control", "/tmp")):
                with self.subTest(name, case=case):
                    session = str(uuid.uuid4())
                    store_session_decision(self.root / "handshake", self._hook_session(name, session), url,
                                           Negotiated(server_hello), SECRET.encode())
                    p = run(url, session, text, ACS_DEFAULT_DENY="0")
                    self.assertTrue(blocked(p), f"stdout={p.stdout!r} stderr={p.stderr[-300:]!r}")
                    audits = [(r["acs_audit_event"], r.get("cause")) for r in _audit_records(p.stderr)
                              if r["acs_audit_event"] != "method_not_evaluated"
                              and r.get("method") != "steps/sessionStart"]
                    expected = [("decision_failure_fail_closed", "transport_failure")]
                    if case.startswith("lone") and name == "claude-code":
                        # Claude Code signs transcript_path; Cursor keys only its session state on the workspace root.
                        expected.insert(0, ("envelope_normalized", None))
                    self.assertEqual(audits, expected, "the surrogate is replaced and the step reaches the transport")

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
        self.assertEqual(guardian.methods_seen(), ["handshake/hello", "steps/sessionStart", "steps/toolCallRequest"])
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
                           else p.returncode == 0 and out.get("continue") is False)
                self.assertTrue(blocked, (p.returncode, p.stdout, p.stderr[-300:]))
                self.assertIn("turn_start_blocked", [r["acs_audit_event"] for r in _audit_records(p.stderr)])
                self.assertEqual(guardian.methods_seen(), ["handshake/hello", "steps/sessionStart", "steps/turnStart"],
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
                         ["handshake/hello", "steps/sessionStart", "steps/toolCallRequest", "steps/toolCallRequest"])


    # One session's first-prompt hooks per host, the session hook last, the order Cursor ran them live.
    STARTUP = {
        "claude-code": [([str(BIN / "acs-claude-code-hook")], {"hook_event_name": "UserPromptSubmit", "prompt": "hello"}),
                        ([str(BIN / "acs-claude-code-hook")], {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                                               "tool_input": {"command": "echo hi"}}),
                        ([str(BIN / "acs-claude-code-hook")], {"hook_event_name": "SessionStart", "source": "startup"})],
        "cursor": [([str(BIN / "acs-cursor-hook"), "beforeSubmitPrompt"], {"prompt": "hello"}),
                   ([str(BIN / "acs-cursor-hook"), "preToolUse"], {"tool_name": "Bash", "tool_input": {"command": "echo hi"}}),
                   ([str(BIN / "acs-cursor-hook"), "sessionStart"], {})],
    }

    def _startup(self, host: str, url: str, *, together: bool, **extra: str) -> list[tuple[str, subprocess.CompletedProcess]]:
        """Runs a new session's startup hooks: in parallel, the session hook 0.2 s after the others, or one by one, the session hook first."""
        session = str(uuid.uuid4())
        key = ({"session_id": session, "cwd": "/tmp"} if host == "claude-code"
               else {"conversation_id": session, "workspace_roots": ["/tmp"]})

        def run(argv: list[str], event: dict) -> subprocess.CompletedProcess:
            return subprocess.run(argv, input=json.dumps({**key, **event}), capture_output=True, text=True,
                                  env=self._env(url, **extra), timeout=30)

        hooks = self.STARTUP[host]
        names = [event.get("hook_event_name") or argv[1] for argv, event in hooks]
        if not together:
            return [(names[-1], run(*hooks[-1]))] + [(n, run(*h)) for n, h in zip(names[:-1], hooks[:-1])]
        with ThreadPoolExecutor(len(hooks)) as pool:
            futures = [pool.submit(run, *hook) for hook in hooks[:-1]]
            time.sleep(0.2)
            futures.append(pool.submit(run, *hooks[-1]))
            return [(n, f.result()) for n, f in zip(names, futures)]

    @staticmethod
    def _blocked(name: str, p: subprocess.CompletedProcess) -> bool | None:
        """Whether a hook process blocked its step, in that hook's own shape; None for the session hooks, which decide nothing."""
        out = json.loads(p.stdout or "{}")
        return {"UserPromptSubmit": out.get("decision") == "block",
                "PreToolUse": out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny",
                "beforeSubmitPrompt": out.get("continue") is False,
                "preToolUse": out.get("permission") == "deny"}.get(name)

    def _slow_hello(self, seconds: float, answer=None) -> ProgrammableGuardian:
        guardian = ProgrammableGuardian(hmac_secret=SECRET, threaded=True)
        answer = answer or guardian._default_handshake
        guardian.handlers["handshake/hello"] = lambda req: (time.sleep(seconds), answer(req))[1]
        guardian.start()
        self.addCleanup(guardian.stop)
        return guardian

    def test_parallel_startup_hooks_send_one_handshake_then_session_start(self) -> None:
        guardian = self._slow_hello(0.5)
        for host in self.STARTUP:
            with self.subTest(host):
                guardian.reset()
                self._startup(host, guardian.url(), together=False)
                one_by_one = guardian.methods_seen()
                guardian.reset()
                results = self._startup(host, guardian.url(), together=True)
                seen = guardian.methods_seen()
                self.assertEqual((seen.count("handshake/hello"), seen.count("steps/sessionStart")), (1, 1), seen)
                self.assertEqual(seen[:2], ["handshake/hello", "steps/sessionStart"],
                                 "every step of the session follows its one handshake and its sessionStart (§8)")
                self.assertEqual(sorted(seen), sorted(one_by_one), "parallel hooks send what the same hooks send one by one")
                self.assertEqual(len({r["params"]["metadata"]["session_id"] for r in guardian.received}), 1)
                for name, p in results:
                    self.assertEqual((name, p.returncode, self._blocked(name, p)),
                                     (name, 0, None if self._blocked(name, p) is None else False), p.stderr[-300:])

    def test_a_resumed_or_compacted_claude_session_keeps_its_one_session_start(self) -> None:
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        guardian.handlers["steps/sessionStart"] = lambda req: {
            "type": "final", "acs_version": "0.1.0", "request_id": req["params"]["request_id"],
            "decision": "allow", "reasoning": "context from the Guardian", "chain_hash": "0" * 64}
        guardian.start()
        self.addCleanup(guardian.stop)
        session = str(uuid.uuid4())
        outputs = []
        for source in ("startup", "resume", "compact"):
            event = {"session_id": session, "cwd": "/tmp", "hook_event_name": "SessionStart", "source": source}
            p = subprocess.run([str(BIN / "acs-claude-code-hook")], input=json.dumps(event), capture_output=True,
                               text=True, env=self._env(guardian.url()), timeout=30)
            self.assertEqual(p.returncode, 0, p.stderr[-300:])
            outputs.append(json.loads(p.stdout) if p.stdout.strip() else None)
        self.assertEqual(guardian.methods_seen(), ["handshake/hello", "steps/sessionStart"])
        context = {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "context from the Guardian"}}
        # Resume and compact start Claude's context again, so the Guardian's context is given each time.
        self.assertEqual(outputs, [context, context, context])
        self.assertEqual(guardian.envelopes_for("steps/sessionStart")[0]["params"]["payload"]["platform_context"]["source"],
                         "startup")

    def test_the_session_start_context_reaches_claude_when_another_hook_opened_the_session(self) -> None:
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        guardian.handlers["steps/sessionStart"] = lambda req: {
            "type": "final", "acs_version": "0.1.0", "request_id": req["params"]["request_id"],
            "decision": "allow", "reasoning": "context from the Guardian", "chain_hash": "0" * 64}
        guardian.start()
        self.addCleanup(guardian.stop)
        session = str(uuid.uuid4())
        first = {"session_id": session, "cwd": "/tmp", "hook_event_name": "UserPromptSubmit", "prompt": "hi"}
        later = {"session_id": session, "cwd": "/tmp", "hook_event_name": "SessionStart", "source": "startup"}
        outputs = []
        for event in (first, later):
            p = subprocess.run([str(BIN / "acs-claude-code-hook")], input=json.dumps(event), capture_output=True,
                               text=True, env=self._env(guardian.url()), timeout=30)
            self.assertEqual(p.returncode, 0, p.stderr[-300:])
            outputs.append(p.stdout.strip())
        self.assertEqual(guardian.methods_seen().count("steps/sessionStart"), 1)
        self.assertEqual(guardian.methods_seen()[:2], ["handshake/hello", "steps/sessionStart"])
        self.assertEqual(json.loads(outputs[1]), {"hookSpecificOutput": {
            "hookEventName": "SessionStart", "additionalContext": "context from the Guardian"}})

    def test_the_session_start_decision_governs_every_hook_of_the_session(self) -> None:
        # sessionStart answer, the negotiated on_decision_failure, and whether the session's tool calls proceed.
        cases = {"allow": ("allow", "deny", True), "deny": ("deny", "proceed", False),
                 "signed refusal": ("refusal", "proceed", False),
                 "timeout under deny": ("timeout", "deny", False),
                 "timeout under proceed": ("timeout", "proceed", True)}
        for host, run in (("claude-code", self._claude), ("cursor", self._cursor)):
            for name, (answer, on_failure, proceeds) in cases.items():
                with self.subTest(host, case=name):
                    guardian = ProgrammableGuardian(hmac_secret=SECRET, threaded=True)

                    def hello(req, base=guardian._default_handshake, on_failure=on_failure):
                        return {**base(req), "on_decision_failure": on_failure, "timeout_config": {"default_ms": 300}}

                    def start(req, answer=answer, allow=guardian._default_allow):
                        if answer == "refusal":
                            return {"code": -32000, "message": "session start refused"}
                        if answer == "timeout":
                            time.sleep(0.6)
                        return {**allow(req), "decision": "deny" if answer == "deny" else "allow",
                                "reasoning": "start policy"}
                    guardian.handlers.update({"handshake/hello": hello, "steps/sessionStart": start})
                    guardian.start()
                    self.addCleanup(guardian.stop)
                    session = str(uuid.uuid4())
                    for process in (1, 2):
                        p, denied, audits = run(guardian.url(), session)
                        self.assertEqual(denied, not proceeds, (process, p.stdout, audits))
                    self.assertEqual(guardian.methods_seen(), ["handshake/hello", "steps/sessionStart"]
                                     + (["steps/toolCallRequest"] * 2 if proceeds else []))

    def test_a_hook_its_own_profile_requirement_refuses_leaves_the_start_to_the_next_hook(self) -> None:
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        guardian.handlers["handshake/hello"] = lambda req: {**guardian._default_handshake(req), "profiles_accepted": []}
        guardian.start()
        self.addCleanup(guardian.stop)
        for host, run in (("claude-code", self._claude), ("cursor", self._cursor)):
            with self.subTest(host):
                guardian.reset()
                session = str(uuid.uuid4())
                p, denied, audits = run(guardian.url(), session, ACS_REQUIRE_PROFILES="acs-core")
                self.assertTrue(denied, p.stdout)
                self.assertEqual(guardian.methods_seen(), ["handshake/hello"])
                p, denied, _ = run(guardian.url(), session)
                self.assertFalse(denied, p.stdout)
                self.assertEqual(guardian.methods_seen(), ["handshake/hello", "steps/sessionStart", "steps/toolCallRequest"])

    def _end(self, host: str, url: str, session: str, **extra: str) -> subprocess.CompletedProcess:
        if host == "claude-code":
            argv, event = [str(BIN / "acs-claude-code-hook")], {"session_id": session, "cwd": "/tmp",
                                                               "hook_event_name": "SessionEnd", "reason": "clear"}
        else:
            argv, event = [str(BIN / "acs-cursor-hook"), "sessionEnd"], {"conversation_id": session,
                                                                        "workspace_roots": ["/tmp"], "reason": "completed"}
        return subprocess.run(argv, input=json.dumps(event), capture_output=True, text=True,
                              env=self._env(url, **extra), timeout=30)

    def test_session_end_counts_the_sessions_decision_failures_once_each(self) -> None:
        # The tool call, or sessionStart, gets no decision within the negotiated 300 ms (§6.4: timeout).
        for host, run in (("claude-code", self._claude), ("cursor", self._cursor)):
            for slow in ("steps/toolCallRequest", "steps/sessionStart"):
                with self.subTest(host, slow=slow):
                    guardian = ProgrammableGuardian(hmac_secret=SECRET, threaded=True)

                    def hello(req, base=guardian._default_handshake):
                        return {**base(req), "timeout_config": {"default_ms": 300}}

                    def late(req, allow=guardian._default_allow):
                        time.sleep(0.6)
                        return allow(req)
                    guardian.handlers.update({"handshake/hello": hello, slow: late})
                    guardian.start()
                    self.addCleanup(guardian.stop)
                    session = str(uuid.uuid4())
                    # A fail-closed hook re-settles a sessionStart failure through the gate; that is not a second failure.
                    run(guardian.url(), session, ACS_DEFAULT_DENY="0" if slow == "steps/toolCallRequest" else "1")
                    p = self._end(host, guardian.url(), session)
                    self.assertEqual(p.returncode, 0, p.stderr[-300:])
                    ends = guardian.envelopes_for("steps/sessionEnd")
                    self.assertEqual(len(ends), 1, guardian.methods_seen())
                    payload = ends[0]["params"]["payload"]
                    self.assertEqual(payload["summary"]["decision_failures"], {"timeout": 1})
                    self.assertEqual(validate_hook_payload(payload, "session-end.json"), [])

    def test_a_fail_closed_session_end_still_reports_a_start_without_a_decision(self) -> None:
        # sessionEnd is audit-only, so a fail-closed hook sends it with the start's timeout (§6.4).
        for host, run in (("claude-code", self._claude), ("cursor", self._cursor)):
            with self.subTest(host):
                guardian = ProgrammableGuardian(hmac_secret=SECRET, threaded=True)

                def hello(req, base=guardian._default_handshake):
                    return {**base(req), "timeout_config": {"default_ms": 300}}

                def late(req, allow=guardian._default_allow):
                    time.sleep(0.6)
                    return allow(req)
                guardian.handlers.update({"handshake/hello": hello, "steps/sessionStart": late})
                guardian.start()
                self.addCleanup(guardian.stop)
                session = str(uuid.uuid4())
                run(guardian.url(), session, ACS_DEFAULT_DENY="1")
                p = self._end(host, guardian.url(), session, ACS_DEFAULT_DENY="1")
                self.assertEqual(p.returncode, 0, p.stderr[-300:])
                [end] = guardian.envelopes_for("steps/sessionEnd")
                self.assertEqual(end["params"]["payload"]["summary"]["decision_failures"], {"timeout": 1})
                self.assertNotIn("steps/toolCallRequest", guardian.methods_seen(), "the fail-closed step was not sent")

    def test_a_claude_reply_without_a_decision_is_counted_and_the_turn_still_ends(self) -> None:
        guardian = ProgrammableGuardian(hmac_secret=SECRET, threaded=True)

        def hello(req, base=guardian._default_handshake):
            return {**base(req), "timeout_config": {"default_ms": 300}}

        def late(req, allow=guardian._default_allow):
            time.sleep(0.6)
            return allow(req)
        guardian.handlers.update({"handshake/hello": hello, "steps/agentResponse": late})
        guardian.start()
        self.addCleanup(guardian.stop)
        session = str(uuid.uuid4())
        for event in ({"hook_event_name": "UserPromptSubmit", "prompt": "hi"},
                      {"hook_event_name": "Stop", "last_assistant_message": "the reply"}):
            p = subprocess.run([str(BIN / "acs-claude-code-hook")], input=json.dumps({"session_id": session, "cwd": "/tmp", **event}),
                               capture_output=True, text=True, env=self._env(guardian.url(), ACS_DEFAULT_DENY="1"), timeout=30)
            self.assertEqual(p.returncode, 0, p.stderr[-300:])
        self.assertEqual(p.stdout.strip(), "", "a block on Stop would tell Claude Code to keep going")
        self.assertIn('"failure_class": "timeout"', p.stderr)
        self.assertEqual(guardian.methods_seen()[-1], "steps/turnEnd")
        self.assertEqual(self._end("claude-code", guardian.url(), session).returncode, 0)
        [end] = guardian.envelopes_for("steps/sessionEnd")
        self.assertEqual(end["params"]["payload"]["summary"]["decision_failures"], {"timeout": 1})

    def test_values_the_signer_cannot_encode_reach_the_guardian_replaced(self) -> None:
        guardian = ProgrammableGuardian(hmac_secret=SECRET)
        guardian.start()
        self.addCleanup(guardian.stop)
        big = 2 ** 53 + 1
        claude = [str(BIN / "acs-claude-code-hook")]
        cursor = str(BIN / "acs-cursor-hook")
        cases = {
            # (argv, event, the method that carries the value, where the replaced value lands, what it becomes)
            "Claude Code tool call with an integer past 2**53": (claude, {
                "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "echo", "id": big}},
                "steps/toolCallRequest", lambda p: p["arguments"]["id"]["value"], str(big)),
            "Claude Code Bash command with a lone surrogate": (claude, {
                "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "echo \ud800"}},
                "steps/toolCallRequest", lambda p: p["arguments"]["command"]["value"], "echo \ufffd"),
            "Claude Code prompt with a lone surrogate": (claude, {
                "hook_event_name": "UserPromptSubmit", "prompt": "hi \ud800"},
                "steps/userMessage", lambda p: p["content"][0]["value"], "hi \ufffd"),
            "Claude Code tool output with an integer past 2**53": (claude, {
                "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "echo"},
                "tool_response": {"stdout": "", "id": big}},
                "steps/toolCallResult", lambda p: p["outputs"][0]["value"]["id"], str(big)),
            "Cursor tool call with an integer past 2**53": ([cursor, "preToolUse"], {
                "tool_name": "Bash", "tool_input": {"command": "echo", "id": big}},
                "steps/toolCallRequest", lambda p: p["arguments"]["id"]["value"], str(big)),
            "Cursor prompt with a lone surrogate": ([cursor, "beforeSubmitPrompt"], {"prompt": "hi \ud800"},
                "steps/userMessage", lambda p: p["content"][0]["value"], "hi \ufffd"),
        }
        for name, (argv, event, method, value, expected) in cases.items():
            with self.subTest(name):
                guardian.reset()
                session = str(uuid.uuid4())
                key = ({"session_id": session, "cwd": "/tmp"} if "claude" in argv[0]
                       else {"conversation_id": session, "workspace_roots": ["/tmp"]})
                raw = json.dumps({**key, **event}).replace("\\\\ud800", "\\ud800")
                p = subprocess.run(argv, input=raw, capture_output=True, text=True,
                                   env=self._env(guardian.url(), ACS_DEFAULT_DENY="0"), timeout=30)
                self.assertEqual(p.returncode, 0, p.stderr[-300:])
                self.assertIn("envelope_normalized", [r["acs_audit_event"] for r in _audit_records(p.stderr)])
                [step] = guardian.envelopes_for(method)
                self.assertEqual(value(step["params"]["payload"]), expected)
                out = json.loads(p.stdout) if p.stdout.strip() else {}
                self.assertNotIn(out.get("hookSpecificOutput", {}).get("permissionDecision"), ("deny",), out)
                self.assertNotIn(out.get("decision"), ("block",), out)
                self.assertNotEqual(out.get("permission"), "deny", out)
                self.assertNotEqual(out.get("continue"), False, out)

    def test_parallel_startup_hooks_follow_one_refusal(self) -> None:
        guardian = self._slow_hello(0.5, lambda req: {"code": -32000, "message": "agent not permitted"})
        for host in self.STARTUP:
            with self.subTest(host):
                guardian.reset()
                results = self._startup(host, guardian.url(), together=True)
                self.assertEqual(guardian.methods_seen(), ["handshake/hello"])
                audits = [a for _, p in results for a in (r["acs_audit_event"] for r in _audit_records(p.stderr))]
                self.assertEqual(audits.count("session_refused"), 1, audits)
                for name, p in results:
                    self.assertEqual(p.returncode, 0, (name, p.stderr[-300:]))
                    self.assertIn(self._blocked(name, p), (True, None), (name, p.stdout))

    def test_parallel_startup_hooks_follow_one_unanswered_handshake(self) -> None:
        guardian = self._slow_hello(3)
        for host in self.STARTUP:
            with self.subTest(host):
                guardian.reset()
                results = self._startup(host, guardian.url(), together=True, ACS_HANDSHAKE_TIMEOUT_SECONDS="1")
                self.assertEqual(guardian.methods_seen(), ["handshake/hello"])
                audits = {name: [r["acs_audit_event"] for r in _audit_records(p.stderr)] for name, p in results}
                self.assertEqual(sum(a.count("session_without_negotiated_guardian") for a in audits.values()), 1, audits)
                for name, p in results:
                    self.assertEqual(p.returncode, 0, (name, p.stderr[-300:]))
                    if self._blocked(name, p) is not None:
                        self.assertFalse(self._blocked(name, p), (name, p.stdout))
                        self.assertIn("unguarded_session_bypass", audits[name])


if __name__ == "__main__":
    unittest.main()
