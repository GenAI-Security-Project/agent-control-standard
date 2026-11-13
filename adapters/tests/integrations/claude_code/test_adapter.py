from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE.parents[2] / "src" / "acs" / "integrations" / "claude_code"
ADAPTER = ADAPTER_DIR / "adapter.py"


from acs.testing.harness import (  # noqa: E402
    ProgrammableGuardian,
    launch_guardian,
    signing_env,
    seed_negotiated_session,
)


def _claude_code_event(name: str, **extra) -> dict:
    base = {
        "session_id": "00000000-0000-4000-8000-000000000001",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/tmp/work",
        "hook_event_name": name,
    }
    if name in ("PreToolUse", "PostToolUse", "Stop"):
        base["permission_mode"] = "default"
        base["effort"] = {"level": "high"}
    base.update(extra)
    return base


class AdapterRoundTrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        env = {k: v for k, v in os.environ.items() if k != "ACS_HMAC_SECRET_FILE"}
        env.update(signing_env())
        cls.guardian_proc, cls.port = launch_guardian(env=env)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.guardian_proc.terminate()
        try:
            cls.guardian_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            cls.guardian_proc.kill()

    def setUp(self) -> None:
        # Per-test handshake records, so no run reads a session decision another test stored.
        handshake = tempfile.TemporaryDirectory(prefix="acs-handshake-")
        self.addCleanup(handshake.cleanup)
        self._handshake_dir = handshake.name

    def _negotiated(self, url: str, session_id: str) -> dict[str, str]:
        """Env overrides in which the session already negotiated with url, so the test exercises a step-level failure."""
        seed_negotiated_session(self._handshake_dir, session_id=session_id, guardian_url=url,
                                hmac_secret=signing_env()["ACS_HMAC_SECRET"])
        return {"ACS_HANDSHAKE_CACHE": self._handshake_dir}

    def _run_adapter(
        self,
        event: dict,
        env_overrides: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        env = {k: v for k, v in os.environ.items() if k != "ACS_HMAC_SECRET_FILE"}
        env.update(signing_env())
        env["ACS_GUARDIAN_URL"] = f"http://127.0.0.1:{self.port}/acs"
        env["ACS_HANDSHAKE_CACHE"] = self._handshake_dir
        # Turn state is per test unless the test passes its own ACS_SESSION_STATE_DIR.
        if not (env_overrides and "ACS_SESSION_STATE_DIR" in env_overrides):
            self._state_tmp = tempfile.TemporaryDirectory()
            self.addCleanup(self._state_tmp.cleanup)
            env["ACS_SESSION_STATE_DIR"] = self._state_tmp.name
        if env_overrides:
            env.update(env_overrides)
        proc = subprocess.run(
            [sys.executable, str(ADAPTER)],
            input=json.dumps(event),
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

    def test_safe_tool_call_allows(self) -> None:
        rc, out, err = self._run_adapter(_claude_code_event(
            "PreToolUse", tool_name="Read", tool_input={"file_path": "/tmp/safe.txt"},
        ))
        self.assertEqual(rc, 0, err)
        # An allow prints nothing, so Claude Code's own permission prompt still applies.
        self.assertEqual(out, "")
        self.assertNotIn("ACS_AUDIT", err, "the Guardian answered; nothing proceeded undecided")

    def test_destructive_bash_denied(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "PreToolUse", tool_name="Bash", tool_input={"command": "rm -rf /home/user"},
        ))
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        hso = payload["hookSpecificOutput"]
        self.assertEqual(hso["hookEventName"], "PreToolUse")
        self.assertEqual(hso["permissionDecision"], "deny")
        self.assertIn("destructive", hso["permissionDecisionReason"].lower())

    def test_a_deny_carries_its_reason_to_claude_in_additional_context(self) -> None:
        """Claude reads the permissionDecisionReason of the deny that finishes last, so another hook's deny would hide the ACS reason."""
        cases = {
            "guardian deny": ({}, "destructive"),
            "decision failure": ({"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead", "ACS_DEFAULT_DENY": "1",
                                  **self._negotiated("http://127.0.0.1:1/dead", "00000000-0000-4000-8000-000000000001")},
                                 "decision-failure"),
        }
        for name, (env, expected) in cases.items():
            with self.subTest(name):
                rc, out, err = self._run_adapter(_claude_code_event(
                    "PreToolUse", tool_name="Bash", tool_input={"command": "rm -rf /home/user"}), env_overrides=env)
                self.assertEqual(rc, 0, err)
                hso = json.loads(out)["hookSpecificOutput"]
                self.assertEqual(hso["permissionDecision"], "deny")
                self.assertIn(expected, hso["permissionDecisionReason"].lower())
                self.assertEqual(hso["additionalContext"], f"ACS blocked this tool call: {hso['permissionDecisionReason']}")

    def test_write_to_protected_path_denied(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "PreToolUse", tool_name="Write",
            tool_input={"file_path": "/etc/passwd", "content": "x"},
        ))
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("protected", payload["hookSpecificOutput"]["permissionDecisionReason"].lower())

    def test_session_start_no_output(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "SessionStart", source="startup", model="claude-opus-4-7",
        ))
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_session_end_no_output(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "SessionEnd", reason="clear",
        ))
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_user_prompt_submit_no_block(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "UserPromptSubmit", prompt="summarize my emails",
        ))
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_post_tool_use_no_block(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "PostToolUse", tool_name="Read",
            tool_input={"file_path": "/tmp/x"}, tool_output="file contents",
        ))
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_notification_no_block(self) -> None:
        rc, out, _ = self._run_adapter(_claude_code_event(
            "Notification", notification_type="permission_prompt",
            message="confirm action",
        ))
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_unmapped_hook_proceeds(self) -> None:
        rc, out, _ = self._run_adapter({
            "hook_event_name": "SomeFutureHook",
            "session_id": "x",
            "cwd": "/tmp",
            "transcript_path": "/tmp/t",
            "data": {"x": 1},
        })
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_guardian_unreachable_default_deny_pretoolue(self) -> None:
        rc, out, err = self._run_adapter(
            _claude_code_event(
                "PreToolUse", tool_name="Read",
                tool_input={"file_path": "/tmp/x"},
            ),
            env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead",
                           "ACS_DEFAULT_DENY": "1",
                           **self._negotiated("http://127.0.0.1:1/dead", "00000000-0000-4000-8000-000000000001")},
        )
        self.assertEqual(rc, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("decision-failure", payload["hookSpecificOutput"]["permissionDecisionReason"].lower())
        # §6.4: every decision-failure path must produce an audit event
        self.assertIn("ACS_AUDIT", err)
        self.assertIn("decision_failure_fail_closed", err)

    def test_guardian_unreachable_default_deny_posttool(self) -> None:
        rc, out, err = self._run_adapter(
            _claude_code_event(
                "PostToolUse", tool_name="Read",
                tool_input={"file_path": "/tmp/x"}, tool_output="x",
            ),
            env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead",
                           "ACS_DEFAULT_DENY": "1",
                           **self._negotiated("http://127.0.0.1:1/dead", "00000000-0000-4000-8000-000000000001")},
        )
        self.assertEqual(rc, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["decision"], "block")
        self.assertIn("decision-failure", payload["reason"].lower())
        self.assertIn("ACS_AUDIT", err)

    def test_an_unanswered_handshake_refuses_the_step(self) -> None:
        with mock.patch.dict(os.environ):
            for name in ("ACS_DEFAULT_DENY", "ACS_STARTUP_POSTURE"):
                os.environ.pop(name, None)
            rc, out, err = self._run_adapter(
                _claude_code_event("PreToolUse", tool_name="Read", tool_input={"file_path": "/tmp/x"}),
                env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead"})
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("session_not_started_fail_closed", err)

    def test_guardian_unreachable_under_a_local_proceed_is_audited(self) -> None:
        rc, out, err = self._run_adapter(
            _claude_code_event(
                "PreToolUse", tool_name="Read",
                tool_input={"file_path": "/tmp/x"},
            ),
            env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead", "ACS_DEFAULT_DENY": "0",
                           **self._negotiated("http://127.0.0.1:1/dead", "00000000-0000-4000-8000-000000000001")},
        )
        self.assertEqual(rc, 0, err)
        self.assertEqual(out, "")  # proceed (fail-open)
        # §6.4: 'Every step that proceeds without a decision MUST be recorded as an audit event'
        self.assertIn("ACS_AUDIT", err, "fail-open MUST emit an audit event per §6.4")
        self.assertIn("fail_open_bypass", err)

    def test_a_guardian_s_declared_proceed_alone_denies(self) -> None:
        """The seeded ServerHello declares proceed, and only the hook's own ACS_DEFAULT_DENY=0 can opt into it."""
        env = {k: v for k, v in os.environ.items() if k != "ACS_DEFAULT_DENY"}
        with mock.patch.dict(os.environ, env, clear=True):
            rc, out, err = self._run_adapter(
                _claude_code_event("PreToolUse", tool_name="Read", tool_input={"file_path": "/tmp/x"}),
                env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead",
                               **self._negotiated("http://127.0.0.1:1/dead", "00000000-0000-4000-8000-000000000001")},
            )
        self.assertEqual(rc, 0, err)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("decision_failure_fail_closed", err)
        self.assertNotIn("fail_open_bypass", err)

    def test_audit_only_hooks_never_emit_a_block(self) -> None:
        """Claude Code reads a block on Stop as "keep going", so neither a DENY nor a decision failure may produce one."""
        for hook in ("Stop",):
            with self.subTest(hook=hook, case="guardian denies"):
                g = ProgrammableGuardian()
                g.handlers["__default__"] = lambda req: {
                    "type": "final", "acs_version": "0.1.0",
                    "request_id": req["params"]["request_id"],
                    "chain_hash": "0" * 64, "decision": "deny",
                    "reasoning": "policy hit",
                }
                # turnEnd reaches the Guardian only for an open turn, so a UserPromptSubmit opens one first in an isolated state dir.
                with g, tempfile.TemporaryDirectory() as state:
                    env = {"ACS_GUARDIAN_URL": g.url(),
                           "ACS_HMAC_SECRET": g.hmac_secret, "ACS_HMAC_KEY_ID": "test-key",
                           "ACS_SESSION_STATE_DIR": state}
                    if hook == "Stop":
                        # The default handler denies, which would block the prompt before the turn opened.
                        g.handlers["steps/turnStart"] = lambda req: {
                            "type": "final", "acs_version": "0.1.0",
                            "request_id": req["params"]["request_id"],
                            "chain_hash": "0" * 64, "decision": "allow",
                        }
                        g.handlers["steps/userMessage"] = g.handlers["steps/turnStart"]
                        self._run_adapter(
                            _claude_code_event("UserPromptSubmit",
                                               prompt="open a turn"),
                            env_overrides=env)
                    rc, out, err = self._run_adapter(
                        _claude_code_event(hook), env_overrides=env)
                self.assertNotIn('"decision": "block"', out,
                    f"{hook} carries no decision; a block tells Claude Code to "
                    f"keep going. Got {out!r}")
                self.assertIn("unenforceable_decision", err,
                    "the verdict must still be recorded")

            with self.subTest(hook=hook, case="guardian unreachable"):
                rc, out, err = self._run_adapter(
                    _claude_code_event(hook),
                    env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/acs",
                                   "ACS_DEFAULT_DENY": "1",
                                   **self._negotiated("http://127.0.0.1:1/acs", "00000000-0000-4000-8000-000000000001")})
                self.assertNotIn('"decision": "block"', out,
                    f"fail-closed on {hook} must not emit a block, which reads "
                    f"as 'do not stop'. Got {out!r}")
                self.assertIn("ACS_AUDIT", err)

    def test_subagent_stop_is_unmapped_silent(self) -> None:
        rc, out, err = self._run_adapter(
            _claude_code_event("SubagentStop"),
            env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/acs",
                           "ACS_DEFAULT_DENY": "1",
                           **self._negotiated("http://127.0.0.1:1/acs", "00000000-0000-4000-8000-000000000001")})
        self.assertEqual(rc, 0)
        self.assertEqual(out, "",
            f"unmapped SubagentStop must produce no output; got {out!r}")



def _answer(**decision):
    return lambda req: {"type": "final", "acs_version": "0.1.0", "request_id": req["params"]["request_id"],
                        "chain_hash": "0" * 64, **decision}


class _GuardianRun(unittest.TestCase):
    def _run(self, g: ProgrammableGuardian, *events: dict) -> list[tuple[str, str]]:
        results = []
        with tempfile.TemporaryDirectory() as root:
            env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
            env.update(ACS_GUARDIAN_URL=g.url(), ACS_HMAC_SECRET=g.hmac_secret, ACS_HMAC_KEY_ID="test-key",
                       ACS_HANDSHAKE_CACHE=f"{root}/handshake", ACS_SESSION_STATE_DIR=f"{root}/state")
            for event in events:
                proc = subprocess.run([sys.executable, str(ADAPTER)], input=json.dumps(event),
                                      capture_output=True, text=True, env=env, timeout=10)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                results.append((proc.stdout.strip(), proc.stderr))
        return results


# The Bash replacement shape the hooks reference documents (PostToolUse decision control, 2026-11-01).
DOCUMENTED_BASH_REPLACEMENT = {"stdout": "[redacted]", "stderr": "", "interrupted": False, "isImage": False}
BASH_SHAPE = set(DOCUMENTED_BASH_REPLACEMENT)

# Built-in tools' tool_response, and for each the fields and literals its output schema requires, transcribed from the
# Claude Code 2.1.317 program; a replacement without them is ignored and Claude sees the original output.
BUILT_IN_RESPONSES = {
    "Read": ({"type": "text", "file": {"filePath": "/repo/.env", "content": "SECRET-OUTPUT", "numLines": 1,
                                       "startLine": 1, "totalLines": 1}},
             {"type": "text"}, ("file",), lambda r: r["file"]["content"]),
    "Grep": ({"mode": "content", "numFiles": 1, "filenames": ["/repo/SECRET-OUTPUT"], "content": "SECRET-OUTPUT",
              "numLines": 1}, {"mode": "content"}, ("numFiles", "filenames"), lambda r: r["content"]),
    "Glob": ({"durationMs": 3, "numFiles": 1, "filenames": ["/repo/SECRET-OUTPUT"], "truncated": False},
             {}, ("durationMs", "numFiles", "filenames", "truncated"), None),
    "WebFetch": ({"bytes": 13, "code": 200, "codeText": "OK", "result": "SECRET-OUTPUT", "durationMs": 5,
                  "url": "https://example.com/page"}, {}, ("bytes", "code", "codeText", "durationMs", "url"),
                 lambda r: r["result"]),
    "WebSearch": ({"query": "q", "results": [{"tool_use_id": "s1", "content": [{"title": "SECRET-OUTPUT",
                                                                                "url": "https://example.com"}]}],
                   "durationSeconds": 1.5}, {}, ("query", "durationSeconds"), lambda r: r["results"][0]),
    "Write": ({"type": "update", "filePath": "/repo/a", "content": "SECRET-OUTPUT", "structuredPatch": [{"lines": ["SECRET-OUTPUT"]}],
               "originalFile": "SECRET-OUTPUT"}, {"type": "update"}, ("filePath", "structuredPatch", "originalFile"),
              lambda r: r["content"]),
    "Edit": ({"filePath": "/repo/a", "oldString": "SECRET-OUTPUT", "newString": "SECRET-OUTPUT", "originalFile": "SECRET-OUTPUT",
              "structuredPatch": [{"lines": ["SECRET-OUTPUT"]}], "userModified": False, "replaceAll": False},
             {}, ("filePath", "originalFile", "structuredPatch", "userModified", "replaceAll"), lambda r: r["newString"]),
    "Agent": ({"status": "completed", "agentId": "a1", "prompt": "explore", "canContinueAgent": True,
               "content": [{"type": "text", "text": "SECRET-OUTPUT"}], "handbackReport": {"text": "SECRET-OUTPUT"},
               "totalToolUseCount": 2, "totalDurationMs": 9, "totalTokens": 10,
               "usage": {"input_tokens": 1, "output_tokens": 1, "cache_creation_input_tokens": None,
                         "cache_read_input_tokens": None}},
              {"status": "completed"}, ("agentId", "prompt", "totalToolUseCount", "totalDurationMs", "totalTokens", "usage"),
              lambda r: r["content"][0]["text"]),
}
ASYNC_AGENT = {"status": "async_launched", "agentId": "a2", "description": "SECRET-OUTPUT", "prompt": "explore",
               "outputFile": "/tmp/a2.out"}


class PostToolUseWithholdsOutput(_GuardianRun):
    """A decision that keeps a delivered result from Claude replaces the output where Claude Code applies a
    replacement (hooks reference, PostToolUse decision control) and is recorded where it cannot."""

    def _post(self, tool_name: str, tool_response=None, **decision) -> tuple[dict, str]:
        g = ProgrammableGuardian()
        g.handlers["steps/toolCallResult"] = _answer(**decision)
        if tool_response is None:
            tool_response = {"stdout": "SECRET-OUTPUT", "stderr": "", "interrupted": False, "isImage": False}
        with g:
            [(out, err)] = self._run(g, _claude_code_event(
                "PostToolUse", tool_name=tool_name, tool_input={"command": "cat key"},
                tool_response=tool_response, tool_use_id="t1"))
            self.assertIn("steps/toolCallResult", g.methods_seen())
        self.assertNotIn("SECRET-OUTPUT", out)
        return json.loads(out), err

    def test_a_denied_bash_result_is_replaced_in_bash_s_output_shape(self) -> None:
        for decision in ({"decision": "deny", "reasoning": "leaks a key"},
                         {"decision": "ask", "reasoning": "needs a person", "ask_details": {"approver": {"type": "human", "id": "owner"}, "question": "Run it?", "timeout_seconds": 60}},
                         {"decision": "defer", "reasoning": "later", "defer_details": {"reason": "pending_dependency", "resolution_method": "timeout", "resolution_timeout_ms": 1000, "timeout_decision": "deny"}},
                         {"decision": "maybe", "reasoning": "not a disposition"},
                         {"decision": "modify", "reasoning": "both shapes",
                          "modifications": {"modified_content": "x", "parameter_overrides": {"command": "y"}}}):
            with self.subTest(decision["decision"]):
                out, err = self._post("Bash", **decision)
                self.assertEqual(out["decision"], "block")
                replacement = out["hookSpecificOutput"]["updatedToolOutput"]
                self.assertEqual(set(replacement), BASH_SHAPE)
                self.assertEqual((replacement["stderr"], replacement["interrupted"], replacement["isImage"]),
                                 ("", False, False))
                self.assertIn("withheld", replacement["stdout"])
                self.assertNotIn("unenforceable_decision", err)

    def test_a_denied_mcp_result_is_replaced_with_text(self) -> None:
        out, err = self._post("mcp__files__read", decision="deny", reasoning="leaks a key")
        self.assertEqual(out["decision"], "block")
        self.assertIsInstance(out["hookSpecificOutput"]["updatedToolOutput"], str)
        self.assertIn("withheld", out["hookSpecificOutput"]["updatedToolOutput"])
        self.assertNotIn("unenforceable_decision", err)

    def test_a_denied_result_of_each_supported_built_in_tool_keeps_its_schema(self) -> None:
        for tool, (response, literals, required, notice) in BUILT_IN_RESPONSES.items():
            for decision in ({"decision": "deny", "reasoning": "leaks a key"},
                             {"decision": "modify", "reasoning": "rewrite", "modifications": {"modified_content": "x"}}):
                with self.subTest(tool, decision=decision["decision"]):
                    out, err = self._post(tool, response, **decision)
                    self.assertEqual(out["decision"], "block")
                    replacement = out["hookSpecificOutput"]["updatedToolOutput"]
                    for key, value in literals.items():
                        self.assertEqual(replacement[key], value, f"{tool} keeps the {key} literal")
                    for key in required:
                        self.assertIn(key, replacement)
                    if notice is not None:
                        self.assertIn("withheld", notice(replacement))
                    self.assertNotIn("unenforceable_decision", err)
                    if decision["decision"] == "modify":
                        self.assertIn('"acs_audit_event": "modify_unsupported"', err)

    def test_an_async_agent_launch_keeps_its_status(self) -> None:
        out, _ = self._post("Agent", ASYNC_AGENT, decision="deny", reasoning="leaks a key")
        replacement = out["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual((replacement["status"], replacement["agentId"], replacement["outputFile"]),
                         ("async_launched", "a2", "/tmp/a2.out"))
        self.assertIn("withheld", replacement["description"])

    def test_a_tool_or_output_variant_with_no_known_shape_is_blocked_and_recorded(self) -> None:
        for tool, response in (("NotebookEdit", {"new_source": "SECRET-OUTPUT"}),
                               ("Read", {"type": "image", "file": {"base64": "SECRET-OUTPUT", "type": "image/png",
                                                                  "originalSize": 1}}),
                               ("Agent", {"status": "remote_launched", "taskId": "t", "sessionUrl": "https://example.com",
                                          "description": "SECRET-OUTPUT", "prompt": "p", "outputFile": "/tmp/x"})):
            with self.subTest(tool, variant=response.get("type", response.get("status"))):
                g = ProgrammableGuardian()
                g.handlers["steps/toolCallResult"] = _answer(decision="deny", reasoning="leaks a key")
                with g:
                    [(out, err)] = self._run(g, _claude_code_event("PostToolUse", tool_name=tool, tool_input={},
                                                                   tool_response=response, tool_use_id="t1"))
                self.assertNotIn("updatedToolOutput", json.loads(out)["hookSpecificOutput"])
                self.assertIn('"acs_audit_event": "unenforceable_decision"', err)

    def test_a_denied_result_with_no_tool_response_is_blocked_and_recorded_as_unenforceable(self) -> None:
        g = ProgrammableGuardian()
        g.handlers["steps/toolCallResult"] = _answer(decision="deny", reasoning="leaks a key")
        with g:
            [(out, err)] = self._run(g, _claude_code_event("PostToolUse", tool_name="Read",
                                                           tool_input={"file_path": "/x"}, tool_use_id="t1"))
        self.assertNotIn("updatedToolOutput", json.loads(out)["hookSpecificOutput"])
        self.assertIn('"acs_audit_event": "unenforceable_decision"', err)

    def test_a_modify_with_content_that_is_not_a_string_is_withheld(self) -> None:
        out, err = self._post("Bash", decision="modify", reasoning="rewrite", modifications={"modified_content": ["x"]})
        self.assertEqual(out["decision"], "block")
        self.assertIn("withheld", out["hookSpecificOutput"]["updatedToolOutput"]["stdout"])
        self.assertIn('"acs_audit_event": "modify_composition_invalid"', err)

    def test_a_fail_closed_result_is_withheld_too(self) -> None:
        for tool_name, replaced in (("Bash", True), ("mcp__files__read", True), ("Read", False), (7, False)):
            with self.subTest(tool=tool_name), tempfile.TemporaryDirectory() as root:
                env = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
                env.update(ACS_GUARDIAN_URL="http://127.0.0.1:1/acs", ACS_DEFAULT_DENY="1", ACS_HMAC_KEY_ID="test-key",
                           ACS_HMAC_SECRET=signing_env()["ACS_HMAC_SECRET"], ACS_HANDSHAKE_CACHE=root,
                           ACS_SESSION_STATE_DIR=root)
                seed_negotiated_session(root, session_id="00000000-0000-4000-8000-000000000001",
                                        guardian_url="http://127.0.0.1:1/acs", hmac_secret=signing_env()["ACS_HMAC_SECRET"])
                proc = subprocess.run([sys.executable, str(ADAPTER)], input=json.dumps(_claude_code_event(
                    "PostToolUse", tool_name=tool_name, tool_input={"command": "cat key"},
                    tool_response={"stdout": "SECRET-OUTPUT", "stderr": "", "interrupted": False, "isImage": False})),
                    capture_output=True, text=True, env=env, timeout=10)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                out = json.loads(proc.stdout)
                self.assertEqual(out["decision"], "block")
                self.assertEqual("updatedToolOutput" in out["hookSpecificOutput"], replaced)
                self.assertNotIn("SECRET-OUTPUT", proc.stdout)

    def test_a_modify_replaces_bash_and_mcp_output_with_the_guardian_s_content(self) -> None:
        for tool, expected in (("Bash", {"stdout": "redacted", "stderr": "", "interrupted": False, "isImage": False}),
                               ("mcp__files__read", "redacted")):
            with self.subTest(tool):
                out, err = self._post(tool, decision="modify", reasoning="redact",
                                      modifications={"modified_content": "redacted"})
                self.assertNotIn("decision", out)
                self.assertEqual(out["hookSpecificOutput"]["updatedToolOutput"], expected)


class SubagentHandbackHasNoPrompt(_GuardianRun):
    """Auto mode runs SubagentHandback without a prompt, so only a deny stops it (hooks reference, 2026-11-01)."""

    def _pre(self, **decision) -> tuple[dict, str]:
        g = ProgrammableGuardian()
        g.handlers["steps/toolCallRequest"] = _answer(**decision)
        with g:
            [(out, err)] = self._run(g, _claude_code_event("PreToolUse", tool_name="SubagentHandback",
                                                           permission_mode="auto", tool_input={"message": "report"},
                                                           tool_use_id="t1"))
        return json.loads(out), err

    def test_an_ask_is_a_deny(self) -> None:
        out, err = self._pre(decision="ask", reasoning="check", ask_details={
            "approver": {"type": "human", "id": "owner"}, "question": "Deliver?", "timeout_seconds": 60})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn('"substituted": "deny"', err)

    def test_a_modify_applies_the_rewritten_input(self) -> None:
        out, _ = self._pre(decision="modify", reasoning="redact",
                           modifications={"parameter_overrides": {"message": "[redacted]"}})
        self.assertEqual((out["hookSpecificOutput"]["permissionDecision"], out["hookSpecificOutput"]["updatedInput"]),
                         ("allow", {"message": "[redacted]"}))


class StopSendsTheReply(_GuardianRun):
    """Stop's last_assistant_message is the turn's reply (hooks reference, Stop input): it goes out as
    steps/agentResponse under the open turn, before steps/turnEnd."""

    def _turn(self, g: ProgrammableGuardian, stop: dict) -> tuple[str, str]:
        return self._run(g, _claude_code_event("UserPromptSubmit", prompt="hi"), stop)[1]

    def test_the_reply_is_sent_under_the_open_turn_before_the_turn_ends(self) -> None:
        g = ProgrammableGuardian()
        with g:
            out, _ = self._turn(g, _claude_code_event("Stop", last_assistant_message="the reply"))
            methods = g.methods_seen()
            [reply] = g.envelopes_for("steps/agentResponse")
            [turn_start] = g.envelopes_for("steps/turnStart")
        self.assertEqual(out, "")
        self.assertEqual(methods[-2:], ["steps/agentResponse", "steps/turnEnd"])
        self.assertEqual(reply["params"]["payload"]["content"], [{"type": "text", "value": "the reply"}])
        self.assertEqual(reply["params"]["metadata"]["turn_id"], turn_start["params"]["payload"]["turn_id"])

    def test_a_decision_on_the_delivered_reply_is_recorded_and_the_turn_still_ends(self) -> None:
        g = ProgrammableGuardian()
        g.handlers["steps/agentResponse"] = _answer(decision="deny", reasoning="policy hit")
        with g:
            out, err = self._turn(g, _claude_code_event("Stop", last_assistant_message="the reply"))
            methods = g.methods_seen()
        self.assertEqual(out, "", "a block on Stop would tell Claude Code to keep going")
        self.assertEqual(methods[-1], "steps/turnEnd")
        self.assertIn('"acs_audit_event": "unenforceable_decision"', err)
        self.assertIn('"method": "steps/agentResponse"', err)

    def test_a_modify_on_the_delivered_reply_is_recorded_as_modify_unsupported(self) -> None:
        g = ProgrammableGuardian()
        g.handlers["steps/agentResponse"] = _answer(decision="modify", reasoning="trim",
                                                    modifications={"modified_content": "shorter"})
        with g:
            out, err = self._turn(g, _claude_code_event("Stop", last_assistant_message="the reply"))
        self.assertEqual(out, "")
        [record] = [json.loads(line[len("ACS_AUDIT "):]) for line in err.splitlines()
                    if '"modify_unsupported"' in line]
        self.assertEqual((record["reason_codes"], record["method"]), (["modify_unsupported"], "steps/agentResponse"))

    def test_a_deny_on_the_turn_end_is_recorded_and_nothing_is_emitted(self) -> None:
        g = ProgrammableGuardian()
        g.handlers["steps/turnEnd"] = _answer(decision="deny", reasoning="policy hit")
        with g:
            out, err = self._turn(g, _claude_code_event("Stop"))
        self.assertEqual(out, "", "a block on Stop would tell Claude Code to keep going")
        self.assertIn('"acs_audit_event": "unenforceable_decision"', err)

    def test_a_subagent_spawn_inside_a_turn_carries_the_turn_id(self) -> None:
        g = ProgrammableGuardian()
        with g:
            self._run(g, _claude_code_event("UserPromptSubmit", prompt="hi"),
                      _claude_code_event("PreToolUse", tool_name="Agent", tool_use_id="t9",
                                         tool_input={"prompt": "explore", "subagent_type": "Explore"}))
            [turn_start] = g.envelopes_for("steps/turnStart")
            [spawn] = g.envelopes_for("steps/subagentStart")
        self.assertEqual(spawn["params"]["metadata"]["turn_id"], turn_start["params"]["payload"]["turn_id"])

    def test_a_stop_without_a_reply_sends_no_agent_response(self) -> None:
        g = ProgrammableGuardian()
        with g:
            self._turn(g, _claude_code_event("Stop"))
            methods = g.methods_seen()
        self.assertNotIn("steps/agentResponse", methods)
        self.assertEqual(methods[-1], "steps/turnEnd")

    def test_a_notification_sends_nothing(self) -> None:
        g = ProgrammableGuardian()
        with g:
            [(out, _)] = self._run(g, _claude_code_event("Notification", message="Claude needs your permission",
                                                         notification_type="permission_prompt"))
            methods = g.methods_seen()
        self.assertEqual(out, "")
        self.assertEqual(methods, [], "Notification is unmapped, so the Guardian receives nothing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
