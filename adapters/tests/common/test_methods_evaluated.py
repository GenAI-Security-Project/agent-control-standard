"""handshake.json: methods absent from methods_evaluated are ALLOW-by-default, so a block can only come from the adapter's own handling."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

from acs.testing.harness import ProgrammableGuardian  # noqa: E402

ADAPTERS = Path(__file__).resolve().parents[2]
TOOL_HOOKS = ["steps/toolCallRequest", "steps/toolCallResult"]


class SubsetGuardian(ProgrammableGuardian):
    """Declares `evaluated` in its ServerHello, or no methods_evaluated at all when it is None."""

    def __init__(self, evaluated: list[str] | None, tool_decision: str = "allow") -> None:
        super().__init__()
        self.evaluated = evaluated

        def hello(req: dict) -> dict:
            result = self._default_handshake(req)
            if evaluated is None:
                del result["methods_evaluated"]
            else:
                result["methods_evaluated"] = list(evaluated)
            return result

        def step(req: dict) -> dict:
            if evaluated is not None and req["method"] not in evaluated:
                return {"code": -32601, "message": "Method not found"}
            result = self._default_allow(req)
            if req["method"] == "steps/toolCallRequest":
                result["decision"] = tool_decision
                if tool_decision == "deny":
                    result["reasoning"] = "blocked by test policy"
            return result

        self.handlers["handshake/hello"] = hello
        self.handlers["__default__"] = step

    def methods_received(self) -> list[str]:
        return [r.get("method", "") for r in self.received]


class Harness:
    def __init__(self, guardian: ProgrammableGuardian, *, fail_closed: bool = True) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        d = Path(self._tmp.name)
        self.audit_path = d / "audit.log"
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ("ACS_HMAC_SECRET_FILE", "ACS_DEFAULT_DENY", "ACS_HANDSHAKE")}
        self.env.update(
            ACS_GUARDIAN_URL=guardian.url(), ACS_HMAC_SECRET=guardian.hmac_secret, ACS_HMAC_KEY_ID="test-key",
            ACS_HANDSHAKE_CACHE=str(d / "handshake"),
            ACS_SESSION_STATE_DIR=str(d / "state"),
            ACS_AUDIT_FILE=str(self.audit_path))
        if fail_closed:
            self.env["ACS_DEFAULT_DENY"] = "1"
        self.session_id = str(uuid.uuid4())

    def close(self) -> None:
        self._tmp.cleanup()

    def run(self, adapter: str, event_name: str, fields: dict) -> subprocess.CompletedProcess:
        argv = [sys.executable, str(ADAPTERS / "src" / "acs" / "integrations" / adapter.replace("-", "_") / "adapter.py")]
        if adapter == "claude-code":
            event = {"session_id": self.session_id, "transcript_path": "/tmp/t.jsonl",
                     "cwd": "/tmp", "hook_event_name": event_name, **fields}
        else:
            argv.append(event_name)
            event = {"session_id": self.session_id, "conversation_id": self.session_id,
                     "workspace_roots": ["/tmp"], **fields}
        return subprocess.run(argv, input=json.dumps(event), capture_output=True,
                              text=True, env=self.env, timeout=30)

    def audits(self) -> list[dict]:
        if not self.audit_path.exists():
            return []
        return [json.loads(line.removeprefix("ACS_AUDIT "))
                for line in self.audit_path.read_text().splitlines()]

    def audit_names(self) -> list[str]:
        return [a.get("acs_audit_event", "") for a in self.audits()]


PROMPT = {"claude-code": ("UserPromptSubmit", {"prompt": "list the files"}),
          "cursor": ("beforeSubmitPrompt", {"prompt": "list the files"})}
SHELL = {"claude-code": ("PreToolUse", {"tool_name": "Bash", "tool_input": {"command": "ls"},
                                         "tool_use_id": "toolu_evaluated01",
                                         "permission_mode": "default"}),
         "cursor": ("beforeShellExecution", {"command": "ls", "cwd": "/tmp"})}
RESULT = {"claude-code": ("PostToolUse", {"tool_name": "Bash", "tool_input": {"command": "ls"},
                                          "tool_use_id": "toolu_evaluated01",
                                          "tool_response": {"stdout": "a", "stderr": "",
                                                            "interrupted": False},
                                          "permission_mode": "default"}),
          "cursor": ("postToolUse", {"tool_name": "Read", "tool_input": "{\"path\": \"/tmp/x\"}",
                                     "tool_output": "{\"content\": \"x\"}",
                                     "tool_use_id": "tu_evaluated01"})}
FAILURE_EVENTS = {"decision_failure_fail_closed", "fail_open_bypass",
                  "guardian_refusal_fail_closed"}


class MethodsEvaluatedBoundsTraffic(unittest.TestCase):

    def _session(self, evaluated, **kwargs):
        guardian = SubsetGuardian(evaluated, tool_decision=kwargs.pop("tool_decision", "allow"))
        guardian.start()
        self.addCleanup(guardian.stop)
        harness = Harness(guardian, **kwargs)
        self.addCleanup(harness.close)
        return guardian, harness

    def test_prompt_proceeds_when_turn_and_message_are_unevaluated(self) -> None:
        for adapter in ("claude-code", "cursor"):
            with self.subTest(adapter=adapter):
                guardian, h = self._session(TOOL_HOOKS)
                p = h.run(adapter, *PROMPT[adapter])
                self.assertEqual(p.returncode, 0, p.stderr)
                if adapter == "claude-code":
                    self.assertEqual(p.stdout.strip(), "")
                else:
                    self.assertEqual(json.loads(p.stdout), {"continue": True})
                self.assertEqual(guardian.methods_received(), ["handshake/hello"])
                skipped = [a.get("method") for a in h.audits()
                           if a.get("acs_audit_event") == "method_not_evaluated"]
                self.assertEqual(skipped, ["steps/sessionStart", "steps/turnStart", "steps/userMessage"])
                self.assertFalse(FAILURE_EVENTS & set(h.audit_names()), h.audit_names())

    def test_unevaluated_gate_resolves_as_allow(self) -> None:
        """Cursor gets its explicit allow, since a failClosed gate reads an empty reply as a failed hook."""
        for adapter in ("claude-code", "cursor"):
            with self.subTest(adapter=adapter):
                guardian, h = self._session(["steps/toolCallResult"])
                p = h.run(adapter, *SHELL[adapter])
                self.assertEqual(p.returncode, 0, p.stderr)
                if adapter == "claude-code":
                    self.assertEqual(p.stdout.strip(), "")
                else:
                    self.assertEqual(json.loads(p.stdout), {})
                self.assertNotIn("steps/toolCallRequest", guardian.methods_received())
                self.assertFalse(FAILURE_EVENTS & set(h.audit_names()), h.audit_names())

    def test_evaluated_method_decision_still_applies(self) -> None:
        for adapter in ("claude-code", "cursor"):
            with self.subTest(adapter=adapter):
                guardian, h = self._session(TOOL_HOOKS, tool_decision="deny")
                p = h.run(adapter, *SHELL[adapter])
                self.assertEqual(p.returncode, 0, p.stderr)
                out = json.loads(p.stdout)
                if adapter == "claude-code":
                    self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
                else:
                    self.assertEqual(out.get("permission"), "deny")
                self.assertIn("steps/toolCallRequest", guardian.methods_received())

    def test_turn_id_survives_an_unevaluated_turn_start(self) -> None:
        for adapter in ("claude-code", "cursor"):
            with self.subTest(adapter=adapter):
                guardian, h = self._session(TOOL_HOOKS)
                h.run(adapter, *PROMPT[adapter])
                h.run(adapter, *SHELL[adapter])
                calls = [r for r in guardian.received
                         if r.get("method") == "steps/toolCallRequest"]
                self.assertEqual(len(calls), 1)
                self.assertTrue(calls[0]["params"]["metadata"].get("turn_id"))

    def test_an_unevaluated_claude_reply_is_not_sent(self) -> None:
        guardian, h = self._session(["steps/turnStart", "steps/userMessage", "steps/turnEnd"])
        h.run("claude-code", *PROMPT["claude-code"])
        p = h.run("claude-code", "Stop", {"last_assistant_message": "the reply", "permission_mode": "default"})
        self.assertEqual((p.returncode, p.stdout.strip()), (0, ""), p.stderr)
        self.assertNotIn("steps/agentResponse", guardian.methods_received())
        self.assertEqual(guardian.methods_received()[-1], "steps/turnEnd")
        skipped = [a.get("method") for a in h.audits() if a.get("acs_audit_event") == "method_not_evaluated"]
        self.assertIn("steps/agentResponse", skipped)
        self.assertFalse(FAILURE_EVENTS & set(h.audit_names()), h.audit_names())

    def _sent_result(self, guardian: SubsetGuardian, h: Harness) -> dict:
        results = [r for r in guardian.received if r.get("method") == "steps/toolCallResult"]
        self.assertEqual(len(results), 1)
        self.assertFalse(FAILURE_EVENTS & set(h.audit_names()), h.audit_names())
        return results[0]["params"]["payload"]

    def test_result_never_cites_an_unsent_request(self) -> None:
        """A result's request_id_ref would name a request the Guardian never received, so it is dropped and the envelope re-signed."""
        for adapter in ("claude-code", "cursor"):
            for evaluated, cites in ((["steps/toolCallResult"], False), (TOOL_HOOKS, True)):
                with self.subTest(adapter=adapter, evaluated=evaluated):
                    guardian, h = self._session(evaluated)
                    p = h.run(adapter, *RESULT[adapter])
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertEqual("request_id_ref" in self._sent_result(guardian, h), cites)

    def test_an_agent_result_cites_no_tool_call_request_whatever_is_evaluated(self) -> None:
        agent_result = {"tool_name": "Agent", "tool_input": {"prompt": "look around"},
                        "tool_use_id": "toolu_agent01",
                        "tool_response": {"content": "done"}, "permission_mode": "default"}
        for evaluated in (["steps/subagentStart", "steps/toolCallResult"], TOOL_HOOKS):
            with self.subTest(evaluated=evaluated):
                guardian, h = self._session(evaluated)
                p = h.run("claude-code", "PostToolUse", agent_result)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertNotIn("request_id_ref", self._sent_result(guardian, h))

    def test_a_server_hello_without_methods_evaluated_negotiates_nothing(self) -> None:
        """handshake.json requires methods_evaluated, so a ServerHello without it is no answer, and the fail-closed startup posture blocks the prompt."""
        for adapter in ("claude-code", "cursor"):
            with self.subTest(adapter=adapter):
                guardian, h = self._session(None)
                p = h.run(adapter, *PROMPT[adapter])
                self.assertEqual(guardian.methods_received(), ["handshake/hello"])
                if adapter == "claude-code":
                    self.assertEqual(json.loads(p.stdout)["decision"], "block")
                else:
                    self.assertEqual((p.returncode, json.loads(p.stdout)["continue"]), (0, False), p.stderr)
                start = [a for a in h.audits() if a.get("acs_audit_event") == "session_without_negotiated_guardian"]
                self.assertEqual([(a["cause"], a["problem"]) for a in start],
                                 [("invalid_server_hello", "methods_evaluated is not a list of method names")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
