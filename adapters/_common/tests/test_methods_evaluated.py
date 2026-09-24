"""The ServerHello's methods_evaluated bounds what the CLI adapters send.

handshake.json, ServerHello.methods_evaluated: "Methods listed by the client
but absent here are NOT evaluated; the Guardian's enforcement does not cover
them. Clients MAY still emit them for audit but MUST treat them as
ALLOW-by-default." The Guardian below signs every reply, declares a legal
subset, and answers unevaluated methods with the registered -32601, so a
blocked step can only come from the adapter's own handling.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import acs_common  # noqa: E402
from test_harness import ProgrammableGuardian  # noqa: E402

ADAPTERS = Path(__file__).resolve().parents[2]
TOOL_HOOKS = ["steps/toolCallRequest", "steps/toolCallResult"]


class SubsetGuardian(ProgrammableGuardian):
    """Declares `evaluated` in its ServerHello and signs error replies too,
    since ACS-Core requires a signature on every response."""

    def __init__(self, evaluated: list[str], tool_decision: str = "allow") -> None:
        super().__init__()
        self.evaluated = evaluated

        def hello(req: dict) -> dict:
            result = self._default_handshake(req)
            result["methods_evaluated"] = list(evaluated)
            return result

        def step(req: dict) -> dict:
            if req["method"] not in evaluated:
                return {"code": -32601, "message": "Method not found"}
            result = self._default_allow(req)
            if req["method"] == "steps/toolCallRequest":
                result["decision"] = tool_decision
                if tool_decision == "deny":
                    result["reasoning"] = "blocked by test policy"
            return result

        self.handlers["handshake/hello"] = hello
        self.handlers["__default__"] = step

    def _make_handler_cls(self):
        base = super()._make_handler_cls()
        guardian = self

        class SigningHandler(base):
            def _reply(self_h, resp: dict) -> None:
                if "error" in resp and guardian.received:
                    sid = guardian.received[-1]["params"]["metadata"]["session_id"]
                    key = acs_common.derive_session_key(
                        guardian.hmac_secret.encode(), sid)
                    acs_common.sign_envelope(resp, key=key, session_id=sid)
                super()._reply(resp)

        return SigningHandler

    def methods_received(self) -> list[str]:
        return [r.get("method", "") for r in self.received]


class Harness:
    """Runs one adapter process per event against a Guardian, sharing
    session state across the events of one test."""

    def __init__(self, guardian: ProgrammableGuardian, *, fail_closed: bool = True,
                 handshake: bool = True) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        d = Path(self._tmp.name)
        self.audit_path = d / "audit.log"
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ("ACS_HMAC_SECRET_FILE", "ACS_DEFAULT_DENY", "ACS_HANDSHAKE")}
        self.env.update(
            ACS_GUARDIAN_URL=guardian.url(), ACS_HMAC_SECRET=guardian.hmac_secret,
            ACS_HANDSHAKE_CACHE=str(d / "handshake"),
            ACS_SESSION_STATE_DIR=str(d / "state"),
            ACS_AUDIT_FILE=str(self.audit_path))
        if fail_closed:
            self.env["ACS_DEFAULT_DENY"] = "1"
        if not handshake:
            self.env["ACS_HANDSHAKE"] = "0"
        self.session_id = str(uuid.uuid4())

    def close(self) -> None:
        self._tmp.cleanup()

    def run(self, adapter: str, event_name: str, fields: dict) -> subprocess.CompletedProcess:
        argv = [sys.executable, str(ADAPTERS / adapter / "acs_adapter.py")]
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
        """Fail-closed must not block a prompt whose methods the Guardian
        declared unevaluated, and those methods never reach the Guardian."""
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
                self.assertEqual(skipped, ["steps/turnStart", "steps/userMessage"])
                self.assertFalse(FAILURE_EVENTS & set(h.audit_names()), h.audit_names())

    def test_unevaluated_gate_resolves_as_allow(self) -> None:
        """An unevaluated toolCallRequest proceeds without Guardian traffic;
        Cursor gets its explicit allow because failClosed gates read an
        empty reply as a failed hook."""
        for adapter in ("claude-code", "cursor"):
            with self.subTest(adapter=adapter):
                guardian, h = self._session(["steps/toolCallResult"])
                p = h.run(adapter, *SHELL[adapter])
                self.assertEqual(p.returncode, 0, p.stderr)
                if adapter == "claude-code":
                    self.assertEqual(p.stdout.strip(), "")
                else:
                    self.assertEqual(json.loads(p.stdout).get("permission"), "allow")
                self.assertNotIn("steps/toolCallRequest", guardian.methods_received())
                self.assertFalse(FAILURE_EVENTS & set(h.audit_names()), h.audit_names())

    def test_evaluated_method_decision_still_applies(self) -> None:
        """A deny on a method the Guardian does evaluate still blocks."""
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
        """The turn opens locally when turnStart is unevaluated, so evaluated
        in-turn steps still carry metadata.turn_id."""
        for adapter in ("claude-code", "cursor"):
            with self.subTest(adapter=adapter):
                guardian, h = self._session(TOOL_HOOKS)
                h.run(adapter, *PROMPT[adapter])
                h.run(adapter, *SHELL[adapter])
                calls = [r for r in guardian.received
                         if r.get("method") == "steps/toolCallRequest"]
                self.assertEqual(len(calls), 1)
                self.assertTrue(calls[0]["params"]["metadata"].get("turn_id"))

    def _sent_result(self, guardian: SubsetGuardian, h: Harness) -> dict:
        results = [r for r in guardian.received if r.get("method") == "steps/toolCallResult"]
        self.assertEqual(len(results), 1)
        self.assertFalse(FAILURE_EVENTS & set(h.audit_names()), h.audit_names())
        return results[0]["params"]["payload"]

    def test_result_never_cites_an_unsent_request(self) -> None:
        """With toolCallRequest unevaluated, a result's request_id_ref would
        name a request the Guardian never received, so it is dropped (and the
        envelope re-signed); with the request evaluated, the ref stays."""
        for adapter in ("claude-code", "cursor"):
            for evaluated, cites in ((["steps/toolCallResult"], False), (TOOL_HOOKS, True)):
                with self.subTest(adapter=adapter, evaluated=evaluated):
                    guardian, h = self._session(evaluated)
                    p = h.run(adapter, *RESULT[adapter])
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertEqual("request_id_ref" in self._sent_result(guardian, h), cites)

    def test_agent_result_checks_the_spawn_method(self) -> None:
        """A Claude Code Agent call originates as steps/subagentStart, so its
        result's ref follows whether subagentStart is evaluated."""
        agent_result = {"tool_name": "Agent", "tool_input": {"prompt": "look around"},
                        "tool_use_id": "toolu_agent01",
                        "tool_response": {"content": "done"}, "permission_mode": "default"}
        for evaluated, cites in ((["steps/subagentStart", "steps/toolCallResult"], True),
                                 (TOOL_HOOKS, False)):
            with self.subTest(evaluated=evaluated):
                guardian, h = self._session(evaluated)
                p = h.run("claude-code", "PostToolUse", agent_result)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual("request_id_ref" in self._sent_result(guardian, h), cites)

    def test_without_a_negotiated_list_every_method_is_sent(self) -> None:
        """No ServerHello means no evaluated subset is known, so the adapters
        keep sending every method they implement."""
        for adapter in ("claude-code", "cursor"):
            with self.subTest(adapter=adapter):
                guardian, h = self._session(
                    ["steps/turnStart", "steps/userMessage", *TOOL_HOOKS],
                    handshake=False)
                p = h.run(adapter, *PROMPT[adapter])
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(guardian.methods_received(),
                                 ["steps/turnStart", "steps/userMessage"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
