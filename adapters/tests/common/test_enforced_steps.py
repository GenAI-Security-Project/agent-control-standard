from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from acs.client import _exchange, _handshake, _store
from acs.core import coerce_uuid
from acs.testing.harness import NEGOTIATED_HELLO, seed_negotiated_session, signing_env

URL = "http://127.0.0.1:1/acs"


def run_in_process(module, argv: list[str], event: dict, *, server_hello: dict | None = None,
                   env: dict[str, str] | None = None) -> tuple[dict, list[dict]]:
    """Run an adapter's main() on one event in a session already negotiated with URL; return its output and audits."""
    with tempfile.TemporaryDirectory(prefix="acs-enforced-") as root:
        session = event.get("session_id") or coerce_uuid(event["conversation_id"], namespace_prefix="cursor")
        seed_negotiated_session(Path(root) / "handshake", session_id=session, guardian_url=URL,
                                hmac_secret=signing_env()["ACS_HMAC_SECRET"],
                                server_hello=server_hello or NEGOTIATED_HELLO)
        stdout, stderr = io.StringIO(), io.StringIO()
        environ = {k: v for k, v in os.environ.items() if not k.startswith("ACS_")}
        environ.update(signing_env(), ACS_GUARDIAN_URL=URL, ACS_DEFAULT_DENY="0", **(env or {}))
        with mock.patch.dict(os.environ, environ, clear=True), \
                mock.patch.object(_handshake, "_HANDSHAKE_CACHE_DIR", Path(root) / "handshake"), \
                mock.patch.object(_store, "_SESSION_STATE_DIR", Path(root) / "state"), \
                mock.patch.object(sys, "argv", argv), mock.patch.object(sys, "stdin", io.StringIO(json.dumps(event))), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = module.main()
    assert code == 0, stderr.getvalue()
    audits = [json.loads(line[len("ACS_AUDIT "):]) for line in stderr.getvalue().splitlines()
              if line.startswith("ACS_AUDIT ")]
    return (json.loads(stdout.getvalue()) if stdout.getvalue().strip() else {}), audits


def _unsignable(*args, **kwargs):
    raise ValueError("no RFC 8785 form")


class AnUnsignableResultIsWithheld(unittest.TestCase):
    def test_claude_code_withholds_a_tool_result_it_cannot_sign_under_fail_open(self) -> None:
        from acs.integrations.claude_code import adapter
        event = {"session_id": str(uuid.uuid4()), "cwd": "/tmp", "hook_event_name": "PostToolUse",
                 "tool_name": "Bash", "tool_input": {"command": "cat creds"},
                 "tool_response": {"stdout": "secret", "stderr": "", "interrupted": False, "isImage": False}}
        with mock.patch.object(_exchange, "sign_envelope", _unsignable):
            out, audits = run_in_process(adapter, ["acs-claude-code-hook"], event)
        self.assertNotIn("secret", json.dumps(out["hookSpecificOutput"]["updatedToolOutput"]))
        self.assertIn(("decision_failure_fail_closed", "envelope_not_signable"),
                      [(a["acs_audit_event"], a.get("cause")) for a in audits])


    def test_cursor_withholds_an_mcp_result_it_cannot_sign_under_fail_open(self) -> None:
        from acs.integrations.cursor import adapter
        event = {"conversation_id": str(uuid.uuid4()), "workspace_roots": ["/tmp"], "tool_name": "MCP:fetch",
                 "tool_input": {"url": "https://example.com"}, "tool_output": json.dumps({"text": "secret"})}
        with mock.patch.object(_exchange, "sign_envelope", _unsignable):
            out, audits = run_in_process(adapter, ["acs-cursor-hook", "postToolUse"], event)
        self.assertNotIn("secret", json.dumps(out))
        self.assertIn("withheld", json.dumps(out["updated_mcp_tool_output"]))
        self.assertIn(("decision_failure_fail_closed", "envelope_not_signable"),
                      [(a["acs_audit_event"], a.get("cause")) for a in audits])


class AStepErrorKeepsTheNegotiatedDeny(unittest.TestCase):
    HELLO = {**NEGOTIATED_HELLO, "on_decision_failure": "deny"}

    def _raises(self, *args, **kwargs):
        raise RuntimeError("boom")

    def test_claude_code(self) -> None:
        from acs.integrations.claude_code import adapter
        event = {"session_id": str(uuid.uuid4()), "cwd": "/tmp", "hook_event_name": "PreToolUse",
                 "tool_name": "Bash", "tool_input": {"command": "echo"}}
        with mock.patch.object(adapter, "build_request", self._raises):
            out, audits = run_in_process(adapter, ["acs-claude-code-hook"], event, server_hello=self.HELLO)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn(("decision_failure_fail_closed", "adapter_exception"),
                      [(a["acs_audit_event"], a.get("cause")) for a in audits])

    def test_cursor(self) -> None:
        from acs.integrations.cursor import adapter
        event = {"conversation_id": str(uuid.uuid4()), "workspace_roots": ["/tmp"],
                 "tool_name": "Shell", "tool_input": {"command": "echo"}}
        with mock.patch.object(adapter, "build_request", self._raises):
            out, audits = run_in_process(adapter, ["acs-cursor-hook", "preToolUse"], event, server_hello=self.HELLO)
        self.assertEqual(out["permission"], "deny")
        self.assertIn(("decision_failure_fail_closed", "adapter_exception"),
                      [(a["acs_audit_event"], a.get("cause")) for a in audits])


if __name__ == "__main__":
    unittest.main()
