"""
End-to-end tests for the Cursor adapter, using the Claude Code example
Guardian. Cursor's hook schema is taken from the create-hook skill that
ships with Cursor.

Live verification status: unit-tested only. Cursor has no documented
headless mode, so a live fire-through is a manual procedure
(tests/live_verification.md).
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE.parents[2] / "src" / "acs" / "integrations" / "cursor"
ADAPTER = ADAPTER_DIR / "adapter.py"


from acs.core import coerce_uuid  # noqa: E402
from acs.testing.harness import launch_guardian, seed_negotiated_session, signing_env  # noqa: E402


class CursorAdapter(unittest.TestCase):
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

    def _run(self, event_name: str, event: dict, env_overrides: dict | None = None) -> tuple[int, str, str]:
        env = {k: v for k, v in os.environ.items() if k != "ACS_HMAC_SECRET_FILE"}
        env.update(signing_env())
        env["ACS_GUARDIAN_URL"] = f"http://127.0.0.1:{self.port}/acs"
        env["ACS_HANDSHAKE_CACHE"] = self._handshake_dir
        # Turn state is per test, so earlier runs cannot leak into this one.
        if not (env_overrides and "ACS_SESSION_STATE_DIR" in env_overrides):
            tmp = tempfile.TemporaryDirectory()
            self.addCleanup(tmp.cleanup)
            env["ACS_SESSION_STATE_DIR"] = tmp.name
        if env_overrides:
            env.update(env_overrides)
        proc = subprocess.run(
            [sys.executable, str(ADAPTER), event_name],
            input=json.dumps(event),
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

    # ----- preToolUse: allow path -----
    def test_pre_tool_safe_read_allows(self) -> None:
        rc, out, err = self._run("preToolUse", {
            "session_id": "cur-1", "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/x"},
        })
        self.assertEqual(rc, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["permission"], "allow")

    def test_pre_tool_destructive_bash_denies(self) -> None:
        rc, out, _ = self._run("preToolUse", {
            "session_id": "cur-3", "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /home/user"},
        })
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload["permission"], "deny")
        self.assertIn("destructive", payload["user_message"].lower())

    def test_pre_tool_write_to_protected_path_denies(self) -> None:
        rc, out, _ = self._run("preToolUse", {
            "session_id": "cur-4", "tool_name": "Write",
            "tool_input": {"file_path": "/etc/passwd", "content": "x"},
        })
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["permission"], "deny")

    # ----- beforeShellExecution -----
    def test_before_shell_safe(self) -> None:
        rc, out, _ = self._run("beforeShellExecution", {
            "session_id": "cur-5", "command": "ls",
        })
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["permission"], "allow")

    def test_before_shell_destructive_denies(self) -> None:
        rc, out, _ = self._run("beforeShellExecution", {
            "session_id": "cur-6", "command": "rm -rf /home/x",
        })
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["permission"], "deny")

    # ----- subagentStart -----
    def test_subagent_start_gated_by_default(self) -> None:
        """The example Guardian denies subagent spawns by default
        (ACS_ALLOW_SUBAGENT unset), so routing spawns through the proper
        hook never gets a weaker gate than a generic tool call."""
        rc, out, _ = self._run("subagentStart", {
            "session_id": "cur-7", "subagent_type": "explore",
        })
        self.assertEqual(rc, 0)
        payload = json.loads(out) if out else {}
        self.assertEqual(payload.get("permission"), "deny",
            "spawns must be gated by default; got: " + out)

    # ----- Lifecycle events: empty output -----
    def test_session_start_silent(self) -> None:
        rc, out, _ = self._run("sessionStart", {"session_id": "cur-8"})
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_after_agent_response_silent(self) -> None:
        # `text` is the real Cursor field (docs 2026-08-22).
        rc, out, _ = self._run("afterAgentResponse", {
            "session_id": "cur-9", "text": "ok"})
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    # ----- Unknown event -----
    def test_unmapped_event_silent(self) -> None:
        rc, out, _ = self._run("someFutureCursorEvent", {"session_id": "x"})
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    # ----- Fail posture -----
    def test_guardian_unreachable_default_deny_on_permission_event(self) -> None:
        rc, out, err = self._run("preToolUse",
            {"session_id": "cur-10", "tool_name": "Read",
             "tool_input": {"file_path": "/tmp/x"}},
            env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead",
                           "ACS_DEFAULT_DENY": "1",
                           **self._negotiated("http://127.0.0.1:1/dead", coerce_uuid("cur-10", namespace_prefix="cursor"))},
        )
        self.assertEqual(rc, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["permission"], "deny")
        self.assertIn("decision-failure", payload["user_message"].lower())
        self.assertIn("ACS_AUDIT", err)
        self.assertIn("decision_failure_fail_closed", err)

    def test_guardian_unreachable_fail_open_default_is_audit(self) -> None:
        """§6.4 spec default: fail-open with audit event."""
        rc, out, err = self._run("preToolUse",
            {"session_id": "cur-11", "tool_name": "Read",
             "tool_input": {"file_path": "/tmp/x"}},
            env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead",
                           **self._negotiated("http://127.0.0.1:1/dead", coerce_uuid("cur-11", namespace_prefix="cursor"))},
        )
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out), {"permission": "allow"},
            "a decided proceed answers in Cursor's allow shape; failClosed reads an empty reply as a failed hook")
        self.assertIn("ACS_AUDIT", err, "fail-open MUST emit an audit event per §6.4")
        self.assertIn("fail_open_bypass", err)

    def test_before_submit_prompt_block_with_readable_message(self) -> None:
        rc, out, err = self._run("beforeSubmitPrompt",
            {"session_id": "cur-12", "prompt": "anything"},
            env_overrides={"ACS_GUARDIAN_URL": "http://127.0.0.1:1/dead",
                           "ACS_DEFAULT_DENY": "1",
                           **self._negotiated("http://127.0.0.1:1/dead", coerce_uuid("cur-12", namespace_prefix="cursor"))},
        )
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out), {"continue": False,
                                           "user_message": "ACS adapter: prompt blocked (transport_failure)"})
        self.assertIn("prompt blocked", err.lower())
        self.assertIn("ACS_AUDIT", err)
        self.assertIn("transport_failure", err,
            "audit event must carry cause=transport_failure when Guardian unreachable")


if __name__ == "__main__":
    unittest.main(verbosity=2)
