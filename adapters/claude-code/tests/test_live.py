"""
Live end-to-end test: real Claude Code -> ACS adapter -> Guardian.

Spawns `claude --print` in a subprocess against a project-level settings.json
that wires the adapter, exercises both ALLOW and DENY paths, asserts Claude
Code's observable output reflects the Guardian's verdict.

Requires:
  - `claude` CLI available on PATH (Claude Code installed)
  - Python 3.10+

Skipped automatically when `claude` is not on PATH.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ADAPTER_DIR = HERE.parent
ADAPTER = ADAPTER_DIR / "acs_adapter.py"


CLAUDE_AVAILABLE = shutil.which("claude") is not None


sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "_common"))
from test_harness import launch_guardian  # noqa: E402


@unittest.skipUnless(CLAUDE_AVAILABLE, "`claude` CLI not on PATH")
class LiveClaudeCodeRoundTrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workdir = tempfile.mkdtemp(prefix="acs-live-cc-")

        # Launch first: settings.json below needs the OS-assigned port
        # launch_guardian returns.
        env = os.environ.copy()
        env["ACS_DEV_MODE"] = "1"
        env.pop("ACS_HMAC_SECRET", None)
        env.pop("ACS_HMAC_SECRET_FILE", None)
        cls.guardian_proc, cls.port = launch_guardian(env=env)

        # Project-level settings.json wires the adapter into Claude Code's
        # PreToolUse hook. Using the project root .claude/ so we don't
        # touch the user's ~/.claude/settings.json.
        claude_dir = Path(cls.workdir) / ".claude"
        claude_dir.mkdir()
        settings = {
            "hooks": {
                "PreToolUse": [{
                    "matcher": "*",
                    "hooks": [{
                        "type": "command",
                        "command": (
                            f"ACS_GUARDIAN_URL=http://127.0.0.1:{cls.port}/acs "
                            f"python3 {ADAPTER}"
                        ),
                    }],
                }],
            }
        }
        (claude_dir / "settings.json").write_text(json.dumps(settings, indent=2))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.guardian_proc.terminate()
        try:
            cls.guardian_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            cls.guardian_proc.kill()
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def _claude(self, prompt: str, timeout: float = 120.0) -> tuple[int, str]:
        """Invoke `claude --print` from the test workdir, capture stdout."""
        proc = subprocess.run(
            ["claude", "--print", "--permission-mode", "acceptEdits", prompt],
            cwd=self.workdir,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout

    # ----- ALLOW path -----

    def test_benign_bash_runs(self) -> None:
        """Guardian's policy allows benign Bash; Claude Code runs it and
        the marker string appears in stdout."""
        marker = "ACS_LIVE_TEST_OK_MARKER"
        rc, stdout = self._claude(f"Run the shell command: echo {marker}")
        self.assertEqual(rc, 0, f"claude exited {rc}; stdout={stdout[:200]}")
        self.assertIn(marker, stdout,
                      f"benign command should have run; stdout={stdout[:300]}")

    # ----- DENY path -----

    def test_destructive_bash_blocked(self) -> None:
        """Guardian's destructive-Bash policy denies; Claude Code surfaces
        the block in its output. We test against a string the example
        Guardian's regex blocks (no actual destructive op is attempted
        because PreToolUse fires before execution)."""
        # The example_guardian DESTRUCTIVE_BASH pattern matches 'rm -rf /...'
        # PreToolUse fires BEFORE the command runs, so the Guardian sees
        # the proposed command and denies it; the command never executes.
        prompt = (
            "Use the Bash tool with this exact command: "
            "rm -rf /tmp/acs-nonexistent-live-test-target"
        )
        rc, stdout = self._claude(prompt)
        self.assertEqual(rc, 0)
        # Claude Code's response should reference the block / the Guardian
        lo = stdout.lower()
        self.assertTrue(
            "block" in lo or "denied" in lo or "policy" in lo
            or "destructive" in lo,
            f"deny should surface in Claude Code's response; stdout={stdout[:400]}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
