"""
Live integration test for Cursor.

Cursor is a desktop application with no documented headless mode, so the
live test cannot run in CI. The manual reproduction procedure is in
`live_verification.md` in this directory.

This file is intentionally skipped in automated test runs. It exists to
keep the file naming identical across all three adapters
(`test_live.py`), and to serve as a pointer to the manual procedure.
"""
from __future__ import annotations

import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
VERIFICATION_DOC = HERE / "live_verification.md"


class LiveCursorPlaceholder(unittest.TestCase):
    @unittest.skip("Cursor live verification is a manual procedure; see live_verification.md")
    def test_run_manual_procedure(self) -> None:
        """Open Cursor on a project with the example hooks.json.

        See `tests/live_verification.md` for the full procedure.

        Verifies:
          - The example Guardian receives sessionStart, beforeSubmitPrompt,
            preToolUse, postToolUse, beforeShellExecution, afterShellExecution
            events when a benign agent prompt triggers tool use.
          - The agent's tool calls are gated by the Guardian's policy.
          - Adapter writes zero errors to its stderr log.
        """
        self.assertTrue(VERIFICATION_DOC.exists(),
                        f"live verification doc missing: {VERIFICATION_DOC}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
