"""Cursor has no headless mode, so its live check is the manual procedure in live_verification.md."""
from __future__ import annotations

import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
VERIFICATION_DOC = HERE.parents[2] / "docs" / "cursor" / "live_verification.md"


class LiveCursorPlaceholder(unittest.TestCase):
    @unittest.skip("Cursor live verification is a manual procedure; see live_verification.md")
    def test_run_manual_procedure(self) -> None:
        self.assertTrue(VERIFICATION_DOC.exists(),
                        f"live verification doc missing: {VERIFICATION_DOC}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
