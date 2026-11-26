"""The help text and docs tell an operator how to make a secret file the one reader accepts (issue #576, round 4).

mkdir under the common umask 002 gives 0775, which the reader now accepts, but the help still creates ~/.acs owner-only
so a fresh setup starts from the tightest mode. Each adapter's troubleshooting table lists the real causes of
SecretFilePermissionsError, so an operator who meets one knows which rule tripped.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

from acs.integrations.claude_code import wire as claude_code_wire
from acs.integrations.cursor import wire as cursor_wire

ADAPTERS = Path(__file__).resolve().parents[2]
READMES = {name: ADAPTERS / "docs" / name / "README.md" for name in ("claude_code", "cursor", "nat")}
MKDIR = "mkdir -p -m 700 ~/.acs"


class SecretDirectoryHelp(unittest.TestCase):
    def test_the_wire_help_creates_an_owner_only_directory(self) -> None:
        for name, module in (("claude_code", claude_code_wire), ("cursor", cursor_wire)):
            with self.subTest(name):
                self.assertIn(MKDIR, module.__doc__)

    def test_the_readmes_create_an_owner_only_directory(self) -> None:
        for name, path in READMES.items():
            with self.subTest(name):
                text = path.read_text(encoding="utf-8")
                self.assertIn(MKDIR, text)
                self.assertNotRegex(text, r"mkdir -p ~/\.acs\b")


class TroubleshootingTables(unittest.TestCase):
    def test_each_table_lists_every_cause_of_a_permissions_error(self) -> None:
        for name, path in READMES.items():
            with self.subTest(name):
                rows = [line for line in path.read_text(encoding="utf-8").splitlines()
                        if line.startswith("|") and "SecretFilePermissionsError" in line]
                self.assertTrue(rows, "no SecretFilePermissionsError row")
                text = " ".join(rows)
                for cause in ("0600", "symlink", "regular file", "owned by", "world-writable"):
                    self.assertRegex(text, re.escape(cause), cause)


if __name__ == "__main__":
    unittest.main()
