from __future__ import annotations

import contextlib
import io
import json
import os
import shlex
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from acs.integrations._hook_command import resolve_hook_command
from acs.integrations.claude_code import wire as claude_wire
from acs.integrations.cursor import wire as cursor_wire


def _executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class ResolveHookCommand(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())

    def test_absolute_executable_override_is_kept(self) -> None:
        hook = _executable(self.tmp / "acs-claude-code-hook")
        self.assertEqual(resolve_hook_command("acs-claude-code-hook", str(hook)), str(hook))

    def test_relative_override_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "absolute path"):
            resolve_hook_command("acs-claude-code-hook", "bin/acs-claude-code-hook")

    def test_missing_override_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "not an executable file"):
            resolve_hook_command("acs-claude-code-hook", str(self.tmp / "absent"))

    def test_non_executable_override_is_refused(self) -> None:
        plain = self.tmp / "acs-claude-code-hook"
        plain.write_text("not executable")
        with self.assertRaisesRegex(ValueError, "not an executable file"):
            resolve_hook_command("acs-claude-code-hook", str(plain))

    def test_relative_path_entry_resolves_to_an_absolute_path(self) -> None:
        _executable(self.tmp / "bin" / "acs-claude-code-hook")
        cwd = os.getcwd()
        try:
            os.chdir(self.tmp)
            with mock.patch.dict(os.environ, {"PATH": "bin"}):
                resolved = resolve_hook_command("acs-claude-code-hook")
        finally:
            os.chdir(cwd)
        self.assertTrue(os.path.isabs(resolved), resolved)
        self.assertEqual(Path(resolved).resolve(), (self.tmp / "bin" / "acs-claude-code-hook").resolve())

    def test_command_missing_from_path_is_refused(self) -> None:
        with mock.patch.dict(os.environ, {"PATH": str(self.tmp)}):
            with self.assertRaisesRegex(ValueError, "not on PATH"):
                resolve_hook_command("acs-claude-code-hook")


class WireRefusesUnusableCommands(unittest.TestCase):
    CASES = (
        (claude_wire, "settings.json", "acs-claude-code-hook"),
        (cursor_wire, "hooks.json", "acs-cursor-hook"),
    )

    def _main(self, module, argv: list[str]) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                return module.main(argv)
            except SystemExit as e:
                return int(e.code or 0)

    def test_nonexistent_override_exits_without_writing(self) -> None:
        for module, name, _ in self.CASES:
            with self.subTest(wire=module.__name__), tempfile.TemporaryDirectory() as tmp:
                settings = Path(tmp) / name
                rc = self._main(module, ["--guardian-url=http://127.0.0.1:8787/acs",
                                         f"--settings={settings}", f"--hook-command={tmp}/absent", "--write"])
                self.assertEqual(rc, 2)
                self.assertFalse(settings.exists())

    def test_written_command_runs_the_resolved_path_even_with_spaces(self) -> None:
        for module, name, script in self.CASES:
            with self.subTest(wire=module.__name__), tempfile.TemporaryDirectory() as tmp:
                hook = _executable(Path(tmp) / "dir with space" / script)
                settings = Path(tmp) / name
                rc = self._main(module, ["--guardian-url=http://127.0.0.1:8787/acs",
                                         f"--settings={settings}", f"--hook-command={hook}", "--write"])
                self.assertEqual(rc, 0)
                commands = [h["command"] for h in _commands(json.loads(settings.read_text()))]
                self.assertTrue(commands)
                for command in commands:
                    self.assertIn(str(hook), shlex.split(command))


def _commands(config: dict) -> list[dict]:
    found: list[dict] = []
    for entries in config.get("hooks", {}).values():
        for entry in entries:
            found.extend(entry.get("hooks", [entry]))
    return [h for h in found if "command" in h]


if __name__ == "__main__":
    unittest.main()
