from __future__ import annotations

import contextlib
import io
import json
import os
import shlex
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from acs.integrations._hook_command import resolve_hook_command
from acs.integrations.claude_code import wire as claude_wire
from acs.integrations.cursor import wire as cursor_wire

# The wire tools refuse to wire without a secret and its label (§10).
SECRET_ARGS = ["--secret-env-inline=" + "0" * 64, "--key-id=test-key"]


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
        # A home and working directory of its own, so no hook file on this machine counts as a second copy.
        with tempfile.TemporaryDirectory() as home, contextlib.chdir(home), \
                mock.patch.dict(os.environ, {"HOME": home}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                return module.main(argv)
            except SystemExit as e:
                return int(e.code or 0)

    def test_nonexistent_override_exits_without_writing(self) -> None:
        for module, name, _ in self.CASES:
            with self.subTest(wire=module.__name__), tempfile.TemporaryDirectory() as tmp:
                settings = Path(tmp) / name
                rc = self._main(module, ["--guardian-url=http://127.0.0.1:8787/acs",
                                         f"--settings={settings}", f"--hook-command={tmp}/absent", "--write",
                                         *SECRET_ARGS])
                self.assertEqual(rc, 2)
                self.assertFalse(settings.exists())

    def test_written_command_runs_the_resolved_path_even_with_spaces(self) -> None:
        for module, name, script in self.CASES:
            with self.subTest(wire=module.__name__), tempfile.TemporaryDirectory() as tmp:
                hook = _executable(Path(tmp) / "dir with space" / script)
                settings = Path(tmp) / name
                rc = self._main(module, ["--guardian-url=http://127.0.0.1:8787/acs",
                                         f"--settings={settings}", f"--hook-command={hook}", "--write",
                                         *SECRET_ARGS])
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



class ClaudeCodeGateHooksBlockOnFailure(unittest.TestCase):
    """A fail-closed hook that crashes, times out or cannot start blocks its action too (onFailure, Claude Code v2.1.295+)."""

    def _wire(self, *mode: str) -> dict[str, set[str]]:
        with tempfile.TemporaryDirectory() as tmp, contextlib.chdir(tmp), mock.patch.dict(os.environ, {"HOME": tmp}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            hook = _executable(Path(tmp) / "acs-claude-code-hook")
            settings = Path(tmp) / "settings.json"
            claude_wire.main(["--guardian-url=http://127.0.0.1:8787/acs", f"--settings={settings}",
                              f"--hook-command={hook}", "--write", *SECRET_ARGS, *mode])
            hooks = json.loads(settings.read_text())["hooks"]
        return {"block": {name for name, entries in hooks.items() if entries[0]["hooks"][0].get("onFailure") == "block"},
                "all": set(hooks)}

    def test_each_wiring_mode_blocks_exactly_its_fail_closed_hooks(self) -> None:
        default = self._wire()
        self.assertEqual(default["block"], {"PreToolUse", "UserPromptSubmit"})
        strict = self._wire("--default-deny")
        self.assertEqual(strict["block"], strict["all"] - {"Stop"}, "Claude Code ignores onFailure on Stop")
        self.assertEqual(self._wire("--all-fail-open")["block"], set())


class WrittenCommandsAndFiles(unittest.TestCase):
    """A path with a space stays one argument, and the settings file keeps its link and mode."""

    CASES = ((claude_wire, "settings.json", "acs-claude-code-hook"), (cursor_wire, "hooks.json", "acs-cursor-hook"))

    def _wire(self, module, tmp: Path, settings: Path, *extra: str) -> None:
        with contextlib.chdir(tmp), mock.patch.dict(os.environ, {"HOME": str(tmp)}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            module.main(["--guardian-url=http://127.0.0.1:8787/acs", f"--settings={settings}", "--write", *extra])

    def test_a_secret_and_audit_path_with_spaces_reach_the_hook_whole(self) -> None:
        for module, name, script in self.CASES:
            with self.subTest(wire=module.__name__), tempfile.TemporaryDirectory() as d:
                tmp = Path(d)
                seen = tmp / "seen.json"
                hook = tmp / "bin dir" / script
                hook.parent.mkdir()
                hook.write_text(f"#!/bin/sh\nprintf '%s\\n%s\\n' \"$ACS_HMAC_SECRET_FILE\" \"$ACS_AUDIT_FILE\" > '{seen}'\n")
                hook.chmod(0o755)
                key = tmp / "My Keys" / "hmac.key"
                key.parent.mkdir()
                key.write_text("0" * 64)
                key.chmod(0o600)
                audit = tmp / "My Logs" / "audit.log"
                settings = tmp / name
                self._wire(module, tmp, settings, f"--hook-command={hook}", f"--secret-file={key}",
                           "--key-id=test-key", f"--audit-file={audit}")
                for command in (h["command"] for h in _commands(json.loads(settings.read_text()))):
                    p = subprocess.run(["sh", "-c", command], input="{}", capture_output=True, text=True, timeout=10)
                    self.assertEqual(p.returncode, 0, (command, p.stderr))
                    self.assertEqual(seen.read_text().splitlines(), [str(key), str(audit)])

    def test_a_symlinked_settings_file_keeps_its_link_and_mode(self) -> None:
        for module, name, script in self.CASES:
            with self.subTest(wire=module.__name__), tempfile.TemporaryDirectory() as d:
                tmp = Path(d)
                hook = _executable(tmp / script)
                real = tmp / "dotfiles" / name
                real.parent.mkdir()
                real.write_text("{}")
                real.chmod(0o600)
                link = tmp / name
                link.symlink_to(real)
                self._wire(module, tmp, link, f"--hook-command={hook}", *SECRET_ARGS)
                self.assertTrue(link.is_symlink(), "the wire tool replaced the symlink with a plain file")
                self.assertIn("acs-adapter-wired", real.read_text())
                self.assertEqual(stat.S_IMODE(real.stat().st_mode), 0o600, "the secret-bearing file lost its mode")

    def test_a_new_settings_file_is_private(self) -> None:
        for module, name, script in self.CASES:
            with self.subTest(wire=module.__name__), tempfile.TemporaryDirectory() as d:
                tmp = Path(d)
                settings = tmp / name
                self._wire(module, tmp, settings, f"--hook-command={_executable(tmp / script)}", *SECRET_ARGS)
                self.assertEqual(stat.S_IMODE(settings.stat().st_mode), 0o600)

if __name__ == "__main__":
    unittest.main()
