from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from acs.integrations import _duplicates
from acs.integrations._duplicates import claude_code_plugins, hook_files, wired_copies
from acs.integrations.claude_code import wire as claude_wire
from acs.integrations.cursor import wire as cursor_wire

# The wire tools refuse to wire without a secret and its label (§10).
SECRET_ARGS = ["--secret-env-inline=" + "0" * 64, "--key-id=test-key"]


def _claude_hook(command: str) -> dict:
    return {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": command}]}]}}


def _cursor_hook(command: str) -> dict:
    return {"version": 1, "hooks": {"preToolUse": [{"command": command}]}}


class _WireTest(unittest.TestCase):
    MODULE: object = None
    SCRIPT = ""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.home, self.project, self.managed = root / "home", root / "project", root / "managed"
        self.enterprise = root / "enterprise" / "hooks.json"
        self.home.mkdir()
        self.project.mkdir()
        self.hook = root / "bin" / self.SCRIPT
        self.hook.parent.mkdir()
        self.hook.write_text("#!/bin/sh\n")
        self.hook.chmod(self.hook.stat().st_mode | stat.S_IXUSR)
        for patcher in (mock.patch.object(_duplicates, "CLAUDE_CODE_MANAGED_DIRS", (self.managed,)),
                        mock.patch.object(_duplicates, "CURSOR_ENTERPRISE_FILES", (self.enterprise,))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _write(self, path: Path, config: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(config))

    def _wire(self, settings: Path, *extra: str, cwd: Path | None = None) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.chdir(cwd or self.project), mock.patch.dict(os.environ, {"HOME": str(self.home)}), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            try:
                rc = self.MODULE.main(["--guardian-url=http://127.0.0.1:8787/acs", f"--settings={settings}",
                                       f"--hook-command={self.hook}", "--write", *SECRET_ARGS, *extra])
            except SystemExit as e:
                rc = int(e.code or 0)
        return rc, err.getvalue()

    def _assert_refused(self, settings: Path, where: Path, *extra: str, cwd: Path | None = None) -> str:
        rc, err = self._wire(settings, *extra, cwd=cwd)
        self.assertEqual(rc, 1, err)
        self.assertIn(str(where.resolve()), err)
        self.assertFalse(settings.exists(), "nothing is written when a copy exists")
        return err


class ClaudeCodeDuplicates(_WireTest):
    MODULE = claude_wire
    SCRIPT = "acs-claude-code-hook"

    def setUp(self) -> None:
        super().setUp()
        self.user = self.home / ".claude" / "settings.json"
        self.shared = self.project / ".claude" / "settings.json"
        self.local = self.project / ".claude" / "settings.local.json"

    def _install(self, plugin_id: str = "acs@test", *, scope: str = "user", project: Path | None = None,
                 manifest: dict | None = None, hooks_file: bool = True) -> Path:
        name, marketplace = plugin_id.split("@")
        root = self.home / ".claude" / "plugins" / "cache" / marketplace / name / "1.0.0"
        if hooks_file:
            self._write(root / "hooks" / "hooks.json", _claude_hook("${CLAUDE_PLUGIN_ROOT}/bin/acs-claude-code-hook"))
        if manifest is not None:
            self._write(root / ".claude-plugin" / "plugin.json", {"name": name, **manifest})
        record = self.home / ".claude" / "plugins" / "installed_plugins.json"
        install = {"scope": scope, "installPath": str(root), "version": "1.0.0"}
        if project is not None:
            install["projectPath"] = str(project)
        self._write(record, {"version": 2, "plugins": {plugin_id: [install]}})
        return root

    def _enable(self, path: Path, on: bool) -> None:
        config = json.loads(path.read_text()) if path.exists() else {}
        self._write(path, {**config, "enabledPlugins": {"acs@test": on}})

    def test_a_copy_in_user_local_or_managed_settings_refuses(self) -> None:
        for existing, target in ((self.user, self.shared), (self.local, self.user),
                                 (self.managed / "managed-settings.d" / "10-acs.json", self.shared)):
            with self.subTest(existing.name):
                self._write(existing, _claude_hook("python3 /opt/acs/src/acs/integrations/claude_code/adapter.py"))
                err = self._assert_refused(target, existing)
                self.assertIn(f"{existing.resolve()}: PreToolUse", err)
                existing.unlink()

    def test_a_copy_beside_a_target_in_another_project_refuses(self) -> None:
        other = self.home / "other-project" / ".claude"
        self._write(other / "settings.local.json", _claude_hook("acs-claude-code-hook"))
        self._assert_refused(other / "settings.json", other / "settings.local.json")

    def test_an_enabled_installed_plugin_refuses(self) -> None:
        root = self._install()
        err = self._assert_refused(self.shared, root / "hooks" / "hooks.json")
        self.assertIn("(plugin acs@test): PreToolUse", err)

    def test_enabled_plugins_decide_per_scope_with_the_highest_winning(self) -> None:
        self._install()
        self._enable(self.user, False)
        self.assertEqual(self._wire(self.shared)[0], 0, "a plugin the user turned off does not load")
        self.shared.unlink()
        self._write(self.shared, {"enabledPlugins": {"acs@test": True}})
        self.assertEqual(self._wire(self.local)[0], 1, "project settings override user settings")
        self._enable(self.local, False)
        self.assertEqual(self._wire(self.user)[0], 0, "local settings override project settings")
        self._write(self.managed / "managed-settings.json", {"enabledPlugins": {"acs@test": True}})
        self.assertEqual(self._wire(self.user)[0], 1, "managed settings override local settings")

    def test_a_plugin_follows_its_default_when_no_scope_sets_it(self) -> None:
        self._install(manifest={"defaultEnabled": False})
        self.assertEqual(self._wire(self.shared)[0], 0)
        self.shared.unlink()
        self._enable(self.user, True)
        self.assertEqual(self._wire(self.shared)[0], 1)

    def test_hooks_declared_in_the_manifest_count(self) -> None:
        inline = _claude_hook("acs-claude-code-hook")["hooks"]
        for name, manifest, where in (("path", {"hooks": "./config/extra.json"}, "config/extra.json"),
                                      ("inline", {"hooks": [inline]}, ".claude-plugin/plugin.json")):
            with self.subTest(name):
                root = self._install(manifest=manifest, hooks_file=False)
                if name == "path":
                    self._write(root / "config" / "extra.json", _claude_hook("acs-claude-code-hook"))
                self._assert_refused(self.shared, root / where)

    def test_every_inline_hook_group_in_the_manifest_is_scanned(self) -> None:
        unrelated = _claude_hook("/usr/bin/my-linter")["hooks"]
        acs = {"PostToolUse": _claude_hook("acs-claude-code-hook")["hooks"]["PreToolUse"]}
        root = self._install(manifest={"hooks": [unrelated, acs]}, hooks_file=False)
        err = self._assert_refused(self.shared, root / ".claude-plugin" / "plugin.json")
        self.assertIn("hooks[1] (plugin acs@test): PostToolUse", err)

    def test_plugin_enablement_follows_the_target_project_from_any_directory(self) -> None:
        other = self.home / "other-project"
        root = self._install()
        self._write(other / ".claude" / "settings.json", {"enabledPlugins": {"acs@test": True}})
        self._enable(self.local, False)
        for cwd in (other, self.project):
            with self.subTest(cwd=cwd.name):
                self._assert_refused(other / ".claude" / "settings.local.json", root / "hooks" / "hooks.json", cwd=cwd)

    def test_each_project_resolves_its_own_enabled_plugins(self) -> None:
        root = self._install()
        other = self.home / "other-project"
        self._write(other / ".claude" / "settings.json", {"enabledPlugins": {"acs@test": True}})
        self._enable(self.local, False)
        projects = [self.project.resolve(), other.resolve()]
        self.assertEqual([where for where, _ in claude_code_plugins(home=self.home, projects=projects)],
                         [f"{(root / 'hooks' / 'hooks.json').resolve()} (plugin acs@test)"])
        self.assertEqual(list(claude_code_plugins(home=self.home, projects=projects[:1])), [])
        self._enable(self.local, True)
        self.assertEqual(len(list(claude_code_plugins(home=self.home, projects=projects))), 1,
                         "a plugin both projects enable is scanned once")

    def test_a_copy_in_another_project_does_not_block_this_one(self) -> None:
        self._write(self.shared, _claude_hook("acs-claude-code-hook"))
        other = self.home / "other-project" / ".claude" / "settings.json"
        self.assertEqual(self._wire(other)[0], 0, "sessions in the other project never load this project's settings")

    def test_plugins_that_do_not_load_here_are_ignored(self) -> None:
        clone = self.home / ".claude" / "plugins" / "marketplaces" / "test" / "plugins" / "acs" / "hooks" / "hooks.json"
        self._write(clone, _claude_hook("acs-claude-code-hook"))
        self.assertEqual(self._wire(self.shared)[0], 0, "a marketplace catalog copy is not installed")
        self.shared.unlink()
        self._install(scope="project", project=self.home / "elsewhere")
        self.assertEqual(self._wire(self.shared)[0], 0, "a project install loads only in its project")
        self.shared.unlink()
        root = self._install(scope="project", project=self.project)
        self._assert_refused(self.shared, root / "hooks" / "hooks.json")

    def test_a_cursor_copy_refuses_a_file_cursor_imports_unless_the_import_is_off(self) -> None:
        cursor = self.project / ".cursor" / "hooks.json"
        self._write(cursor, _cursor_hook("acs-cursor-hook preToolUse"))
        for target in (self.user, self.shared, self.local):
            with self.subTest(target.name):
                err = self._assert_refused(target, cursor)
                self.assertIn("--cursor-third-party-imports-off", err)
        other = self.project / "other-settings.json"
        self.assertEqual(self._wire(other)[0], 0, "Cursor does not import other files")
        other.unlink()
        self.assertEqual(self._wire(self.shared, "--cursor-third-party-imports-off")[0], 0)

    def test_rewiring_the_same_file_and_unrelated_hooks_are_allowed(self) -> None:
        self._write(self.shared, _claude_hook("/usr/bin/my-linter"))
        self.assertEqual(self._wire(self.user)[0], 0)
        self.assertEqual(self._wire(self.user)[0], 0, "wiring the file that holds the copy replaces it")

    def test_unwiring_ignores_copies_elsewhere(self) -> None:
        self._write(self.user, _claude_hook("acs-claude-code-hook"))
        self.assertEqual(self._wire(self.shared, "--unwire")[0], 0)


class CursorDuplicates(_WireTest):
    MODULE = cursor_wire
    SCRIPT = "acs-cursor-hook"

    def test_a_copy_in_another_hooks_json_refuses(self) -> None:
        user, project = self.home / ".cursor" / "hooks.json", self.project / ".cursor" / "hooks.json"
        for existing, target in ((user, project), (project, user), (self.enterprise, user)):
            with self.subTest(existing=str(existing)):
                self._write(existing, _cursor_hook("/usr/local/bin/acs-cursor-hook preToolUse"))
                err = self._assert_refused(target, existing)
                self.assertIn(f"{existing.resolve()}: preToolUse", err)
                existing.unlink()

    def test_an_imported_claude_code_copy_refuses_unless_the_import_is_off(self) -> None:
        target = self.project / ".cursor" / "hooks.json"
        for existing in (self.project / ".claude" / "settings.json", self.project / ".claude" / "settings.local.json",
                         self.home / ".claude" / "settings.json"):
            with self.subTest(existing.name):
                self._write(existing, _claude_hook("/usr/local/bin/acs-claude-code-hook"))
                err = self._assert_refused(target, existing)
                self.assertIn("--cursor-third-party-imports-off", err)
                self.assertEqual(self._wire(target, "--cursor-third-party-imports-off")[0], 0)
                target.unlink()
                existing.unlink()

    def test_rewiring_the_same_file_is_allowed(self) -> None:
        user = self.home / ".cursor" / "hooks.json"
        self.assertEqual(self._wire(user)[0], 0)
        self.assertEqual(self._wire(user)[0], 0)


class CopyScanner(unittest.TestCase):
    def test_unreadable_and_deeply_nested_files_hold_no_copy(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            broken, deep = Path(d) / "broken.json", Path(d) / "deep.json"
            broken.write_text("{")
            deep.write_text('{"hooks": {"x": ' + "[" * 5000 + "]" * 5000 + "}}")
            files = [broken, deep, Path(d) / "absent.json"]
            self.assertEqual(wired_copies(hook_files(files, target=Path(d) / "t.json")), [])


if __name__ == "__main__":
    unittest.main()
