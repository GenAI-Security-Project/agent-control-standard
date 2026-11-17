from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

ADAPTER_SIGNATURES = (
    "acs-claude-code-hook", "acs-cursor-hook", "# acs-adapter-wired",
    "claude_code/adapter.py", "claude-code/acs_adapter.py", "claude_code.hook", "claude_code.adapter",
    "cursor/adapter.py", "cursor/acs_adapter.py", "cursor.hook", "cursor.adapter",
)

if os.name == "nt":
    CLAUDE_CODE_MANAGED_DIRS: tuple[Path, ...] = (Path("C:/Program Files/ClaudeCode"),)
    CURSOR_ENTERPRISE_FILES: tuple[Path, ...] = (Path("C:/ProgramData/Cursor/hooks.json"),)
else:
    CLAUDE_CODE_MANAGED_DIRS = (Path("/Library/Application Support/ClaudeCode"), Path("/etc/claude-code"))
    CURSOR_ENTERPRISE_FILES = (Path("/Library/Application Support/Cursor/hooks.json"), Path("/etc/cursor/hooks.json"))

REFUSAL = ("the ACS adapter is already wired in another file this host may load. Two copies send each "
           "event to the Guardian twice, and both requests for one tool call carry the same request_id, "
           "which §10.3 replay protection rejects. Unwire the copy listed below first, or wire that "
           "file instead:")
CURSOR_IMPORT = ("Cursor also runs the Claude Code hooks in ~/.claude/settings.json and in the project's "
                 ".claude/settings.json and .claude/settings.local.json while its 'Include Third-Party Plugins, "
                 "Skills, and Other Configs' setting is on, which is the default. In Cursor, these copies would "
                 "run alongside this one, each with its own request_ids:")
CURSOR_IMPORT_OFF = ("Unwire them first, or turn that setting off and rerun with "
                     "--cursor-third-party-imports-off.")

Source = tuple[str, Any]  # where hooks are configured, and the event map configured there


def project_roots(target: Path, *, home: Path, cwd: Path) -> list[Path]:
    """The project whose sessions load target: the one holding a project's .claude or .cursor file, else the working directory."""
    target = target.expanduser().resolve()
    if target.parent.name in (".claude", ".cursor") and target.parent.parent != home.expanduser().resolve():
        return [target.parent.parent]
    return [cwd.resolve()]


def claude_code_settings(*, home: Path, projects: Iterable[Path]) -> list[Path]:
    """User, project, local and managed Claude Code settings, lowest precedence first."""
    files = [home / ".claude" / "settings.json"]
    files += [project / ".claude" / "settings.json" for project in projects]
    files += [project / ".claude" / "settings.local.json" for project in projects]
    for directory in CLAUDE_CODE_MANAGED_DIRS:
        files += [directory / "managed-settings.json", *sorted((directory / "managed-settings.d").glob("*.json"))]
    return files


def cursor_imported_settings(*, home: Path, projects: Iterable[Path]) -> list[Path]:
    """The Claude Code settings files whose hooks Cursor's third-party import runs."""
    return [home / ".claude" / "settings.json",
            *(project / ".claude" / name for project in projects for name in ("settings.json", "settings.local.json"))]


def cursor_hooks(*, home: Path, projects: Iterable[Path]) -> list[Path]:
    return [*CURSOR_ENTERPRISE_FILES, *(project / ".cursor" / "hooks.json" for project in projects),
            home / ".cursor" / "hooks.json"]


def hook_files(files: Iterable[Path], *, target: Path) -> Iterator[Source]:
    seen = {target.expanduser().resolve()}
    for path in files:
        resolved = path.expanduser().resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        config = _read_json(resolved)
        if isinstance(config, dict):
            yield str(resolved), config.get("hooks")


def claude_code_plugins(*, home: Path, projects: list[Path]) -> Iterator[Source]:
    """The hooks of each installed plugin a project enables: its highest-scope setting wins, else the manifest's defaultEnabled, true by default."""
    record = _read_json(home / ".claude" / "plugins" / "installed_plugins.json")
    installed = record.get("plugins") if isinstance(record, dict) else None
    if not isinstance(installed, dict):
        return
    scanned: set[Path] = set()
    for project in projects:
        enabled: dict[str, bool] = {}
        for path in claude_code_settings(home=home, projects=[project]):
            config = _read_json(path)
            plugins = config.get("enabledPlugins") if isinstance(config, dict) else None
            if isinstance(plugins, dict):
                enabled.update({name: on for name, on in plugins.items() if isinstance(on, bool)})
        for plugin_id, installs in installed.items():
            for install in installs if isinstance(installs, list) else []:
                path = install.get("installPath") if isinstance(install, dict) else None
                if not isinstance(path, str) or not _applies(install, project):
                    continue
                root = Path(path).expanduser().resolve()
                if root in scanned:
                    continue
                manifest = _read_json(root / ".claude-plugin" / "plugin.json")
                manifest = manifest if isinstance(manifest, dict) else {}
                if enabled.get(plugin_id, manifest.get("defaultEnabled") is not False):
                    scanned.add(root)
                    yield from _plugin_hooks(plugin_id, root, manifest)


def wired_copies(sources: Iterable[Source]) -> list[str]:
    """'<where>: <event>' for every hook event whose command runs an ACS adapter."""
    found: list[str] = []
    for where, hooks in sources:
        if not isinstance(hooks, dict):
            continue
        for event, entries in hooks.items():
            try:
                if any(sig in command for command in _commands(entries) for sig in ADAPTER_SIGNATURES):
                    found.append(f"{where}: {event}")
            except RecursionError:
                continue
    return found


def refuse(copies: list[str], imported: list[str]) -> bool:
    if copies:
        print(f"FATAL: {REFUSAL}", file=sys.stderr)
        for copy in copies:
            print(f"  {copy}", file=sys.stderr)
    if imported:
        print(f"FATAL: {CURSOR_IMPORT}", file=sys.stderr)
        for copy in imported:
            print(f"  {copy}", file=sys.stderr)
        print(CURSOR_IMPORT_OFF, file=sys.stderr)
    return bool(copies or imported)


def _applies(install: dict, project: Path) -> bool:
    """A project or local install applies only in its own project."""
    if install.get("scope") not in ("project", "local"):
        return True
    path = install.get("projectPath")
    return isinstance(path, str) and Path(path).expanduser().resolve() == project


def _plugin_hooks(plugin_id: str, root: Path, manifest: dict) -> Iterator[Source]:
    """hooks/hooks.json and the manifest's hooks: files that wrap the event map in "hooks", or inline event maps."""
    declared = manifest.get("hooks")
    entries = declared if isinstance(declared, list) else [declared]
    files = [root / "hooks" / "hooks.json", *(root / entry for entry in entries if isinstance(entry, str))]
    for path in dict.fromkeys(file.resolve() for file in files):
        config = _read_json(path)
        if isinstance(config, dict):
            yield f"{path} (plugin {plugin_id})", config.get("hooks")
    for index, entry in enumerate(entries):
        if isinstance(entry, dict):
            where = root / ".claude-plugin" / "plugin.json"
            yield f"{where}{f' hooks[{index}]' if isinstance(declared, list) else ''} (plugin {plugin_id})", entry


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except Exception:  # noqa: BLE001
        # A missing, unreadable, unparseable or too deeply nested file configures nothing.
        return None


def _commands(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "command" and isinstance(item, str):
                yield item
            else:
                yield from _commands(item)
    elif isinstance(value, list):
        for item in value:
            yield from _commands(item)
