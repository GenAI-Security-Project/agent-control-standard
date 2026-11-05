#!/usr/bin/env python3
"""
Wire (or unwire) the Cursor ACS adapter into a hooks.json.

Operator-driven by design: you supply the deployment-specific values
(Guardian URL, secret file location), this tool computes the exact
hooks entries and either prints them (dry-run, the default) or writes
them with a timestamped backup of the original file.

Default mode is dry-run — nothing on disk changes until you pass
`--write`. The dry-run output includes a unified diff of what would
change, so you see the exact edit before approving it.

Cursor reads from two locations (Cursor docs):
  - `<project>/.cursor/hooks.json` — project-level (per-workspace)
  - `~/.cursor/hooks.json` — user-level (global)

When both exist, Cursor's project-level entries take precedence.
This CLI defaults to the user-level path; pass --settings for project-
level wiring.

Examples
========

# 1. Preview what would be wired into ~/.cursor/hooks.json
acs-cursor-wire \\
  --guardian-url=http://127.0.0.1:8787/acs \\
  --secret-file=~/.acs/hmac.key

# 2. Same, but actually write (with backup at ~/.cursor/hooks.json.bak.<ts>)
acs-cursor-wire \\
  --guardian-url=http://127.0.0.1:8787/acs \\
  --secret-file=~/.acs/hmac.key \\
  --write

# 3. Project-level wiring
acs-cursor-wire \\
  --guardian-url=http://127.0.0.1:8787/acs \\
  --secret-file=~/.acs/hmac.key \\
  --settings=./.cursor/hooks.json \\
  --write

# 4. Subset of hooks
acs-cursor-wire \\
  --guardian-url=http://127.0.0.1:8787/acs \\
  --secret-file=~/.acs/hmac.key \\
  --hooks=preToolUse,postToolUse

# 5. Remove ACS wiring (preserves any other hooks you have)
acs-cursor-wire --unwire --write

What this tool does NOT do
==========================

  - Generate the HMAC secret. Run:
      openssl rand -hex 32 > ~/.acs/hmac.key && chmod 600 ~/.acs/hmac.key
  - Start the Guardian. Run it yourself.
  - Validate that the Guardian is reachable.
  - Choose any of the deployment-specific values. All explicit flags.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import shlex
import stat
import sys
from pathlib import Path
from typing import Any

from acs.integrations._duplicates import (
    cursor_hooks,
    cursor_imported_settings,
    hook_files,
    project_roots,
    refuse,
    wired_copies,
)
from acs.integrations._hook_command import resolve_hook_command
from acs.integrations._settings_file import write_atomically


HOOK_SCRIPT = "acs-cursor-hook"

# ACS-Core's six unconditional hooks in Cursor's names, plus postToolUseFailure and stop.
CURRENT_CORE_HOOKS = [
    "sessionStart",
    "beforeSubmitPrompt",
    "preToolUse",
    "postToolUse",
    "postToolUseFailure",
    "afterAgentResponse",
    "stop",
    "sessionEnd",
]

# ACS-Core requires subagentStart of a subagent-capable client.
SUBAGENT_HOOKS = [
    "subagentStart",
]
DEFAULT_HOOKS = CURRENT_CORE_HOOKS + SUBAGENT_HOOKS

# Gate hooks get Cursor's failClosed for a crashed hook and ACS_DEFAULT_DENY=1, so an ACS_DEFAULT_DENY=0 inherited from the environment leaves them closed.
GATE_HOOKS = frozenset({
    "preToolUse", "beforeSubmitPrompt",
    "beforeShellExecution", "beforeMCPExecution", "subagentStart",
})

# Embedded in the command, so a wired entry is recognized without parsing it.
WIRE_MARKER = "# acs-adapter-wired"


def wired_elsewhere(target: Path, *, home: Path, cwd: Path, cursor_imports: bool) -> tuple[list[str], list[str]]:
    """Adapter copies in the hooks.json files Cursor loads besides target, and in the Claude Code
    settings Cursor's third-party import runs."""
    projects = project_roots(target, home=home, cwd=cwd)
    copies = wired_copies(hook_files(cursor_hooks(home=home, projects=projects), target=target))
    imported = (wired_copies(hook_files(cursor_imported_settings(home=home, projects=projects), target=target))
                if cursor_imports else [])
    return copies, imported


def build_command(*, hook_command: str, event_name: str,
                   guardian_url: str,
                   secret_file: str | None,
                   secret_env: str | None,
                   key_id: str | None = None,
                   default_deny: bool,
                   host_allowlist: str | None,
                   fail_open: bool = False,
                   audit_file: str | None = None) -> str:
    env_pairs: list[str] = [f"ACS_GUARDIAN_URL={shlex.quote(guardian_url)}"]
    if secret_file:
        env_pairs.append(f"ACS_HMAC_SECRET_FILE={shlex.quote(str(_expand(secret_file)))}")
    elif secret_env:
        env_pairs.append(f"ACS_HMAC_SECRET={shlex.quote(secret_env)}")
    if key_id:
        env_pairs.append(f"ACS_HMAC_KEY_ID={shlex.quote(key_id)}")
    if default_deny:
        env_pairs.append("ACS_DEFAULT_DENY=1")
    elif fail_open:
        env_pairs += ["ACS_DEFAULT_DENY=0", "ACS_STARTUP_POSTURE=proceed"]
    if host_allowlist:
        env_pairs.append(f"ACS_GUARDIAN_HOST_ALLOWLIST={shlex.quote(host_allowlist)}")
    if audit_file:
        # A durable audit sink: hook stderr is not kept by Cursor.
        env_pairs.append(f"ACS_AUDIT_FILE={shlex.quote(str(_expand(audit_file)))}")
    env_prefix = " ".join(env_pairs)
    return f"{env_prefix} {shlex.quote(hook_command)} {event_name} {WIRE_MARKER}"


# sessionEnd runs under the per-script timeout, whose default Cursor leaves to the platform (hooks docs, Per-Script
# Configuration Options); 15 s covers a handshake, a sessionStart and the sessionEnd at the default 5 s each.
SESSION_END_TIMEOUT_S = 15


def hook_timeout(hook: str) -> int | None:
    return SESSION_END_TIMEOUT_S if hook == "sessionEnd" else None


def build_hook_entry(command: str, *, fail_closed: bool, timeout: int | None = None) -> dict:
    entry: dict = {"command": command}
    if timeout is not None:
        entry["timeout"] = timeout
    if fail_closed:
        entry["failClosed"] = True
    return entry


def load_settings(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise SystemExit(f"FATAL: {path} is not valid JSON ({e}). Fix or remove first.")


def merge_wire(existing: dict, hook_names: list[str],
                entries_by_hook: dict[str, dict]) -> dict:
    """A copy of hooks.json with ACS wired in; only our entries are replaced, so the user's entries for the same event stay."""
    out = json.loads(json.dumps(existing))  # deep copy
    out.setdefault("version", 1)
    hooks = out.setdefault("hooks", {})
    for name in hook_names:
        entry = entries_by_hook[name]
        existing_list = hooks.get(name, [])
        kept = [e for e in existing_list
                if WIRE_MARKER not in (e.get("command") or "")]
        kept.append(entry)
        hooks[name] = kept
    return out


def merge_unwire(existing: dict, hook_names: list[str]) -> dict:
    """A copy of hooks.json without ACS's entries; an event or hooks dict left empty is removed."""
    out = json.loads(json.dumps(existing))
    hooks = out.get("hooks", {})
    for name in list(hooks.keys()):
        if name not in hook_names:
            continue
        entries = hooks.get(name) or []
        kept = [e for e in entries
                if WIRE_MARKER not in (e.get("command") or "")]
        if kept:
            hooks[name] = kept
        else:
            hooks.pop(name, None)
    if not hooks:
        out.pop("hooks", None)
    return out


def render(settings: dict) -> str:
    return json.dumps(settings, indent=2, sort_keys=False) + "\n"


def render_diff(before: dict, after: dict, label: str) -> str:
    a = render(before).splitlines(keepends=True)
    b = render(after).splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b,
                                          fromfile=f"{label} (current)",
                                          tofile=f"{label} (proposed)",
                                          n=3))


def _expand(p: str) -> Path:
    # Absolute at wiring time: the hook runs in whatever directory the host gives it.
    return Path(os.path.abspath(os.path.expanduser(p)))


def validate_inputs(args: argparse.Namespace) -> list[str]:
    """Warnings for the operator; none of them stops the run."""
    warnings: list[str] = []

    if not args.unwire:
        if args.secret_file:
            sf = _expand(args.secret_file)
            if sf.exists():
                mode = stat.S_IMODE(sf.stat().st_mode)
                if mode & 0o077:
                    warnings.append(
                        f"WARNING: {sf} is mode {oct(mode)} — the adapter "
                        f"will refuse to read it. Run: chmod 600 {sf}")
            else:
                warnings.append(
                    f"NOTE: secret file {sf} doesn't exist yet. Create with: "
                    f"openssl rand -hex 32 > {sf} && chmod 600 {sf}")
        elif args.secret_env_inline:
            warnings.append(
                "WARNING: --secret-env-inline embeds the secret directly in "
                "hooks.json (visible in `ps aux`). For production, prefer "
                "--secret-file with a 0600 key file.")

        if not args.guardian_url.startswith(("http://", "https://")):
            warnings.append(
                "WARNING: Guardian URL must start with http:// or https://. "
                "The adapter's URL allowlist will reject any other scheme.")

        if args.guardian_url.startswith("http://") and not (
            args.guardian_url.startswith("http://127.")
            or args.guardian_url.startswith("http://localhost")
        ):
            warnings.append(
                "WARNING: plaintext HTTP to a non-loopback Guardian. The "
                "envelope is HMAC-signed (so unmodifiable) but the payload "
                "is readable on the wire. Use https:// for production.")

        missing = set(CURRENT_CORE_HOOKS) - set(args.hooks)
        if missing:
            warnings.append(
                f"NOTE: wiring a SUBSET of ACS-Core's minimum hooks. "
                f"Missing: {sorted(missing)}. ACS-Core conformance requires "
                f"all {len(CURRENT_CORE_HOOKS)} "
                f"({', '.join(CURRENT_CORE_HOOKS)}).")
        if "subagentStart" not in args.hooks:
            warnings.append(
                "NOTE: subagentStart is not wired. ACS-Core requires it "
                "of subagent-capable clients, and Cursor exposes that "
                "boundary.")

    return warnings


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Wire (or unwire) the Cursor ACS adapter into hooks.json.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples\n========")[1] if "Examples\n========" in __doc__ else "",
    )
    p.add_argument("--guardian-url",
                    help="Guardian endpoint (http:// or https://). Required unless --unwire.")
    p.add_argument("--secret-file",
                    help="Path to the HMAC secret file (preferred). The adapter reads it lazily.")
    p.add_argument("--key-id", metavar="LABEL",
                    help="The label that names the secret (§10), the same one the Guardian has; "
                         "required with --secret-file or --secret-env-inline.")
    p.add_argument("--secret-env-inline", metavar="HEX",
                    help="HMAC secret inlined into hooks.json env (visible in `ps aux`; "
                         "dev only). Use --secret-file for production.")
    p.add_argument("--settings",
                    default="~/.cursor/hooks.json",
                    help="Path to Cursor hooks.json (default: ~/.cursor/hooks.json — "
                         "user-level). Use ./.cursor/hooks.json for project-level.")
    p.add_argument("--hook-command", default=None,
                    help=f"Command the hooks run (default: the absolute path of the installed "
                         f"{HOOK_SCRIPT} console script).")
    p.add_argument("--hooks", default=",".join(DEFAULT_HOOKS),
                    help="Comma-separated hook names to wire (default: the ACS-Core minimum set, "
                         "postToolUseFailure, stop, and the subagentStart gate ACS-Core requires of a "
                         f"subagent-capable client: {','.join(DEFAULT_HOOKS)}).")
    posture_group = p.add_mutually_exclusive_group()
    posture_group.add_argument("--default-deny", action="store_true",
                    help="Write Cursor's failClosed and ACS_DEFAULT_DENY=1 (fail-CLOSED whatever the "
                         "Guardian declares) on EVERY wired hook. By default only the gate hooks "
                         f"({', '.join(sorted(GATE_HOOKS & set(DEFAULT_HOOKS)))}) carry them; the others "
                         "fail closed too unless their environment sets ACS_DEFAULT_DENY=0, and every hook "
                         "refuses its step in a session whose handshake got no answer.")
    posture_group.add_argument("--all-fail-open", action="store_true",
                    help="Write ACS_DEFAULT_DENY=0 and ACS_STARTUP_POSTURE=proceed on EVERY wired hook, "
                         "gates included: a step with no usable decision proceeds, audited, unless the "
                         "Guardian declares on_decision_failure: deny. NOT RECOMMENDED for production.")
    p.add_argument("--audit-file",
                    help="Durable ACS_AUDIT sink appended by every hook process "
                         "(created 0600). RECOMMENDED: without it, §6.4 audit "
                         "events land on hook stderr, which nothing collects.")
    p.add_argument("--host-allowlist", default=None,
                    help="Comma-separated hostnames the adapter will accept as Guardian URLs.")
    p.add_argument("--unwire", action="store_true",
                    help="Remove any ACS-wired hooks (preserves non-ACS entries).")
    p.add_argument("--cursor-third-party-imports-off", action="store_true",
                    help="Cursor's 'Include Third-Party Plugins, Skills, and Other Configs' setting is off, "
                         "so Cursor runs no Claude Code hooks; skip the copies only that import combines.")
    p.add_argument("--write", action="store_true",
                    help="Actually write the changes to hooks.json (with timestamped backup). "
                         "Without this flag, this tool only prints what it WOULD do.")

    args = p.parse_args(argv)

    if not args.unwire and not args.guardian_url:
        p.error("--guardian-url is required (unless --unwire)")
    if args.secret_file and args.secret_env_inline:
        p.error("provide --secret-file OR --secret-env-inline, not both")
    if not args.unwire and not (args.secret_file or args.secret_env_inline):
        p.error("a secret is required (--secret-file or --secret-env-inline): ACS-Core signs every request (§10)")
    if (args.secret_file or args.secret_env_inline) and not (args.key_id or "").strip():
        p.error("--key-id is required with a secret: it names the secret, and the Guardian must hold the same label")

    settings_path = _expand(args.settings)
    # A hook command that cannot run makes the host proceed with no audit record.
    hook_command = ""
    if not args.unwire:
        try:
            hook_command = resolve_hook_command(HOOK_SCRIPT, args.hook_command)
        except ValueError as e:
            p.error(str(e))
        if refuse(*wired_elsewhere(settings_path, home=Path.home(), cwd=Path.cwd(),
                                   cursor_imports=not args.cursor_third_party_imports_off)):
            return 1

    hook_names = [h.strip() for h in args.hooks.split(",") if h.strip()]
    args.hooks = hook_names  # for the warning function

    existing = load_settings(settings_path)
    if args.unwire:
        new = merge_unwire(
            existing,
            hook_names if args.hooks else DEFAULT_HOOKS + [
                "stop", "beforeShellExecution", "afterShellExecution",
                "beforeMCPExecution", "afterMCPExecution",
                "afterFileEdit", "afterTabFileEdit",
                "subagentStart", "preCompact",
                "postToolUseFailure", "afterAgentThought",
            ])
    else:
        # Gate hooks fail closed by default; --default-deny closes every hook and --all-fail-open opens every hook.
        entries_by_hook: dict[str, dict] = {}
        for hook in hook_names:
            if args.default_deny:
                hook_deny = True
            elif args.all_fail_open:
                hook_deny = False
            else:
                hook_deny = hook in GATE_HOOKS
            cmd = build_command(
                hook_command=hook_command,
                event_name=hook,
                guardian_url=args.guardian_url,
                secret_file=args.secret_file,
                secret_env=args.secret_env_inline,
                key_id=args.key_id,
                default_deny=hook_deny,
                fail_open=args.all_fail_open,
                host_allowlist=args.host_allowlist,
                audit_file=args.audit_file,
            )
            entries_by_hook[hook] = build_hook_entry(cmd, fail_closed=hook_deny, timeout=hook_timeout(hook))
        new = merge_wire(existing, hook_names, entries_by_hook)

    warnings = validate_inputs(args)
    for w in warnings:
        print(f"  ⚠ {w}", file=sys.stderr)
    if warnings:
        print(file=sys.stderr)

    if not args.unwire:
        print("Per-hook fail posture:")
        for hook in hook_names:
            if args.default_deny:
                posture = "fail-CLOSED (forced via --default-deny)"
            elif args.all_fail_open:
                posture = "fail-OPEN (forced via --all-fail-open)"
            elif hook in GATE_HOOKS:
                posture = "fail-CLOSED (gate hook default)"
            else:
                posture = "fail-CLOSED unless the environment sets ACS_DEFAULT_DENY=0"
            print(f"  {hook:22s} → {posture}")
        print()

    diff = render_diff(existing, new, label=str(settings_path))
    if not diff:
        print(f"No change — {settings_path} already in the desired state.")
        return 0

    print("=" * 70)
    print(f"Proposed change to {settings_path}")
    print("=" * 70)
    print(diff if diff else "(no diff)")
    print("=" * 70)

    if not args.write:
        print()
        print("Dry-run only. To apply, re-run with --write.")
        print("A timestamped backup of the original file will be created.")
        return 0

    backup = write_atomically(settings_path, render(new))
    print()
    print(f"✓ wrote {settings_path}")
    if backup:
        print(f"  backup at {backup}")
    if not args.unwire:
        print()
        print("Next steps:")
        print("  1. Make sure the Guardian is running and reachable at "
              f"{args.guardian_url}")
        print("  2. Restart Cursor — hooks.json is read at startup, not live")
        print("  3. Verify the wiring from a repository checkout:")
        print("       cd adapters && uv run python tests/integrations/cursor/e2e_check.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
