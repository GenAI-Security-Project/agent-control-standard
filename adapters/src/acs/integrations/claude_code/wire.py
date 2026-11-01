#!/usr/bin/env python3
"""
Wire (or unwire) the Claude Code ACS adapter into a settings.json.

Operator-driven by design: you supply the deployment-specific values
(Guardian URL, secret file location), this tool computes the exact
hooks entries and either prints them (dry-run, the default) or writes
them with a timestamped backup of the original file.

Default mode is dry-run — nothing on disk changes until you pass
`--write`. The dry-run output includes a unified diff of what would
change, so you see the exact edit before approving it.

Examples
========

# 1. Preview what would be wired into the user's ~/.claude/settings.json
#    (default dry-run; shows a diff against the current file).
acs-claude-code-wire \\
  --guardian-url=http://127.0.0.1:8787/acs \\
  --secret-file=~/.acs/hmac.key

# 2. Same, but actually write (with backup at ~/.claude/settings.json.bak.<ts>)
acs-claude-code-wire \\
  --guardian-url=http://127.0.0.1:8787/acs \\
  --secret-file=~/.acs/hmac.key \\
  --write

# 3. Project-level settings: point at a different file
acs-claude-code-wire \\
  --guardian-url=https://guardian.internal/acs \\
  --secret-file=/etc/acs/hmac.key \\
  --settings=./.claude/settings.json \\
  --write

# 4. Subset of hooks (default is the full mapped set (ACS_CORE_HOOKS))
acs-claude-code-wire \\
  --guardian-url=http://127.0.0.1:8787/acs \\
  --secret-file=~/.acs/hmac.key \\
  --hooks=PreToolUse,PostToolUse

# 5. Fail-closed posture (default is fail-open per §6.4)
acs-claude-code-wire \\
  --guardian-url=http://127.0.0.1:8787/acs \\
  --secret-file=~/.acs/hmac.key \\
  --default-deny

# 6. Remove ACS wiring (preserves any other hooks you have)
acs-claude-code-wire --unwire --settings=~/.claude/settings.json --write

What this tool does NOT do
==========================

  - Generate the HMAC secret. Run:
      openssl rand -hex 32 > ~/.acs/hmac.key && chmod 600 ~/.acs/hmac.key
  - Start the Guardian. Run it yourself in a terminal, launchd, systemd,
    Docker, whatever fits your deployment.
  - Validate that the Guardian is reachable. Test that with
    tests/integrations/claude_code/e2e_check.py after wiring.
  - Choose any of the deployment-specific values (URL, secret path,
    fail posture). All explicit flags — no hidden defaults.
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
    claude_code_plugins,
    claude_code_settings,
    cursor_hooks,
    cursor_imported_settings,
    hook_files,
    project_roots,
    refuse,
    wired_copies,
)
from acs.integrations._hook_command import resolve_hook_command
from acs.integrations._settings_file import write_atomically


HOOK_SCRIPT = "acs-claude-code-hook"

# ACS-Core minimum hook set per conformance.md:19, plus Stop
# (steps/turnEnd). SubagentStop is not wired: steps/subagentStop requires
# final_chain_hash, which Claude Code cannot supply (no chain); a separate
# schema PR proposes making it optional. --hooks wires a subset, warned.
ACS_CORE_HOOKS = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "SessionEnd",
    "Stop",
]

# Wired by an earlier version; wiring and unwiring both remove them.
RETIRED_HOOKS = ["Notification"]

# Hooks that gate an action fail closed by default; the others report what already happened, where §6.4's default is fail-open.
GATE_HOOKS = {"PreToolUse", "UserPromptSubmit"}

# A marker we embed in the command string so we can later detect "is
# this hook entry one we wired?" without parsing argument shapes.
WIRE_MARKER = "# acs-adapter-wired"


def wired_elsewhere(target: Path, *, home: Path, cwd: Path, cursor_imports: bool) -> tuple[list[str], list[str]]:
    """Adapter copies in the settings and enabled plugins Claude Code loads besides target, and in the
    Cursor hooks that run alongside target when Cursor imports it."""
    projects = project_roots(target, home=home, cwd=cwd)
    copies = wired_copies([*hook_files(claude_code_settings(home=home, projects=projects), target=target),
                           *claude_code_plugins(home=home, projects=projects)])
    imported_by_cursor = target.expanduser().resolve() in {
        path.resolve() for path in cursor_imported_settings(home=home, projects=projects)}
    imported = (wired_copies(hook_files(cursor_hooks(home=home, projects=projects), target=target))
                if cursor_imports and imported_by_cursor else [])
    return copies, imported


def build_command(*, hook_command: str, guardian_url: str,
                   secret_file: str | None,
                   secret_env: str | None,
                   key_id: str | None = None,
                   default_deny: bool,
                   host_allowlist: str | None,
                   audit_file: str | None = None) -> str:
    """The settings.json hook command, with absolute paths, since the hook's shell and working directory vary."""
    env_pairs: list[str] = [f"ACS_GUARDIAN_URL={shlex.quote(guardian_url)}"]
    if secret_file:
        # Resolve ~ and $VAR ahead of time — Python's open() doesn't
        # expand tildes and POSIX sh tilde-after-= is not guaranteed.
        env_pairs.append(f"ACS_HMAC_SECRET_FILE={shlex.quote(str(_expand(secret_file)))}")
    elif secret_env:
        env_pairs.append(f"ACS_HMAC_SECRET={shlex.quote(secret_env)}")
    if key_id:
        env_pairs.append(f"ACS_HMAC_KEY_ID={shlex.quote(key_id)}")
    if default_deny:
        env_pairs.append("ACS_DEFAULT_DENY=1")
    if host_allowlist:
        env_pairs.append(f"ACS_GUARDIAN_HOST_ALLOWLIST={shlex.quote(host_allowlist)}")
    if audit_file:
        env_pairs.append(f"ACS_AUDIT_FILE={shlex.quote(str(_expand(audit_file)))}")
    env_prefix = " ".join(env_pairs)
    return f"{env_prefix} {shlex.quote(hook_command)} {WIRE_MARKER}"


# Hooks on which Claude Code ignores onFailure: a failure there cannot block anything.
_ON_FAILURE_IGNORED = frozenset({"Stop", "SubagentStop"})


def build_inner_hook(command: str, *, block_on_failure: bool = False) -> dict:
    """One wired command hook; block_on_failure makes Claude Code block the action when the hook fails or times out (v2.1.295+)."""
    inner = {"type": "command", "command": command}
    if block_on_failure:
        inner["onFailure"] = "block"
    return inner


def build_hook_entry(command: str, *, block_on_failure: bool = False) -> dict:
    return {
        "matcher": "*",
        "hooks": [build_inner_hook(command, block_on_failure=block_on_failure)],
    }


# ──────────────────────────────────────────────────────────────────────
# settings.json merge
# ──────────────────────────────────────────────────────────────────────

def load_settings(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise SystemExit(f"FATAL: {path} is not valid JSON ({e}). Fix or remove first.")


def merge_wire(existing: dict, hook_names: list[str],
                commands_by_hook: dict[str, str], blocking: frozenset[str] = frozenset()) -> dict:
    """A copy of the settings with ACS wired in; only our inner hooks are replaced, so the user's hooks on the same matcher stay."""
    out = json.loads(json.dumps(existing))  # deep copy
    hooks = out.setdefault("hooks", {})
    for name in hook_names:
        command = commands_by_hook[name]
        entries = hooks.get(name, [])
        # Strip our inner hooks from any matching-* entries and append
        # ours. Non-matching entries left as-is.
        kept_entries: list[dict] = []
        matcher_star_seen = False
        for entry in entries:
            if entry.get("matcher", "*") == "*":
                matcher_star_seen = True
                inner = [h for h in entry.get("hooks", [])
                          if WIRE_MARKER not in h.get("command", "")]
                inner.append(build_inner_hook(command, block_on_failure=name in blocking))
                kept_entries.append({**entry, "hooks": inner})
            else:
                kept_entries.append(entry)
        if not matcher_star_seen:
            kept_entries.append(build_hook_entry(command, block_on_failure=name in blocking))
        hooks[name] = kept_entries
    return out


def merge_unwire(existing: dict, hook_names: list[str]) -> dict:
    """Strip ACS-wired INNER HOOKS from the given hook types.

    Operates at the inner-hooks level so a user's own hook commands
    sharing the same entry / matcher are preserved. If an entry's
    inner-hooks list becomes empty after stripping ours, the entry
    is removed; if a hook type's entries list becomes empty, the hook
    type is removed.
    """
    out = json.loads(json.dumps(existing))
    hooks = out.get("hooks", {})
    for name in list(hooks.keys()):
        if name not in hook_names:
            continue
        entries = hooks.get(name) or []
        new_entries: list[dict] = []
        for entry in entries:
            kept_inner = [h for h in entry.get("hooks", [])
                          if WIRE_MARKER not in h.get("command", "")]
            if kept_inner:
                new_entries.append({**entry, "hooks": kept_inner})
            # else: entry had only our inner hook(s) — drop it
        if new_entries:
            hooks[name] = new_entries
        else:
            hooks.pop(name, None)
    if not hooks:
        out.pop("hooks", None)
    return out


# ──────────────────────────────────────────────────────────────────────
# Diff + atomic write
# ──────────────────────────────────────────────────────────────────────

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
    return Path(os.path.expanduser(os.path.expandvars(p)))


def validate_inputs(args: argparse.Namespace) -> list[str]:
    """Return a list of human-readable warnings for the operator. None
    of these block the operation — they're informational nudges."""
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
                "settings.json (visible in `ps aux`). For production, prefer "
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

        if set(args.hooks) - set(ACS_CORE_HOOKS):
            extras = set(args.hooks) - set(ACS_CORE_HOOKS)
            warnings.append(
                f"NOTE: wiring extra hooks not in the ACS-Core minimum: {sorted(extras)}")
        missing = set(ACS_CORE_HOOKS) - set(args.hooks)
        if missing:
            warnings.append(
                f"NOTE: wiring a SUBSET of the mapped ACS-Core hook set. "
                f"Missing: {sorted(missing)}. ACS-Core conformance requires "
                f"the full set ({', '.join(ACS_CORE_HOOKS)}).")

    return warnings


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Wire (or unwire) the Claude Code ACS adapter into settings.json.",
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
                    help="HMAC secret inlined into settings.json env (visible in `ps aux`; "
                         "dev only). Use --secret-file for production.")
    p.add_argument("--audit-file",
                    help="Durable ACS_AUDIT sink appended by every hook process "
                         "(created 0600). RECOMMENDED: without it, §6.4 audit "
                         "events land on hook stderr, which nothing collects.")
    p.add_argument("--settings",
                    default="~/.claude/settings.json",
                    help="Path to the Claude Code settings file (default: ~/.claude/settings.json).")
    p.add_argument("--hook-command", default=None,
                    help=f"Command the hooks run (default: the absolute path of the installed "
                         f"{HOOK_SCRIPT} console script).")
    p.add_argument("--hooks", default=",".join(ACS_CORE_HOOKS),
                    help=f"Comma-separated hook names to wire (default: the full mapped set: "
                         f"{','.join(ACS_CORE_HOOKS)}).")
    posture_group = p.add_mutually_exclusive_group()
    posture_group.add_argument("--default-deny", action="store_true",
                    help="Force ACS_DEFAULT_DENY=1 (fail-CLOSED) on EVERY wired hook. "
                         "Default behavior: fail-closed only on gate hooks "
                         f"({', '.join(sorted(GATE_HOOKS))}) — these block actions "
                         "until the Guardian decides, so a silent fail-open is a "
                         "policy hole. Non-gate hooks default to fail-open (matches "
                         "§6.4 spec default).")
    posture_group.add_argument("--all-fail-open", action="store_true",
                    help="Force ACS_DEFAULT_DENY=0 (fail-OPEN) on EVERY wired hook, "
                         "including gates. NOT RECOMMENDED for production — an "
                         "unreachable Guardian or malformed envelope on a gate hook "
                         "lets the action run unguarded. Matches strict §6.4 default.")
    p.add_argument("--host-allowlist", default=None,
                    help="Comma-separated hostnames the adapter will accept as Guardian URLs "
                         "(defense in depth against env-var attacks).")
    p.add_argument("--unwire", action="store_true",
                    help="Remove any ACS-wired hooks (preserves non-ACS entries).")
    p.add_argument("--cursor-third-party-imports-off", action="store_true",
                    help="Cursor's 'Include Third-Party Plugins, Skills, and Other Configs' setting is off, "
                         "so Cursor runs no Claude Code hooks; skip the copies only that import combines.")
    p.add_argument("--write", action="store_true",
                    help="Actually write the changes to settings.json (with timestamped backup). "
                         "Without this flag, this tool only prints what it WOULD do.")

    args = p.parse_args(argv)

    # Argument validation
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

    # Build new settings
    existing = load_settings(settings_path)
    if args.unwire:
        new = merge_unwire(existing,
                            (hook_names if args.hooks else ACS_CORE_HOOKS + ["SubagentStop", "PreCompact"])
                            + [h for h in RETIRED_HOOKS if h not in hook_names])
    else:
        # Build one command per hook. Each hook gets the deny posture
        # that matches its safety category:
        #   - --default-deny:   ALL hooks fail-closed.
        #   - --all-fail-open:  ALL hooks fail-open.
        #   - (default):        gate hooks fail-closed, others fail-open.
        commands_by_hook: dict[str, str] = {}
        blocking: set[str] = set()
        for hook in hook_names:
            if args.default_deny:
                hook_deny = True
            elif args.all_fail_open:
                hook_deny = False
            else:
                hook_deny = hook in GATE_HOOKS
            if hook_deny and hook not in _ON_FAILURE_IGNORED:
                # A fail-closed hook that crashes, times out or cannot start blocks too, not only its decision.
                blocking.add(hook)
            commands_by_hook[hook] = build_command(
                hook_command=hook_command,
                guardian_url=args.guardian_url,
                secret_file=args.secret_file,
                secret_env=args.secret_env_inline,
                key_id=args.key_id,
                default_deny=hook_deny,
                host_allowlist=args.host_allowlist,
                audit_file=args.audit_file,
            )
        retired = [h for h in RETIRED_HOOKS if h not in hook_names]
        new = merge_wire(merge_unwire(existing, retired), hook_names, commands_by_hook, frozenset(blocking))

    # Render
    warnings = validate_inputs(args)
    for w in warnings:
        print(f"  ⚠ {w}", file=sys.stderr)
    if warnings:
        print(file=sys.stderr)

    # Show per-hook fail posture so operator sees the chosen safety mix
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
                posture = "fail-OPEN (observational hook default)"
            print(f"  {hook:18s} → {posture}")
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
        print("  2. Restart any open Claude Code sessions — settings.json is "
              "read at session start, not live")
        print("  3. Verify the wiring from a repository checkout:")
        print("       cd adapters && uv run python tests/integrations/claude_code/e2e_check.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
