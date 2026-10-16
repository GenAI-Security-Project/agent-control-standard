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
python3 wire.py \\
  --guardian-url=http://127.0.0.1:8787/acs \\
  --secret-file=~/.acs/hmac.key

# 2. Same, but actually write (with backup at ~/.cursor/hooks.json.bak.<ts>)
python3 wire.py \\
  --guardian-url=http://127.0.0.1:8787/acs \\
  --secret-file=~/.acs/hmac.key \\
  --write

# 3. Project-level wiring
python3 wire.py \\
  --guardian-url=http://127.0.0.1:8787/acs \\
  --secret-file=~/.acs/hmac.key \\
  --settings=./.cursor/hooks.json \\
  --write

# 4. Subset of hooks
python3 wire.py \\
  --guardian-url=http://127.0.0.1:8787/acs \\
  --secret-file=~/.acs/hmac.key \\
  --hooks=preToolUse,postToolUse

# 5. Remove ACS wiring (preserves any other hooks you have)
python3 wire.py --unwire --write

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
import datetime
import difflib
import json
import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
DEFAULT_ADAPTER_PATH = HERE / "acs_adapter.py"

# This branch's ACS-Core minimum in Cursor's vocabulary maps to:
#   sessionStart       — ACS sessionStart
#   beforeSubmitPrompt — ACS userMessage
#   preToolUse         — ACS toolCallRequest
#   postToolUse        — ACS toolCallResult
#   afterAgentResponse — ACS agentResponse
#   sessionEnd         — ACS sessionEnd
CURRENT_CORE_HOOKS = [
    "sessionStart",
    "beforeSubmitPrompt",
    "preToolUse",
    "postToolUse",
    "afterAgentResponse",
    "sessionEnd",
]

# PR #21 (open; not in this branch) proposes subagentStart for the Core
# floor when the client supports subagents; Cursor exposes that boundary,
# so the default wires the confused-deputy gate now.
PR21_PROPOSED_HOOKS = [
    "subagentStart",
]
DEFAULT_HOOKS = CURRENT_CORE_HOOKS + PR21_PROPOSED_HOOKS

# Hooks whose ACS verdict actually gates the action get BOTH Cursor's
# native `failClosed: true` (adapter crash) and ACS_DEFAULT_DENY=1
# (Guardian unreachable / unknown verdict) — two independent mechanisms
# that must both fail open for a gate to leak; observational hooks get
# fail-open per the §6.4 default.
GATE_HOOKS = frozenset({
    "preToolUse", "beforeSubmitPrompt",
    "beforeShellExecution", "beforeMCPExecution", "subagentStart",
})

# Marker embedded in our hook commands so we can identify "is this a
# hook entry we wired?" on unwire, without parsing argument shapes.
WIRE_MARKER = "# acs-adapter-wired"


# ──────────────────────────────────────────────────────────────────────
# Command-line construction
# ──────────────────────────────────────────────────────────────────────

def build_command(*, adapter_path: Path, event_name: str,
                   guardian_url: str,
                   secret_file: str | None,
                   secret_env: str | None,
                   default_deny: bool,
                   host_allowlist: str | None,
                   python_bin: str) -> str:
    """Compose the hook command string used inside hooks.json.

    Cursor passes the event name as argv[1], so the command line ends
    with `python3 /path/to/acs_adapter.py <event_name>`.
    """
    env_pairs: list[str] = [f"ACS_GUARDIAN_URL={guardian_url}"]
    if secret_file:
        env_pairs.append(f"ACS_HMAC_SECRET_FILE={_expand(secret_file)}")
    elif secret_env:
        env_pairs.append(f"ACS_HMAC_SECRET={secret_env}")
    if default_deny:
        env_pairs.append("ACS_DEFAULT_DENY=1")
    if host_allowlist:
        env_pairs.append(f"ACS_GUARDIAN_HOST_ALLOWLIST={host_allowlist}")
    env_prefix = " ".join(env_pairs)
    return f"{env_prefix} {python_bin} {adapter_path} {event_name} {WIRE_MARKER}"


def build_hook_entry(command: str, *, fail_closed: bool) -> dict:
    """The Cursor hook-entry shape under each hook type.

    Includes `failClosed: true` for gate hooks (Cursor's native fail-
    posture mechanism — separate from our ACS_DEFAULT_DENY env var).
    Together they cover both failure modes (adapter crashes vs.
    Guardian unreachable / unknown verdict)."""
    entry = {"command": command}
    if fail_closed:
        entry["failClosed"] = True
    return entry


# ──────────────────────────────────────────────────────────────────────
# hooks.json merge
# ──────────────────────────────────────────────────────────────────────

def load_settings(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise SystemExit(f"FATAL: {path} is not valid JSON ({e}). Fix or remove first.")


def merge_wire(existing: dict, hook_names: list[str],
                entries_by_hook: dict[str, dict]) -> dict:
    """Return a new hooks.json dict with ACS wiring merged in.

    entries_by_hook is {event_name: hook_entry_dict} so each hook can
    have its own deny posture / failClosed setting.

    Re-entrancy: operates at the inner-hooks list level so re-wiring
    REPLACES our entry without touching the user's own entries under
    the same event.
    """
    out = json.loads(json.dumps(existing))  # deep copy
    out.setdefault("version", 1)
    hooks = out.setdefault("hooks", {})
    for name in hook_names:
        entry = entries_by_hook[name]
        existing_list = hooks.get(name, [])
        # Strip our previous entry (carries WIRE_MARKER) and append the new one.
        # Non-ACS entries left untouched.
        kept = [e for e in existing_list
                if WIRE_MARKER not in (e.get("command") or "")]
        kept.append(entry)
        hooks[name] = kept
    return out


def merge_unwire(existing: dict, hook_names: list[str]) -> dict:
    """Strip ACS-wired entries from the given hook types.

    Preserves the user's own non-ACS entries under the same events.
    Empty event lists are removed; empty hooks dict is removed.
    """
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


def write_atomically(path: Path, content: str) -> Path:
    """Write content to path atomically, with a timestamped backup of any
    existing file. Returns the backup path (or None if no original existed).
    """
    backup = None
    if path.exists():
        ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
        backup = path.with_suffix(path.suffix + f".bak.{ts}")
        shutil.copy2(path, backup)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content)
    os.replace(tmp, path)
    return backup


# ──────────────────────────────────────────────────────────────────────
# Validation helpers
# ──────────────────────────────────────────────────────────────────────

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
                "hooks.json (visible in `ps aux`). For production, prefer "
                "--secret-file with a 0600 key file.")
        else:
            warnings.append(
                "WARNING: no HMAC secret configured (neither --secret-file "
                "nor --secret-env-inline). Adapter will run unsigned — Guardian "
                "will reject every request unless it's also unconfigured "
                "(ACS_DEV_MODE=1). ACS-Core baseline integrity (§10) "
                "REQUIRES signing.")

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
                "NOTE: subagentStart is not wired. PR #21 (open; not in "
                "this branch) proposes it as a conditional Core gate for "
                "subagent-capable clients; Cursor exposes that boundary.")

    return warnings


# ──────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────

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
    p.add_argument("--secret-env-inline", metavar="HEX",
                    help="HMAC secret inlined into hooks.json env (visible in `ps aux`; "
                         "dev only). Use --secret-file for production.")
    p.add_argument("--settings",
                    default="~/.cursor/hooks.json",
                    help="Path to Cursor hooks.json (default: ~/.cursor/hooks.json — "
                         "user-level). Use ./.cursor/hooks.json for project-level.")
    p.add_argument("--adapter",
                    default=str(DEFAULT_ADAPTER_PATH),
                    help=f"Absolute path to acs_adapter.py (default: {DEFAULT_ADAPTER_PATH}).")
    p.add_argument("--python-bin",
                    default="python3",
                    help="Python interpreter the hook command uses (default: python3 from PATH).")
    p.add_argument("--hooks", default=",".join(DEFAULT_HOOKS),
                    help="Comma-separated hook names to wire (default: this "
                         "branch's ACS-Core minimum plus PR #21's proposed "
                         f"subagentStart gate: {','.join(DEFAULT_HOOKS)}).")
    posture_group = p.add_mutually_exclusive_group()
    posture_group.add_argument("--default-deny", action="store_true",
                    help="Force fail-CLOSED on EVERY wired hook (sets BOTH Cursor's "
                         "native failClosed AND our ACS_DEFAULT_DENY=1). Default behavior: "
                         "fail-closed only on gate hooks "
                         f"({', '.join(sorted(GATE_HOOKS & set(DEFAULT_HOOKS)))}).")
    posture_group.add_argument("--all-fail-open", action="store_true",
                    help="Force fail-OPEN on EVERY wired hook, including gates. NOT "
                         "RECOMMENDED — strict §6.4 default but a Guardian outage on a "
                         "gate hook lets the action run unguarded.")
    p.add_argument("--host-allowlist", default=None,
                    help="Comma-separated hostnames the adapter will accept as Guardian URLs.")
    p.add_argument("--unwire", action="store_true",
                    help="Remove any ACS-wired hooks (preserves non-ACS entries).")
    p.add_argument("--write", action="store_true",
                    help="Actually write the changes to hooks.json (with timestamped backup). "
                         "Without this flag, this tool only prints what it WOULD do.")

    args = p.parse_args(argv)

    if not args.unwire and not args.guardian_url:
        p.error("--guardian-url is required (unless --unwire)")
    if args.secret_file and args.secret_env_inline:
        p.error("provide --secret-file OR --secret-env-inline, not both")

    settings_path = _expand(args.settings)
    adapter_path = _expand(args.adapter)
    if not args.unwire and not adapter_path.exists():
        p.error(f"adapter not found at {adapter_path}; pass --adapter to override")

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
        # Build one entry per hook. Each gets the deny posture for its
        # safety category:
        #   - --default-deny:    ALL hooks fail-closed
        #   - --all-fail-open:   ALL hooks fail-open
        #   - (default):         gate hooks fail-closed, others fail-open
        entries_by_hook: dict[str, dict] = {}
        for hook in hook_names:
            if args.default_deny:
                hook_deny = True
            elif args.all_fail_open:
                hook_deny = False
            else:
                hook_deny = hook in GATE_HOOKS
            cmd = build_command(
                adapter_path=adapter_path,
                event_name=hook,
                guardian_url=args.guardian_url,
                secret_file=args.secret_file,
                secret_env=args.secret_env_inline,
                default_deny=hook_deny,
                host_allowlist=args.host_allowlist,
                python_bin=args.python_bin,
            )
            entries_by_hook[hook] = build_hook_entry(cmd, fail_closed=hook_deny)
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
                posture = "fail-OPEN (observational hook default)"
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
        print("  3. Verify the wiring works:")
        print(f"       cd {HERE}")
        print("       python3 e2e_check.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
