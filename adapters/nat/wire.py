#!/usr/bin/env python3
"""
Wire (or unwire / lint) the ACS adapter into a NAT `workflow.yml`.

NAT's middleware is opt-in per attachment point: the user has to list
`acs_guardian` under `middleware:` on the workflow, every function_group,
and any function that overrides its group's middleware. Miss one and
that path bypasses the Guardian. This CLI walks the YAML, finds every
attachment point, and either reports gaps (`--check`) or fills them in
(`--write`). It is idempotent: every line we add carries a
`# acs-adapter-wired` comment so a re-run is a no-op and `--unwire`
removes exactly what we added (and nothing else).

NAT's framework-wide lifecycle stream (`IntermediateStepManager`,
subscribed in acs_adapter.py:_ensure_lifecycle_subscribed) gives the
Guardian observability of every call even when middleware wiring is
incomplete — that's a backstop, not a substitute for wire+lint, because
lifecycle subscribers can only OBSERVE calls, not BLOCK them. Enforcement
still needs the middleware wired.

Modes
=====

  python3 wire.py --workflow=path/to/workflow.yml
        Dry-run preview: show the unified diff that --write would apply.

  python3 wire.py --workflow=path/to/workflow.yml --write
        Apply the wiring (backup at workflow.yml.bak.<timestamp>).

  python3 wire.py --workflow=path/to/workflow.yml --check
        Lint-only. Print every attachment point that is not wired and
        exit non-zero if any gap is found. Suitable for CI.

  python3 wire.py --workflow=path/to/workflow.yml --unwire --write
        Remove every line we previously added (carries the marker).

Coverage caveat
===============
This wires what is in the YAML at wire-time. Coverage gaps it cannot
close:
  - Functions registered dynamically in Python (not in the YAML).
  - Sub-workflows loaded at runtime from other files.
  - Custom middleware classes that fork their own call path.

For those, rely on the lifecycle-subscription backstop the adapter
emits and audit the Guardian for "saw call via lifecycle but never via
middleware" findings.
"""
from __future__ import annotations

import argparse
import datetime
import difflib
import io
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from ruamel.yaml import YAML
    from ruamel.yaml.comments import CommentedMap, CommentedSeq
except ImportError:
    sys.stderr.write(
        "wire.py needs `ruamel.yaml` for comment-preserving YAML round-trip.\n"
        "Install: python3 -m pip install ruamel.yaml\n"
    )
    sys.exit(2)


WIRE_MARKER = "acs-adapter-wired"
MIDDLEWARE_NAME = "acs_guardian"
MIDDLEWARE_TYPE = "acs_guardian"


# ──────────────────────────────────────────────────────────────────────
# Gap model — shared by lint + wire
# ──────────────────────────────────────────────────────────────────────

@dataclass
class Gap:
    """One missing-wire finding. Reused by --check (print) and
    default/--write (mutate)."""
    severity: str   # "error" | "warn"
    kind: str       # "workflow" | "function_group" | "function" | "middleware_block" | "config"
    path: str       # dotted location e.g. "function_groups.my_tools"
    line: int | None
    detail: str


def _yaml() -> YAML:
    """Round-trip parser preserving comments, formatting, and order."""
    y = YAML(typ="rt")
    y.preserve_quotes = True
    y.indent(mapping=2, sequence=4, offset=2)
    return y


# ──────────────────────────────────────────────────────────────────────
# Walker — single source of truth for "what attachment points exist
# and which are wired". Used by both lint and wire to guarantee they
# never diverge.
# ──────────────────────────────────────────────────────────────────────

def _line_of(node: Any) -> int | None:
    """ruamel exposes .lc.line on CommentedMap / CommentedSeq nodes
    (1-based after we +1). Returns None if absent."""
    lc = getattr(node, "lc", None)
    if lc is None:
        return None
    return (lc.line or 0) + 1


def _list_includes_middleware(seq: Any) -> bool:
    """Treat both ['acs_guardian'] and ['acs_guardian', ...] as wired."""
    if not isinstance(seq, (list, CommentedSeq)):
        return False
    return any(str(item) == MIDDLEWARE_NAME for item in seq)


def find_attachment_points(doc: Any) -> list[Gap]:
    """Walk the loaded workflow document and return every gap.
    Empty list means fully wired."""
    gaps: list[Gap] = []
    if not isinstance(doc, (dict, CommentedMap)):
        gaps.append(Gap("error", "config", "<root>", None,
                         "workflow file root is not a mapping"))
        return gaps

    # 1) The middleware block must define acs_guardian with _type acs_guardian
    mw_block = doc.get("middleware")
    if not isinstance(mw_block, (dict, CommentedMap)) or MIDDLEWARE_NAME not in mw_block:
        gaps.append(Gap("error", "middleware_block", "middleware",
                         _line_of(mw_block) if mw_block is not None else None,
                         f"top-level `middleware:` block is missing the "
                         f"`{MIDDLEWARE_NAME}:` definition"))
    else:
        mw_def = mw_block[MIDDLEWARE_NAME]
        if not isinstance(mw_def, (dict, CommentedMap)) or mw_def.get("_type") != MIDDLEWARE_TYPE:
            gaps.append(Gap(
                "error", "config", f"middleware.{MIDDLEWARE_NAME}",
                _line_of(mw_def),
                f"`middleware.{MIDDLEWARE_NAME}._type` must be "
                f"`{MIDDLEWARE_TYPE}` (got {mw_def.get('_type') if isinstance(mw_def, dict) else 'non-mapping'!r})"))

    # 2) The workflow attachment point
    wf = doc.get("workflow")
    if isinstance(wf, (dict, CommentedMap)):
        if not _list_includes_middleware(wf.get("middleware")):
            gaps.append(Gap("error", "workflow", "workflow",
                             _line_of(wf),
                             f"`workflow.middleware` does not include `{MIDDLEWARE_NAME}` — the agent's top-level execution will not be gated"))

    # 3) Every function_group attachment point
    fgs = doc.get("function_groups")
    if isinstance(fgs, (dict, CommentedMap)):
        for name, fg in fgs.items():
            if not isinstance(fg, (dict, CommentedMap)):
                continue
            if not _list_includes_middleware(fg.get("middleware")):
                gaps.append(Gap(
                    "error", "function_group",
                    f"function_groups.{name}", _line_of(fg),
                    f"function_group `{name}` does not list `{MIDDLEWARE_NAME}` — every function in this group will bypass the Guardian"))

    # 4) Any individual function with its own middleware: list — that
    # override punches a hole through its group's wiring if it omits us.
    funcs = doc.get("functions")
    if isinstance(funcs, (dict, CommentedMap)):
        for name, fn in funcs.items():
            if not isinstance(fn, (dict, CommentedMap)):
                continue
            if "middleware" in fn and not _list_includes_middleware(fn.get("middleware")):
                gaps.append(Gap(
                    "error", "function",
                    f"functions.{name}", _line_of(fn),
                    f"function `{name}` overrides `middleware:` but omits `{MIDDLEWARE_NAME}` — this call path bypasses the Guardian"))

    return gaps


# ──────────────────────────────────────────────────────────────────────
# Mutators — every line we add carries the WIRE_MARKER comment so
# --unwire knows exactly what we (and only what we) added.
# ──────────────────────────────────────────────────────────────────────

def _make_middleware_def(guardian_url: str, default_deny: bool,
                          timeout_s: float) -> CommentedMap:
    cm = CommentedMap()
    cm["_type"] = MIDDLEWARE_TYPE
    cm["guardian_url"] = guardian_url
    cm["default_deny"] = default_deny
    cm["timeout_s"] = timeout_s
    return cm


def _ensure_middleware_block(doc: CommentedMap, guardian_url: str,
                              default_deny: bool, timeout_s: float) -> bool:
    """Insert middleware.acs_guardian if missing. Returns True iff mutated."""
    mw = doc.get("middleware")
    mutated = False
    if not isinstance(mw, (dict, CommentedMap)):
        mw = CommentedMap()
        # Insert at top of file (before workflow if possible)
        doc.insert(0, "middleware", mw,
                    comment=WIRE_MARKER + " (block created)")
        mutated = True
    if MIDDLEWARE_NAME not in mw:
        mw[MIDDLEWARE_NAME] = _make_middleware_def(guardian_url, default_deny, timeout_s)
        mw.yaml_add_eol_comment(WIRE_MARKER, key=MIDDLEWARE_NAME)
        mutated = True
    return mutated


def _ensure_middleware_listed(parent: CommentedMap, path_for_log: str) -> bool:
    """Ensure parent.middleware includes acs_guardian. Returns True iff mutated."""
    mw = parent.get("middleware")
    if mw is None:
        new = CommentedSeq([MIDDLEWARE_NAME])
        parent["middleware"] = new
        parent.yaml_add_eol_comment(WIRE_MARKER, key="middleware")
        return True
    if isinstance(mw, (list, CommentedSeq)):
        if MIDDLEWARE_NAME in [str(x) for x in mw]:
            return False
        # Insert FIRST so policy gate runs before content filters
        mw.insert(0, MIDDLEWARE_NAME)
        try:
            mw.yaml_add_eol_comment(WIRE_MARKER, key=0)
        except (AttributeError, TypeError):
            pass
        return True
    # middleware is scalar (single middleware) — replace with list
    parent["middleware"] = CommentedSeq([MIDDLEWARE_NAME, mw])
    parent.yaml_add_eol_comment(WIRE_MARKER, key="middleware")
    return True


def install(doc: CommentedMap, *, guardian_url: str, default_deny: bool,
             timeout_s: float) -> list[str]:
    """Apply wiring to doc in place. Returns a list of human-readable
    change descriptions for the operator to review."""
    changes: list[str] = []
    if _ensure_middleware_block(doc, guardian_url, default_deny, timeout_s):
        changes.append(f"middleware.{MIDDLEWARE_NAME}: defined ({guardian_url})")

    wf = doc.get("workflow")
    if isinstance(wf, (dict, CommentedMap)):
        if _ensure_middleware_listed(wf, "workflow"):
            changes.append(f"workflow.middleware: added `{MIDDLEWARE_NAME}`")

    fgs = doc.get("function_groups")
    if isinstance(fgs, (dict, CommentedMap)):
        for name, fg in fgs.items():
            if isinstance(fg, (dict, CommentedMap)):
                if _ensure_middleware_listed(fg, f"function_groups.{name}"):
                    changes.append(f"function_groups.{name}.middleware: added `{MIDDLEWARE_NAME}`")

    funcs = doc.get("functions")
    if isinstance(funcs, (dict, CommentedMap)):
        for name, fn in funcs.items():
            if isinstance(fn, (dict, CommentedMap)) and "middleware" in fn:
                if _ensure_middleware_listed(fn, f"functions.{name}"):
                    changes.append(f"functions.{name}.middleware: added `{MIDDLEWARE_NAME}`")

    return changes


# ──────────────────────────────────────────────────────────────────────
# Unwire — structured removal on the parsed YAML: only nodes carrying
# WIRE_MARKER are removed (text-stripping would orphan child lines).
# ──────────────────────────────────────────────────────────────────────

def _eol_comment_text(parent: CommentedMap | CommentedSeq, key: Any) -> str:
    """Return the EOL comment text attached to `parent[key]` (or empty
    string if none). ruamel stores these in parent.ca.items[key] as a
    quirky 4-tuple — only entry [2] (eol comment token) carries the
    text we need."""
    ca = getattr(parent, "ca", None)
    if ca is None:
        return ""
    items = getattr(ca, "items", None) or {}
    entry = items.get(key)
    if not entry:
        return ""
    # entry is [pre_key_comment, key_comments, eol_comment_token, ...]
    for tok in entry:
        if tok is None:
            continue
        # Handle list of tokens or single token
        toks = tok if isinstance(tok, list) else [tok]
        for t in toks:
            val = getattr(t, "value", None)
            if isinstance(val, str) and WIRE_MARKER in val:
                return val
    return ""


def unwire(text: str) -> tuple[str, list[str]]:
    """Remove every node we previously annotated with WIRE_MARKER.
    Operates on the parsed document; safer than text stripping."""
    removed: list[str] = []
    doc = _yaml().load(text)
    if not isinstance(doc, (dict, CommentedMap)):
        return text, removed

    # 1) middleware block (and its acs_guardian subkey)
    mw = doc.get("middleware")
    if isinstance(mw, (dict, CommentedMap)):
        # Subkey we added: middleware.acs_guardian (marker on that key)
        sub_comment = _eol_comment_text(mw, MIDDLEWARE_NAME)
        if MIDDLEWARE_NAME in mw and WIRE_MARKER in sub_comment:
            del mw[MIDDLEWARE_NAME]
            removed.append(f"middleware.{MIDDLEWARE_NAME}: removed")

        # Top-level block we created (marker on doc.middleware key with
        # "(block created)" suffix means we own the whole thing)
        top_comment = _eol_comment_text(doc, "middleware")
        if "(block created)" in top_comment or len(mw) == 0:
            del doc["middleware"]
            removed.append("middleware: removed block")

    # 2) workflow.middleware
    wf = doc.get("workflow")
    if isinstance(wf, (dict, CommentedMap)):
        _strip_listed_middleware(wf, "workflow", removed)

    # 3) function_groups.*.middleware
    fgs = doc.get("function_groups")
    if isinstance(fgs, (dict, CommentedMap)):
        for name, fg in fgs.items():
            if isinstance(fg, (dict, CommentedMap)):
                _strip_listed_middleware(fg, f"function_groups.{name}", removed)

    # 4) functions.*.middleware
    funcs = doc.get("functions")
    if isinstance(funcs, (dict, CommentedMap)):
        for name, fn in funcs.items():
            if isinstance(fn, (dict, CommentedMap)):
                _strip_listed_middleware(fn, f"functions.{name}", removed)

    buf = io.StringIO()
    _yaml().dump(doc, buf)
    return buf.getvalue(), removed


def _strip_listed_middleware(parent: CommentedMap, path: str,
                              removed: list[str]) -> None:
    """Remove ONLY what we previously added (marked with WIRE_MARKER).
    Hand-wired entries that lack the marker stay untouched — the marker
    is the only signal that a node was ours."""
    mw = parent.get("middleware")
    if mw is None:
        return
    parent_marker = _eol_comment_text(parent, "middleware")
    # Case A: we created the whole `middleware:` key for this parent
    if WIRE_MARKER in parent_marker and isinstance(mw, (list, CommentedSeq)):
        contents = [str(x) for x in mw]
        if contents == [MIDDLEWARE_NAME]:
            del parent["middleware"]
            removed.append(f"{path}.middleware: removed key")
            return
        # Or scalar-to-list conversion: list is [acs_guardian, <original>]
        if len(contents) >= 2 and contents[0] == MIDDLEWARE_NAME:
            # Restore the second entry as the scalar (or keep as list)
            del mw[0]
            removed.append(f"{path}.middleware: removed inserted `{MIDDLEWARE_NAME}`")
            return
    # Case B: we prepended into an existing list — remove only the
    # marker-carrying item(s).
    if isinstance(mw, (list, CommentedSeq)):
        to_remove: list[int] = []
        for i, item in enumerate(mw):
            if str(item) != MIDDLEWARE_NAME:
                continue
            item_comment = _eol_comment_text(mw, i)
            if WIRE_MARKER in item_comment:
                to_remove.append(i)
        for i in reversed(to_remove):
            del mw[i]
            removed.append(f"{path}.middleware[{i}]: removed inserted `{MIDDLEWARE_NAME}`")
        if len(mw) == 0 and WIRE_MARKER in parent_marker:
            del parent["middleware"]
            removed.append(f"{path}.middleware: removed empty list")


# ──────────────────────────────────────────────────────────────────────
# Rendering
# ──────────────────────────────────────────────────────────────────────

def render(doc: Any) -> str:
    buf = io.StringIO()
    _yaml().dump(doc, buf)
    return buf.getvalue()


def render_diff(before: str, after: str, label: str) -> str:
    diff = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"{label} (current)",
        tofile=f"{label} (after wire)",
    )
    return "".join(diff)


def format_gaps(gaps: list[Gap], yaml_path: Path) -> str:
    if not gaps:
        return f"{yaml_path}: fully wired — no gaps."
    lines = [f"{yaml_path}:"]
    by_severity = {"error": 0, "warn": 0}
    for g in gaps:
        by_severity[g.severity] = by_severity.get(g.severity, 0) + 1
        loc = f"line {g.line}" if g.line is not None else "(no line)"
        sev = g.severity.upper().ljust(5)
        lines.append(f"  {sev} {loc}: {g.path} — {g.detail}")
    err = by_severity.get("error", 0)
    wrn = by_severity.get("warn", 0)
    lines.append(f"Summary: {len(gaps)} finding(s) — {err} error, {wrn} warning")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Wire / lint / unwire the ACS adapter in a NAT workflow.yml.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("--workflow", required=True,
                    help="Path to the workflow.yml to operate on.")
    p.add_argument("--guardian-url", default="http://127.0.0.1:8787/acs",
                    help="ACS Guardian endpoint (default: http://127.0.0.1:8787/acs).")
    p.add_argument("--default-deny", action="store_true",
                    help="Set the middleware's default_deny: true (fail-closed when "
                          "Guardian is unreachable). Default false matches §6.4 fail-open + audit.")
    p.add_argument("--timeout-s", type=float, default=5.0,
                    help="Per-request Guardian timeout (default 5.0s).")
    p.add_argument("--write", action="store_true",
                    help="Apply changes. Without this, runs as dry-run (diff to stdout).")
    p.add_argument("--unwire", action="store_true",
                    help="Remove every line we previously added (WIRE_MARKER-tagged).")
    p.add_argument("--check", action="store_true",
                    help="Lint-only: print gaps and exit non-zero if any found.")
    args = p.parse_args(argv)

    yaml_path = Path(args.workflow).expanduser().resolve()
    if not yaml_path.exists():
        sys.stderr.write(f"FATAL: workflow file not found: {yaml_path}\n")
        return 2

    before_text = yaml_path.read_text()

    if args.check:
        doc = _yaml().load(before_text)
        gaps = find_attachment_points(doc)
        print(format_gaps(gaps, yaml_path))
        return 1 if any(g.severity == "error" for g in gaps) else 0

    if args.unwire:
        after_text, removed = unwire(before_text)
        if not removed:
            print(f"{yaml_path}: nothing to unwire (no `{WIRE_MARKER}` markers found).")
            return 0
        if args.write:
            backup = yaml_path.with_suffix(
                yaml_path.suffix + ".bak."
                + datetime.datetime.now().strftime("%Y%m%dT%H%M%S"))
            shutil.copyfile(yaml_path, backup)
            yaml_path.write_text(after_text)
            print(f"unwired {len(removed)} line(s) from {yaml_path}")
            print(f"backup: {backup}")
            for r in removed:
                print(f"  - {r}")
            return 0
        diff = render_diff(before_text, after_text, str(yaml_path))
        sys.stdout.write(diff)
        print(f"\n(dry-run; re-run with --write to apply. {len(removed)} line(s) would be removed.)")
        return 0

    # Default: install / re-install
    doc = _yaml().load(before_text)
    changes = install(doc, guardian_url=args.guardian_url,
                       default_deny=args.default_deny,
                       timeout_s=args.timeout_s)
    after_text = render(doc)

    if not changes:
        print(f"{yaml_path}: already fully wired — no changes needed.")
        return 0

    if args.write:
        backup = yaml_path.with_suffix(
            yaml_path.suffix + ".bak."
            + datetime.datetime.now().strftime("%Y%m%dT%H%M%S"))
        shutil.copyfile(yaml_path, backup)
        yaml_path.write_text(after_text)
        print(f"wired {len(changes)} attachment point(s) in {yaml_path}")
        print(f"backup: {backup}")
        for c in changes:
            print(f"  + {c}")
        return 0

    diff = render_diff(before_text, after_text, str(yaml_path))
    sys.stdout.write(diff)
    print(f"\n{len(changes)} attachment point(s) would be wired (dry-run; re-run with --write to apply):")
    for c in changes:
        print(f"  + {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
