"""Holds the FinBot lab's text to its claims ledger (issue #587, LAB-14).

Version 1.0.0. Owner: ACS lab maintainers.

The ledger (CLAIMS.md) is Markdown for people with three fenced machine blocks. This module parses it and
scans a tree. It is stdlib only so the root test suite and the lab wrapper can both load it by path.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ID_ROW = re.compile(r"^\|\s*([CN]-\d{2})\s*\|", re.M)
SIGN_HEADER = "| Signed by | Date | Commit |"
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
SHA = re.compile(r"[0-9a-f]{40}")


@dataclass(frozen=True)
class Ledger:
    ids: frozenset[str]
    banned: tuple[str, ...]
    triggers: tuple[str, ...]
    exclude: tuple[str, ...]
    signed: bool
    # Claim rows whose evidence still says Unconfirmed:, which the sign gate refuses.
    unconfirmed: tuple[str, ...] = ()


def _block(text: str, tag: str) -> tuple[str, ...]:
    match = re.search(rf"^```{tag}\n(.*?)^```", text, re.S | re.M)
    if not match:
        raise ValueError(f"the ledger has no {tag} block")
    lines = tuple(ln.strip() for ln in match.group(1).splitlines() if ln.strip())
    if not lines:
        raise ValueError(f"the ledger's {tag} block is empty")
    return lines


def _unconfirmed(text: str) -> tuple[str, ...]:
    """Claim rows with Unconfirmed: anywhere in the evidence cell, not only at its start.

    A row can open with the evidence that exists and then name what it can't show. Matching the whole cell keeps
    that row from slipping past the sign gate.
    """
    rows = []
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if re.fullmatch(r"C-\d{2}", cells[0]) and len(cells) >= 3 and "Unconfirmed:" in cells[2]:
            rows.append(cells[0])
    return tuple(rows)


def _signed(text: str) -> bool:
    lines = text.splitlines()
    if SIGN_HEADER not in lines:
        raise ValueError(f"the ledger's sign-off table lacks the header {SIGN_HEADER!r}")
    rows = [ln for ln in lines[lines.index(SIGN_HEADER) + 2:] if ln.startswith("|")]
    if len(rows) != 1:
        raise ValueError("the ledger's sign-off table must hold exactly one row")
    cells = [c.strip() for c in rows[0].strip().strip("|").split("|")]
    if len(cells) != 3:
        raise ValueError("the sign-off row must have three cells")
    name, date, sha = cells
    if (date and not DATE.fullmatch(date)) or (sha and not SHA.fullmatch(sha)):
        raise ValueError("the sign-off row holds a malformed date or commit")
    return bool(name and date and sha)


def load_ledger(path: Path) -> Ledger:
    """Parse the ledger. Raises OSError when unreadable and ValueError when malformed."""
    text = Path(path).read_text(encoding="utf-8")
    return Ledger(
        ids=frozenset(ID_ROW.findall(text)),
        banned=_block(text, "claims-banned"),
        triggers=_block(text, "claims-triggers"),
        exclude=_block(text, "claims-exclude"),
        signed=_signed(text),
        unconfirmed=_unconfirmed(text),
    )


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    kind: str  # "banned", "unledgered", "unknown_id", "unsigned", "unconfirmed" or "unreadable"
    text: str


SCANNED = frozenset({".md", ".txt", ".html", ".js", ".css", ".py", ".rego", ".yaml", ".yml", ".json", ".sh", ".ps1"})
MARKER = re.compile(r"claim:([A-Za-z]+-\d+)")
FENCE = re.compile(r"^\s*(```|~~~)")
SNIFF_BYTES = 8192
SNIPPET_CHARS = 100


def escape_text(text: str) -> str:
    """Make scanned text safe to print: control and format characters (bidi overrides, escape codes) become \\uXXXX.

    Lab text under scan can be pull-request-written, and a finding is printed to a terminal.
    """
    out = []
    for ch in text:
        out.append(ch if ch.isprintable() else f"\\u{ord(ch):04x}")
    return "".join(out)


def _glob_regex(glob: str) -> re.Pattern[str]:
    """Translate a path glob: ** crosses directories (and **/ may match nothing), * stays inside one."""
    out, i = [], 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def _phrase_regex(phrases: tuple[str, ...], *, whole_word: bool) -> re.Pattern[str]:
    """One alternation, case-insensitive, left boundary always. Banned phrases also stop at a word end."""
    parts = [re.escape(p).replace(r"\ ", r"\s+") for p in phrases]
    tail = r"(?!\w)" if whole_word else ""
    return re.compile(r"(?<!\w)(?:" + "|".join(parts) + ")" + tail, re.I)


def _units(text: str, markdown: bool):
    """Yield (first line number, text, in_fence). Markdown paragraphs join wrapped lines with single spaces."""
    lines = text.splitlines()
    if not markdown:
        for n, line in enumerate(lines, 1):
            yield n, line, False
        return
    para: list[str] = []
    start = 0
    in_fence = False
    for n, line in enumerate(lines, 1):
        if FENCE.match(line):
            if para:
                yield start, " ".join(para), False
                para = []
            in_fence = not in_fence
            continue
        if in_fence:
            yield n, line, True
        elif line.strip():
            if not para:
                start = n
            para.append(line.strip())
        elif para:
            yield start, " ".join(para), False
            para = []
    if para:
        yield start, " ".join(para), False


def _check(unit: str, in_fence: bool, ledger: Ledger, banned: re.Pattern[str], triggers: re.Pattern[str]) -> list[tuple[str, str]]:
    markers = MARKER.findall(unit)
    valid = [m for m in markers if m in ledger.ids]
    found = [("unknown_id", f"claim:{m}") for m in markers if m not in ledger.ids]
    # Only a Not claimed marker excuses a banned phrase, because a banned phrase asserted under a claim row is the defect.
    if banned.search(unit) and not any(m.startswith("N-") for m in valid):
        found.append(("banned", unit))
    elif not in_fence and triggers.search(unit) and not valid:
        found.append(("unledgered", unit))
    return found


def scan(root: Path, ledger: Ledger, ledger_path: Path | None = None) -> list[Finding]:
    """Scan every text file under root. Symlinks are not followed and the ledger is never scanned."""
    root = Path(root)
    excluded = [_glob_regex(g) for g in ledger.exclude]
    skip = ledger_path.resolve() if ledger_path else None
    banned = _phrase_regex(ledger.banned, whole_word=True)
    triggers = _phrase_regex(ledger.triggers, whole_word=False)
    findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink() or path.suffix.lower() not in SCANNED:
                continue
            if any(rx.match(rel) for rx in excluded) or (skip and path.resolve() == skip):
                continue
            try:
                raw = path.read_bytes()
            except OSError as e:
                findings.append(Finding(rel, 0, "unreadable", escape_text(str(e))))
                continue
            if b"\x00" in raw[:SNIFF_BYTES]:
                continue
            text = raw.decode("utf-8", errors="replace")
            for line, unit, in_fence in _units(text, path.suffix.lower() == ".md"):
                for kind, shown in _check(unit, in_fence, ledger, banned, triggers):
                    findings.append(Finding(rel, line, kind, escape_text(shown.strip()[:SNIPPET_CHARS])))
    return findings


def _count_files(root: Path) -> int:
    return sum(1 for _, _, names in os.walk(root, followlinks=False) for n in names)


def main(argv: list[str] | None = None) -> int:
    """Exit 0 clean, 1 findings, 2 the ledger or the path can't be read.

    --require-signed also fails on an empty sign-off row and on each claim row still marked Unconfirmed:.
    """
    parser = argparse.ArgumentParser(prog="lab_claims", description="Hold lab text to the claims ledger.")
    parser.add_argument("path", nargs="?", help="directory to scan, default the directory holding the ledger")
    parser.add_argument("--ledger", help="ledger file, default CLAIMS.md beside the cli directory")
    parser.add_argument("--require-signed", action="store_true", help="fail while the sign-off row is empty or any claim row is Unconfirmed:")
    args = parser.parse_args(argv)
    ledger_path = Path(args.ledger) if args.ledger else Path(__file__).resolve().parents[1] / "CLAIMS.md"
    try:
        ledger = load_ledger(ledger_path)
    except (OSError, ValueError) as e:
        print(f"ERROR: can't use the ledger {ledger_path}: {escape_text(str(e))}", file=sys.stderr)
        return 2
    root = Path(args.path) if args.path else ledger_path.parent
    if not root.is_dir():
        print(f"ERROR: {escape_text(str(root))} isn't a readable directory", file=sys.stderr)
        return 2
    findings = scan(root, ledger, ledger_path)
    if args.require_signed and not ledger.signed:
        findings.append(Finding(ledger_path.name, 0, "unsigned", "the sign-off row is empty"))
    if args.require_signed:
        # Signing a ledger that still says a row can't be confirmed would sign a claim nobody checked.
        findings += [Finding(ledger_path.name, 0, "unconfirmed", row) for row in ledger.unconfirmed]
    if findings:
        for f in findings:
            print(f"NOT YET: {f.path}:{f.line} {f.kind} {f.text}")
        return 1
    print(f"DONE: lab text holds to the ledger ({_count_files(root)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
