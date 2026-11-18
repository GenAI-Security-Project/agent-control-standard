"""Holds the FinBot lab's text to its claims ledger (issue #587, LAB-14).

Version 1.0.0. Owner: ACS lab maintainers.

The ledger (CLAIMS.md) is Markdown for people with three fenced machine blocks. This module parses it and
scans a tree. It is stdlib only so the root test suite and the lab wrapper can both load it by path.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import os
import re
import stat
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path

ID_ROW = re.compile(r"^\|\s*([CN]-\d{2})\s*\|", re.M)
SIGN_HEADING = re.compile(r"^## Sign-off$", re.M)
SIGN_HEADER = "| Signed by | Date | Commit | Ledger sha256 |"
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
PLACEHOLDER = re.compile(r"(?:tbd|todo)\b", re.I)


@dataclass(frozen=True)
class Ledger:
    ids: frozenset[str]
    banned: tuple[str, ...]
    triggers: tuple[str, ...]
    exclude: tuple[str, ...]
    signed: bool
    # Claim rows the sign gate refuses: Unconfirmed in any case anywhere in the row, or empty or placeholder evidence.
    unconfirmed: tuple[str, ...] = ()
    # The sign-off row is filled in but its digest no longer matches the ledger text above it.
    stale: bool = False


def _cells(line: str) -> list[str]:
    """Split a Markdown table row on pipes that aren't escaped, and unescape the cells."""
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|") and not line.endswith("\\|"):
        line = line[:-1]
    return [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", line)]


def _block(text: str, tag: str) -> tuple[str, ...]:
    match = re.search(rf"^```{tag}\n(.*?)^```", text, re.S | re.M)
    if not match:
        raise ValueError(f"the ledger has no {tag} block")
    lines = tuple(ln.strip() for ln in match.group(1).splitlines() if ln.strip())
    if not lines:
        raise ValueError(f"the ledger's {tag} block is empty")
    return lines


def ledger_digest(text: str) -> str:
    """The sha256 of the ledger text above the sign-off section.

    The sign-off row records it, so an edit to any claim after signing leaves the row stale and reads as unsigned.
    """
    headings = SIGN_HEADING.findall(text)
    if len(headings) != 1:
        raise ValueError("the ledger must hold exactly one '## Sign-off' section")
    return hashlib.sha256(text[:SIGN_HEADING.search(text).start()].encode("utf-8")).hexdigest()


def _unconfirmed(text: str) -> tuple[str, ...]:
    """Claim rows the sign gate refuses.

    Unconfirmed matches in any case anywhere in the row, because a row can open with the evidence that exists and
    name the gap later. An empty or placeholder evidence cell is refused too, since it says nothing was checked.
    """
    rows = []
    for line in text.splitlines():
        cells = _cells(line) if line.startswith("|") else []
        if len(cells) >= 3 and re.fullmatch(r"C-\d{2}", cells[0]):
            evidence = cells[2]
            if "unconfirmed" in line.lower() or not evidence or PLACEHOLDER.match(evidence):
                rows.append(cells[0])
    return tuple(rows)


def _signed(text: str) -> tuple[bool, bool]:
    """Return (signed, stale). Signed needs a full row whose digest matches the ledger text above it."""
    lines = text.splitlines()
    if SIGN_HEADER not in lines:
        raise ValueError(f"the ledger's sign-off table lacks the header {SIGN_HEADER!r}")
    rows = [ln for ln in lines[lines.index(SIGN_HEADER) + 2:] if ln.startswith("|")]
    if len(rows) != 1:
        raise ValueError("the ledger's sign-off table must hold exactly one row")
    cells = _cells(rows[0])
    if len(cells) != 4:
        raise ValueError("the sign-off row must have four cells")
    name, date, sha, digest = cells
    if (date and not DATE.fullmatch(date)) or (sha and not SHA.fullmatch(sha)) or (digest and not DIGEST.fullmatch(digest)):
        raise ValueError("the sign-off row holds a malformed date, commit or digest")
    if not all(cells):
        return False, False
    stale = digest != ledger_digest(text)
    return not stale, stale


def load_ledger(path: Path) -> Ledger:
    """Parse the ledger. Raises OSError when unreadable and ValueError when malformed."""
    text = Path(path).read_text(encoding="utf-8")
    signed, stale = _signed(text)
    return Ledger(
        ids=frozenset(ID_ROW.findall(text)),
        banned=_block(text, "claims-banned"),
        triggers=_block(text, "claims-triggers"),
        exclude=_block(text, "claims-exclude"),
        signed=signed,
        unconfirmed=_unconfirmed(text),
        stale=stale,
    )


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    # "banned", "unledgered", "unknown_id", "unclosed_fence", "unreadable", or at the sign gate
    # "unsigned", "unconfirmed" and "no_claims".
    kind: str
    text: str


SCANNED = frozenset({".md", ".txt", ".html", ".js", ".css", ".py", ".rego", ".yaml", ".yml", ".json", ".sh", ".ps1"})
MARKER = re.compile(r"claim:([A-Za-z]+-\d+)")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
HEADING = re.compile(r"^\s{0,3}#{1,6}\s")
TABLE_ROW = re.compile(r"^\s*\|")
LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
SNIFF_BYTES = 8192
SNIPPET_CHARS = 100
DASHES = dict.fromkeys(list(range(0x2010, 0x2016)) + [0x2212], "-")
QUOTES = {0x2018: "'", 0x2019: "'"}
MARKUP = dict.fromkeys(map(ord, "*_`~"))


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


def _normalize(text: str) -> str:
    """The copy phrases and triggers are matched against, so markup and look-alike characters can't hide one.

    Markers are read from the raw text, because the author typed them on purpose.
    """
    text = html.unescape(text)
    text = LINK.sub(r"\1", text)
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    text = text.translate(DASHES).translate(QUOTES).translate(MARKUP)
    return " ".join(text.split())


def _phrase_regex(phrases: tuple[str, ...], *, whole_word: bool) -> re.Pattern[str]:
    """One alternation, case-insensitive, left boundary always. Banned phrases also stop at a word end."""
    parts = [re.escape(_normalize(p)).replace(r"\ ", r"\s+") for p in phrases]
    tail = r"(?!\w)" if whole_word else ""
    return re.compile(r"(?<!\w)(?:" + "|".join(parts) + ")" + tail, re.I)


def _units(text: str, markdown: bool) -> tuple[list[tuple[int, str, bool]], int | None]:
    """Return the (first line, text, in_fence) units and the line of a fence left open, if any.

    Markdown paragraphs join wrapped lines with single spaces. A list item, a table row and a heading are each
    their own unit, so one marker clears only the unit it sits in.
    """
    lines = text.splitlines()
    if not markdown:
        return [(n, line, False) for n, line in enumerate(lines, 1)], None
    units: list[tuple[int, str, bool]] = []
    para: list[str] = []
    start = 0
    fence: str | None = None
    fence_line = 0

    def flush() -> None:
        nonlocal para
        if para:
            units.append((start, " ".join(para), False))
            para = []

    for n, line in enumerate(lines, 1):
        opener = FENCE.match(line)
        if fence is None and opener:
            flush()
            fence, fence_line = opener.group(1)[0], n
        elif fence is not None:
            # Only the same fence character closes it, so a ~~~ block can hold a ``` line.
            if opener and opener.group(1)[0] == fence:
                fence = None
            else:
                units.append((n, line, True))
        elif not line.strip():
            flush()
        elif HEADING.match(line) or TABLE_ROW.match(line):
            flush()
            units.append((n, line.strip(), False))
        elif LIST_ITEM.match(line):
            flush()
            start = n
            para.append(line.strip())
        else:
            if not para:
                start = n
            para.append(line.strip())
    flush()
    return units, (fence_line if fence is not None else None)


def _check(unit: str, in_fence: bool, ledger: Ledger, banned: re.Pattern[str], triggers: re.Pattern[str]) -> list[tuple[str, str]]:
    markers = MARKER.findall(unit)
    valid = [m for m in markers if m in ledger.ids]
    found = [("unknown_id", f"claim:{m}") for m in markers if m not in ledger.ids]
    seen = _normalize(unit)
    # Only a Not claimed marker excuses a banned phrase, because a banned phrase asserted under a claim row is the defect.
    if banned.search(seen) and not any(m.startswith("N-") for m in valid):
        found.append(("banned", unit))
    elif not in_fence and triggers.search(seen) and not valid:
        found.append(("unledgered", unit))
    return found


def _scan(root: Path, ledger: Ledger, ledger_path: Path | None) -> tuple[list[Finding], int]:
    root = Path(root)
    excluded = [_glob_regex(g) for g in ledger.exclude]
    skip = ledger_path.resolve() if ledger_path else None
    banned = _phrase_regex(ledger.banned, whole_word=True)
    triggers = _phrase_regex(ledger.triggers, whole_word=False)
    findings: list[Finding] = []
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if path.suffix.lower() not in SCANNED:
                continue
            try:
                # lstat, so a symlink or a FIFO is skipped before anything opens it. Opening a FIFO blocks forever.
                if not stat.S_ISREG(path.lstat().st_mode):
                    continue
            except OSError as e:
                findings.append(Finding(rel, 0, "unreadable", escape_text(str(e))))
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
            scanned += 1
            text = raw.decode("utf-8", errors="replace")
            units, open_fence = _units(text, path.suffix.lower() == ".md")
            for line, unit, in_fence in units:
                for kind, shown in _check(unit, in_fence, ledger, banned, triggers):
                    findings.append(Finding(rel, line, kind, escape_text(shown.strip()[:SNIPPET_CHARS])))
            if open_fence is not None:
                # Everything after an unclosed fence is exempt from triggers, so the fence itself is the defect.
                findings.append(Finding(rel, open_fence, "unclosed_fence", "a code fence is never closed"))
    return findings, scanned


def scan(root: Path, ledger: Ledger, ledger_path: Path | None = None) -> list[Finding]:
    """Scan every text file under root. Symlinks and other non-regular files are skipped, and so is the ledger."""
    return _scan(root, ledger, ledger_path)[0]


def main(argv: list[str] | None = None) -> int:
    """Exit 0 clean, 1 findings, 2 the ledger or the path can't be read.

    --require-signed also fails on a sign-off row that is empty or stale, on each claim row still marked
    Unconfirmed or holding empty or placeholder evidence, and on a ledger with no claim rows.
    """
    parser = argparse.ArgumentParser(prog="lab_claims", description="Hold lab text to the claims ledger.")
    parser.add_argument("path", nargs="?", help="directory to scan, default the directory holding the ledger")
    parser.add_argument("--ledger", help="ledger file, default CLAIMS.md beside the cli directory")
    parser.add_argument("--require-signed", action="store_true",
                        help="fail while the sign-off is empty or stale or any claim row is unconfirmed")
    parser.add_argument("--digest", action="store_true", help="print the digest the sign-off row records, then exit")
    args = parser.parse_args(argv)
    ledger_path = Path(args.ledger) if args.ledger else Path(__file__).resolve().parents[1] / "CLAIMS.md"
    try:
        if args.digest:
            print(ledger_digest(ledger_path.read_text(encoding="utf-8")))
            return 0
        ledger = load_ledger(ledger_path)
    except (OSError, ValueError) as e:
        print(f"ERROR: can't use the ledger {ledger_path}: {escape_text(str(e))}", file=sys.stderr)
        return 2
    root = Path(args.path) if args.path else ledger_path.parent
    if not root.is_dir():
        print(f"ERROR: {escape_text(str(root))} isn't a readable directory", file=sys.stderr)
        return 2
    findings, scanned = _scan(root, ledger, ledger_path)
    if args.require_signed:
        if not ledger.signed:
            why = "the ledger changed after it was signed" if ledger.stale else "the sign-off row is empty"
            findings.append(Finding(ledger_path.name, 0, "unsigned", why))
        if not any(i.startswith("C-") for i in ledger.ids):
            findings.append(Finding(ledger_path.name, 0, "no_claims", "the ledger holds no claim rows"))
        # Signing a ledger that says a row can't be confirmed would sign a claim nobody checked.
        findings += [Finding(ledger_path.name, 0, "unconfirmed", row) for row in ledger.unconfirmed]
    if findings:
        for f in findings:
            print(f"NOT YET: {f.path}:{f.line} {f.kind} {f.text}")
        return 1
    print(f"DONE: lab text holds to the ledger ({scanned} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
