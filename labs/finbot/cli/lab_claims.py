"""Holds the FinBot lab's text to its claims ledger (issue #587, LAB-14).

Version 1.9.0. Owner: ACS lab maintainers.

The ledger (CLAIMS.md) is Markdown for people with four fenced machine blocks. This module parses it and
scans a tree. It loads by path, so the root test suite and the lab wrapper can both run it. Markdown is rendered
with markdown-it-py, a CommonMark parser, because GitHub follows CommonMark plus GFM. Without it the check refuses.
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
import urllib.parse
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path

# Up to three spaces may lead a table row, as in CommonMark, so an indented row is still read.
# The leading pipe is optional, as in GFM, so a row written without one is still a row.
ID_ROW = re.compile(r"^ {0,3}\|?\s*([CN]-\d{2})\s*\|", re.M)
ROW_LINE = re.compile(r" {0,3}\|?\s*[CN]-\d{2}\s*\|")
FENCE_LINE = re.compile(r" {0,3}(`{3,}|~{3,})")
SIGN_HEADING = re.compile(r"^## Sign-off$", re.M)
SIGN_HEADER = "| Signed by | Date | Commit | Ledger sha256 |"
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
# Any fence form a reader would see as a block: backticks or tildes, three or more, indented up to three spaces.
# Only the plain ``` form is parsed, so every other form counts as a second block or a block below the sign-off.
BLOCK_OPEN = re.compile(r"^ {0,3}(?:`{3,}|~{3,})\s*(claims-[a-z-]+)\s*$", re.M)
# An evidence cell that opens with one of these, once punctuation and link syntax are gone, says the work is still
# to do.
PLACEHOLDER_LEAD = ("tbd", "tba", "tbc", "todo", "pending", "not yet", "to be confirmed", "to be determined")
# An evidence cell that is only one of these says nothing was checked.
PLACEHOLDER_WORDS = frozenset({"n a", "na", "none"})
# A backticked token in an Evidence cell that names a file or directory in the repository: a relative path, at any
# depth, ending in a slash or a known file suffix. A token like ACS_RESPONSE_SIGNING names no path. A token that holds
# a slash but is neither, such as acs-lab-keys/1, is skipped, and the sign gate says so.
EVIDENCE_TOKEN = re.compile(r"`([^`]+)`")
# A line number, a line range or an anchor after a cited path points into the file, so it goes before the check.
EVIDENCE_POINTER = re.compile(r"(?::\d+(?:-\d+)?|#[^/]*)$")
# A retired row keeps its id, and its claim cell holds only the date of the ruling that retired it, as
# "Retired 2026-11-22." (Rock, 2026-11-22). Nothing else may share the cell, so no claim rides on a retired id.
RETIRED = re.compile(r"Retired \d{4}-\d{2}-\d{2}\.")
# A space may sit inside a part, as in docs/my file.md, but never at either end of one.
CLEAN_PATH = re.compile(r"[A-Za-z0-9_.@+~-](?:[A-Za-z0-9_.@+~ -]*[A-Za-z0-9_.@+~-])?"
                        r"(?:/[A-Za-z0-9_.@+~-](?:[A-Za-z0-9_.@+~ -]*[A-Za-z0-9_.@+~-])?)*/?")
PATH_SUFFIXES = frozenset({".py", ".md", ".json", ".txt", ".toml", ".yml", ".yaml", ".lock", ".rego", ".sh", ".js",
                           ".html", ".css", ".go", ".mod", ".sum", ".ts", ".tsx", ".mjs", ".rs", ".ini", ".cfg",
                           ".proto", ".xml", ".csv"})
# Evidence paths resolve against the repository holding this file (labs/finbot/cli/lab_claims.py).
REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class Ledger:
    ids: frozenset[str]
    banned: tuple[str, ...]
    triggers: tuple[str, ...]
    exclude: tuple[str, ...]
    signed: bool
    # Claim rows the sign gate refuses: Unconfirmed in any case anywhere in the row, or empty or placeholder evidence.
    unconfirmed: tuple[str, ...] = ()
    # Rows whose claim cell reads only "Retired YYYY-MM-DD.". A marker naming one backs nothing.
    retired: tuple[str, ...] = ()
    # The sign-off row is filled in but its digest no longer matches the ledger text above it.
    stale: bool = False
    # (Not claimed id, the banned phrases that row excuses), from the claims-not-claimed block.
    excuses: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # (claim id, repository path) for each path a claim row's evidence cites before any Unconfirmed note.
    evidence: tuple[tuple[str, str], ...] = ()
    # (claim id, token) for each backticked token with a slash that the gate doesn't read as a path.
    skipped: tuple[tuple[str, str], ...] = ()


def _cells(line: str) -> list[str]:
    """Split a Markdown table row on pipes that aren't escaped, and unescape the cells."""
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|") and not line.endswith("\\|"):
        line = line[:-1]
    return [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", line)]


def _block(text: str, tag: str) -> tuple[str, ...]:
    # A second block of the same kind, even one hidden in a comment, would leave a reader unsure which one binds.
    if sum(1 for m in BLOCK_OPEN.finditer(text) if m.group(1) == tag) > 1:
        raise ValueError(f"the ledger holds more than one {tag} block")
    match = re.search(rf"^```{tag}\n(.*?)^```", text, re.S | re.M)
    if not match:
        raise ValueError(f"the ledger has no {tag} block")
    lines = tuple(ln.strip() for ln in match.group(1).splitlines() if ln.strip())
    if not lines:
        raise ValueError(f"the ledger's {tag} block is empty")
    return lines


def _retired(text: str) -> frozenset[str]:
    """Claim and Not claimed rows whose claim cell reads exactly "Retired YYYY-MM-DD.". The id stays so nothing
    renumbers. A cell that opens with "retired" in any case but holds anything else is refused, so a retired label
    can never sit beside a live claim (review round 4, I3)."""
    found = set()
    for line in text.splitlines():
        cells = _cells(line) if ROW_LINE.match(line) else []
        if len(cells) < 2 or not re.fullmatch(r"[CN]-\d{2}", cells[0]):
            continue
        shown = _cell_text(cells[1])
        if RETIRED.fullmatch(shown):
            found.add(cells[0])
        elif shown.lower().startswith("retired"):
            raise ValueError(f"{cells[0]} looks retired, so its claim cell must read exactly "
                             f"'Retired YYYY-MM-DD.', got {shown!r}")
    return frozenset(found)


def _excuses(text: str, ids: frozenset[str], banned: tuple[str, ...]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Parse the claims-not-claimed block. Every Not claimed row but a retired one needs a line, and each phrase must
    be banned.

    A marker excuses only the phrases its own row names, so one N marker can't carry a different banned phrase.
    """
    known = {_key(b) for b in banned}
    retired = _retired(text)
    rows: dict[str, tuple[str, ...]] = {}
    for line in _block(text, "claims-not-claimed"):
        row, _, rest = line.partition(":")
        phrases = tuple(p.strip() for p in rest.split("|") if p.strip())
        if row in retired:
            # A retired row says nothing, so it can't excuse a phrase. Its phrases stay banned with no excuse left.
            raise ValueError(f"claims-not-claimed line {line!r} names {row}, which is retired")
        if row not in ids or not row.startswith("N-") or row in rows or not phrases:
            raise ValueError(f"claims-not-claimed line {line!r} doesn't name a Not claimed row and its phrases")
        for phrase in phrases:
            if _key(phrase) not in known:
                raise ValueError(f"{row} excuses {phrase!r}, which isn't on the banned list")
        rows[row] = phrases
    missing = sorted(i for i in ids if i.startswith("N-") and i not in rows and i not in retired)
    if missing:
        raise ValueError(f"Not claimed rows with no phrase line: {missing}")
    return tuple(sorted(rows.items()))


def _split(text: str) -> tuple[str, str]:
    """The ledger text above the sign-off heading, and the sign-off section itself."""
    headings = list(SIGN_HEADING.finditer(text))
    if len(headings) != 1:
        raise ValueError("the ledger must hold exactly one '## Sign-off' section")
    return text[:headings[0].start()], text[headings[0].start():]


def ledger_digest(text: str) -> str:
    """The sha256 of the ledger text above the sign-off section.

    The sign-off row records it, so an edit made without recomputing it leaves the row stale and reads as unsigned.
    The digest has no key, so an edit with a recomputed digest passes, and only a reader catches that.
    """
    return hashlib.sha256(_split(text)[0].encode("utf-8")).hexdigest()


def _cell_text(cell: str) -> str:
    """A ledger cell as a reader sees it: entities decoded, emphasis and code marks dropped, characters folded."""
    return _fold(html.unescape(TAG.sub("", cell)).translate(MARKUP))


def _placeholder(evidence: str) -> bool:
    """True for evidence with no letter or digit, or one that is or opens with a placeholder word."""
    bare = " ".join(re.sub(r"[\W_]+", " ", LINK.sub(r"\1", evidence).lower()).split())
    if not bare:
        return True
    return bare in PLACEHOLDER_WORDS or any(bare == w or bare.startswith(w + " ") for w in PLACEHOLDER_LEAD)


def _unconfirmed(text: str) -> tuple[str, ...]:
    """Claim rows the sign gate refuses.

    Unconfirmed matches in any case anywhere in the row, because a row can open with the evidence that exists and
    name the gap later. An empty or placeholder evidence cell is refused too, since it says nothing was checked. A
    retired row is neither confirmed nor unconfirmed. The gate names it on a line of its own.
    """
    retired = _retired(text)
    rows = []
    for line in text.splitlines():
        cells = _cells(line) if ROW_LINE.match(line) else []
        if len(cells) >= 3 and re.fullmatch(r"C-\d{2}", cells[0]) and cells[0] not in retired:
            # The gate reads cells as a reader sees them, so an entity or emphasis can't hide a word from it.
            shown = [_cell_text(c) for c in cells]
            if "unconfirmed" in " ".join(shown).lower() or _placeholder(shown[2]):
                rows.append(cells[0])
    return tuple(rows)


def _evidence(text: str) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]:
    """The repository paths each claim row's evidence cites, and the slash-holding tokens it skips.

    Text after Unconfirmed names what this tree can't show yet, so its paths aren't required to exist. Once the row
    is confirmed, every path it cites must.
    """
    paths, skipped = [], []
    for line in text.splitlines():
        cells = _cells(line) if ROW_LINE.match(line) else []
        if len(cells) >= 3 and re.fullmatch(r"C-\d{2}", cells[0]):
            cited = re.split(r"unconfirmed", cells[2], maxsplit=1, flags=re.I)[0]
            for token in EVIDENCE_TOKEN.findall(cited):
                path = EVIDENCE_POINTER.sub("", token)
                if CLEAN_PATH.fullmatch(path) and (path.endswith("/") or Path(path).suffix.lower() in PATH_SUFFIXES):
                    paths.append((cells[0], path))
                elif "/" in token or Path(path).suffix.lower() in PATH_SUFFIXES:
                    skipped.append((cells[0], token))
    return tuple(paths), tuple(skipped)


def _exists_exact(root: Path, path: str) -> bool:
    """True when path names an entry under root with every part spelled exactly, case included.

    Each part is compared with its directory's listing, because a case-folding filesystem such as macOS's default
    would answer exists() for a wrong-case path that git and a Linux checkout don't hold.
    """
    here = Path(root)
    for part in path.rstrip("/").split("/"):
        try:
            if part in (".", "..") or part not in os.listdir(here):
                return False
        except OSError:
            return False
        here = here / part
    return here.is_dir() if path.endswith("/") else True


def missing_evidence(ledger: Ledger, root: Path = REPO_ROOT) -> list[tuple[str, str]]:
    """Cited evidence paths that don't exist under root, spelled exactly. A path that climbs out counts as missing."""
    return [(row, path) for row, path in ledger.evidence if not _exists_exact(root, path)]


def _unfenced(text: str) -> str:
    """The ledger text with fenced blocks blanked, so a table row shown in an example never becomes a claim row."""
    out, fence = [], None
    for line in text.split("\n"):
        opener = FENCE_LINE.match(line)
        if fence is None and opener:
            fence = opener.group(1)
            out.append("")
        elif fence is not None:
            if opener and opener.group(1)[0] == fence[0] and len(opener.group(1)) >= len(fence) \
                    and not line[opener.end():].strip():
                fence = None
            out.append("")
        else:
            out.append(line)
    return "\n".join(out)


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
    above, below = _split(text)
    # Everything the check reads comes from above the sign-off, the part the digest covers. A row or block below
    # it would change the check without changing the digest.
    if ID_ROW.search(below) or BLOCK_OPEN.search(below):
        raise ValueError("the ledger holds a claim row or a machine block below '## Sign-off'")
    signed, stale = _signed(text)
    rows = _unfenced(above)
    found = ID_ROW.findall(rows)
    duplicates = sorted({i for i in found if found.count(i) > 1})
    if duplicates:
        raise ValueError(f"the ledger repeats the ids {duplicates}")
    ids = frozenset(found)
    banned = _block(above, "claims-banned")
    evidence, skipped = _evidence(_unfenced(above))
    return Ledger(
        ids=ids,
        banned=banned,
        triggers=_block(above, "claims-triggers"),
        exclude=_block(above, "claims-exclude"),
        signed=signed,
        unconfirmed=_unconfirmed(rows),
        retired=tuple(sorted(_retired(rows))),
        stale=stale,
        excuses=_excuses(above, ids, banned),
        evidence=evidence,
        skipped=skipped,
    )


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    # "banned", "unledgered", "unknown_id", "retired_id", "unreadable", or at the sign gate
    # "unsigned", "unconfirmed", "missing_evidence" and "no_claims".
    kind: str
    text: str


# The one allowlist of scanned file types: prose an attendee reads. Code comments and identifiers make no claim to
# attendees, so code is never scanned, and neither are test directories (the ledger's exclusion list names them).
# Each prose suffix belongs to exactly one reader. Routing uses these sets in every place, so a new spelling can't be
# rendered one way and matched another.
MARKDOWN_SUFFIXES = frozenset({".md", ".markdown"})
HTML_SUFFIXES = frozenset({".html", ".htm"})
# GitHub shows these as prose too, but the check has no renderer for them, so they are read as plain text, one line
# at a time, like a .txt file. So is a README with no suffix.
PLAIN_SUFFIXES = frozenset({".txt", ".rst", ".adoc", ".mdx"})
SCANNED = MARKDOWN_SUFFIXES | HTML_SUFFIXES | {".txt"}


def _reader(path: Path) -> str | None:
    """The suffix whose reader scans this file, or None for a file that isn't prose."""
    suffix = path.suffix.lower()
    if suffix in MARKDOWN_SUFFIXES | HTML_SUFFIXES:
        return suffix
    if suffix in PLAIN_SUFFIXES or path.name.upper() == "README":
        return ".txt"
    return None
COMMENT = re.compile(r"<!--(.*?)-->", re.S)
MARKER = re.compile(r"claim:([A-Za-z]+-\d+)")
TAG = re.compile(r"</?[A-Za-z][^>]*>")
LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
SNIFF_BYTES = 8192
# A prose file larger than this is named and fails the run, rather than read whole and walked line by line.
MAX_BYTES = 4 * 1024 * 1024
# Byte order marks, longest first, since the UTF-32 little-endian mark begins with the UTF-16 one.
BOMS = ((b"\xff\xfe\x00\x00", "utf-32-le"), (b"\x00\x00\xfe\xff", "utf-32-be"), (b"\xef\xbb\xbf", "utf-8"),
        (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"))
# Skips that fail the run on their own: a prose file the check can't read as text. Every other skip (a symlink, which
# is never followed, a file that isn't regular, a directory it can't list) is named, and fails only the sign gate.
FATAL_SKIPS = frozenset({"undecodable", "too_large"})
# Rendered Markdown units are searched for their source line this many lines ahead of the last one, so the pointer
# stays linear on text, such as entities, whose rendered letters never appear in the source.
SOURCE_WINDOW = 200
RENDERER_MISSING = "markdown-it-py must be installed, or Markdown files can't be checked"
# Printed once under any unledgered finding, so an author knows where a marker counts.
MARKER_HINT = ("A claim marker such as <!-- claim:C-03 --> goes in the same paragraph, list item, table row or "
               "heading as the claim, before or after the sentence on the same line.")
SNIPPET_CHARS = 100
DASHES = dict.fromkeys(list(range(0x2010, 0x2016)) + [0x2212], "-")
QUOTES = {0x2018: "'", 0x2019: "'", 0x201A: "'", 0x201B: "'", 0x02BC: "'", 0x2032: "'",
          0x201C: '"', 0x201D: '"', 0x201E: '"'}
# Tildes go, because ~~text~~ left as text in raw HTML or a plain-text file is struck text to a reader.
JOINERS = {ord("~"): None}
# An underscore between two letters or digits is part of the word, as in an identifier such as keyring_verified, so
# no trigger starts inside it. Any other underscore, such as an emphasis mark left as text, reads as a space.
EDGE_UNDERSCORE = re.compile(r"(?<![^\W_])_|_(?![^\W_])")
# Emphasis and code marks. An underscore isn't here, because EDGE_UNDERSCORE decides it.
MARKUP = dict.fromkeys(map(ord, "*`~"))
# Rendered Markdown marks each source line break inside a paragraph, heading or table row with this private-use
# character, so a marker binds only to the sentences on its own line.
LINE = "\ue000"
# A sentence ends at ., ! or ? and any run of closing quotes or brackets, followed by whitespace or a line break. The
# split falls at the start of group 1, after the closers, so reads "verified." ends where a reader sees it end.
SENTENCE_END = re.compile("[.!?][\"'\u201d\u2019)\\]}]*([\\s\ue000]+)")
# Line ends an editor shows as a new line. Each becomes \n before any reader runs, in every scanned format.
LINE_ENDS = re.compile("\r\n?|[\u2028\u2029\u0085]")
# A line break in raw HTML or a page that the renderer hasn't marked yet.
BARE_NEWLINE = re.compile("(?<!\ue000)\n")
# Unicode Default_Ignorable_Code_Point (DerivedCoreProperties.txt, Unicode 15.1), which unicodedata doesn't expose.
# These draw nothing or nothing visible, so they are dropped before matching.
IGNORABLE = ((0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
             (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
             (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
             (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF))
# The Braille blank draws as a space but isn't default-ignorable, so it is listed on its own.
BLANKS = frozenset({0x2800})
# Each of these elements is one unit, so one marker clears only the block it sits in.
BLOCKS = frozenset(
    "address article aside blockquote body caption dd details dialog div dl dt fieldset figcaption figure footer "
    "form h1 h2 h3 h4 h5 h6 head header hgroup hr html legend li main nav ol option p pre section summary table "
    "tbody tfoot thead title tr ul center dir listing menu search xmp".split())
# Table cells and line breaks stay inside their unit but keep the words on each side apart.
SPACERS = frozenset({"td", "th", "br"})
# Script and style in a page are code, which makes no claim to attendees, so their content is skipped.
CODE_ELEMENTS = frozenset({"script", "style"})
# Attributes a reader sees. Alt text stands in for an image where it sits. A title shows on hover, so it joins the
# end of its unit rather than splitting the words around its element.
INLINE_ATTRS = frozenset({"alt"})
TRAILING_ATTRS = frozenset({"title"})

try:
    import markdown_it
except ImportError:  # The lab wrapper may run outside the root environment. main() refuses rather than skip files.
    markdown_it = None


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


def _invisible(ch: str) -> bool:
    cp = ord(ch)
    if cp in BLANKS or unicodedata.category(ch) in ("Cf", "Mn", "Me"):
        return True
    return any(lo <= cp <= hi for lo, hi in IGNORABLE)


def _fold(text: str) -> str:
    """Fold look-alike characters so a phrase matches what a reader sees.

    NFKC first, then drop every invisible code point and combining mark, map dash and quote variants, and collapse
    whitespace. This is the only character-level step. Markup is handled by rendering, never by patching here.
    """
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text.replace(LINE, " ") if not _invisible(ch))
    text = EDGE_UNDERSCORE.sub(" ", text).translate(DASHES).translate(QUOTES).translate(JOINERS)
    return " ".join(text.split())


def _key(phrase: str) -> str:
    """A phrase reduced to compare a match with an excuse, whatever whitespace the match spanned."""
    return re.sub(r"\s+", "", _fold(phrase).lower())


def _normalize(text: str) -> str:
    """The matching copy of a line in a plain-text file.

    Plain text has no renderer, so its tags, entities, links and emphasis marks are stripped from the line itself.
    """
    text = text.replace("<!--", " ").replace("-->", " ")
    text = TAG.sub("", text)
    text = html.unescape(text)
    text = LINK.sub(r"\1", text)
    return _fold(text.translate(MARKUP))


def _phrase_regex(phrases: tuple[str, ...], *, whole_word: bool) -> re.Pattern[str]:
    """One alternation, case-insensitive, left boundary always. Banned phrases also stop at a word end.

    Spaces in a phrase match any whitespace or none, and punctuation may carry whitespace on either side, because
    dropping an invisible character or splitting a table cell can glue words or pull them apart.
    """
    parts = []
    for phrase in phrases:
        out = []
        for ch in _fold(phrase):
            if ch.isspace():
                out.append(r"\s*")
            elif ch.isalnum():
                out.append(re.escape(ch))
            else:
                out.append(r"\s*" + re.escape(ch) + r"\s*")
        parts.append("".join(out))
    tail = r"(?!\w)" if whole_word else ""
    return re.compile(r"(?<!\w)(?:" + "|".join(parts) + ")" + tail, re.I)


@dataclass
class Unit:
    line: int
    text: str
    markers: tuple[str, ...]
    # Code blocks hold commands, so triggers don't apply there. Banned phrases still do.
    code: bool
    # (offset in text, id, whole) for each marker, so it binds to the sentences on its own line. whole is set for a
    # marker alone in a table cell, which binds its row.
    marks: tuple[tuple[int, str, bool], ...] = ()
    # (start, end) of each comment's text, which is matched but doesn't start or end a sentence.
    comments: tuple[tuple[int, int], ...] = ()


class _Walker(HTMLParser):
    """Split HTML into units of visible text, reading markers only from real comment nodes."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.units: list[Unit] = []
        self._text: list[str] = []
        self._markers: list[str] = []
        self._marks: list[tuple[int, str, bool]] = []
        self._comments: list[tuple[int, int]] = []
        # (offset, marks so far) where the open table cell starts.
        self._cell: tuple[int, int] | None = None
        self._trailing: list[str] = []
        self._line = 0
        self._code = 0
        self._in_code_element = False

    def _add(self, text: str) -> None:
        if not self._line and text.strip():
            lead = text[: len(text) - len(text.lstrip())]
            self._line = self.getpos()[0] + lead.count("\n")
        # Each source line break carries LINE, in a page and in raw HTML as in rendered Markdown, so a marker binds by
        # line everywhere.
        self._text.append(BARE_NEWLINE.sub(LINE + "\n", text))

    def _offset(self) -> int:
        return sum(map(len, self._text))

    def _flush(self) -> None:
        text = "".join(self._text + [f" {t} " for t in self._trailing])
        self._cell = None
        if text.replace(LINE, "").strip() or self._markers:
            self.units.append(Unit(self._line or self.getpos()[0], text, tuple(self._markers), self._code > 0,
                                   tuple(self._marks), tuple(self._comments)))
        self._text, self._markers, self._marks, self._comments, self._trailing = [], [], [], [], []
        self._line = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in BLOCKS:
            self._flush()
            self._code += tag == "pre"
        elif tag in SPACERS:
            self._add(" ")
        if tag in ("td", "th"):
            self._cell = (self._offset(), len(self._marks))
        if tag in CODE_ELEMENTS:
            self._flush()
            self._in_code_element = True
        for name, value in attrs:
            if name in INLINE_ATTRS and value:
                self._add(f" {value} ")
            elif name in TRAILING_ATTRS and value:
                self._trailing.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th") and self._cell:
            self._close_cell()
        if tag in BLOCKS:
            self._flush()
            self._code = max(0, self._code - (tag == "pre"))
        elif tag in SPACERS:
            self._add(" ")
        if tag in CODE_ELEMENTS:
            self._in_code_element = False

    def _close_cell(self) -> None:
        """A cell that holds nothing but markers binds its row, as a GFM row on one source line does."""
        start, first = self._cell
        self._cell = None
        text = "".join(self._text)
        for a, b in self._comments:
            if a >= start:
                text = text[:a] + " " * (b - a) + text[b:]
        if first < len(self._marks) and not text[start:].replace(LINE, "").strip():
            self._marks[first:] = [(at, i, True) for at, i, _ in self._marks[first:]]

    def handle_data(self, data: str) -> None:
        if not self._in_code_element:
            self._add(data)

    def handle_comment(self, data: str) -> None:
        # The comment's text is still matched, so a banned phrase can't hide in one.
        at = self._offset() + 1
        self._add(f" {data} ")
        # Marking line breaks in the comment changes its length, so offsets come from the text as added.
        data = self._text[-1][1:-1]
        for match in MARKER.finditer(data):
            self._markers.append(match.group(1))
            self._marks.append((at + match.start(), match.group(1), False))
        self._comments.append((at, at + len(data)))

    def close(self) -> None:
        super().close()
        self._flush()


def _walk(html_text: str) -> list[Unit]:
    walker = _Walker()
    walker.feed(html_text)
    walker.close()
    return walker.units


def _line_break(text: str) -> str:
    return text.replace("\n", LINE + "\n")


FOOTNOTE_DEF = re.compile(r" {0,3}\[\^[^\]\s]+\]:")
INDENT = re.compile(r"(?: {4}|\t)")


def _footnote_prose(source: str) -> str:
    """Unindent the paragraphs that continue a footnote, which GitHub shows as prose and CommonMark reads as code.

    A footnote runs from its [^x]: line until a line that holds text and isn't indented follows a blank line.
    """
    out: list[str] = []
    inside = continued = blank = False
    for line in source.split("\n"):
        if FOOTNOTE_DEF.match(line):
            inside, continued = True, False
        elif line.strip():
            if inside and INDENT.match(line) and (blank or continued):
                continued = True
                line = INDENT.sub("", line, count=1)
            elif blank and not INDENT.match(line):
                inside = continued = False
        blank = not line.strip()
        out.append(line)
    return "\n".join(out)


def _render(source: str) -> str:
    """Render Markdown as GitHub reads it: CommonMark with GFM tables and strikethrough, raw HTML kept, no linkify.

    Each source line break inside a paragraph, heading or table row is rendered with LINE before it, so a marker binds
    only to the sentences on its own line. Raw HTML blocks keep their own line breaks bare, so there the element is
    the unit. Line endings inside a code span are spaces in CommonMark, so a code span that wraps loses its LINE.
    """
    if markdown_it is None:
        raise RuntimeError(RENDERER_MISSING)
    md = markdown_it.MarkdownIt("commonmark", {"html": True, "linkify": False}).enable(["table", "strikethrough"])
    md.add_render_rule("softbreak", lambda self, tokens, idx, options, env: LINE + "\n")
    md.add_render_rule("hardbreak", lambda self, tokens, idx, options, env: "<br />" + LINE + "\n")
    md.add_render_rule("html_inline", lambda self, tokens, idx, options, env: _line_break(tokens[idx].content))
    # An HTML block always opens a source line, but a tight list item renders it straight after the paragraph text.
    md.add_render_rule("html_block", lambda self, tokens, idx, options, env: LINE + "\n" + tokens[idx].content)
    env: dict = {}
    rendered = md.render(_footnote_prose(source), env)
    # GitHub shows [^x]: text as a footnote. CommonMark reads a one-word body as a link reference definition, which
    # draws nothing, so each one is added back as a paragraph of its own.
    for label, ref in env.get("references", {}).items():
        if label.startswith("^"):
            body = " ".join(part for part in (urllib.parse.unquote(ref.get("href", "")), ref.get("title", "")) if part)
            rendered += f"<p>{html.escape(body)}</p>\n"
    return rendered


def _source_lines(source: str, units: list[Unit]) -> None:
    """Point each rendered Markdown unit at the source line it starts on.

    Rendering drops positions, so the line is found by the unit's first letters and digits, searched forward from
    the previous unit. A line that can't be found keeps the previous unit's line. It is a pointer for the author.
    """
    keys = [re.sub(r"[\W_]", "", _fold(ln).lower()) for ln in source.splitlines()]
    spans = [keys[i] + "".join(keys[i + 1:i + 4]) for i in range(len(keys))]
    cursor = 0
    # The previous unit's own length, so a long code block doesn't push the next unit out of the window.
    reach = SOURCE_WINDOW
    for unit in units:
        probe = re.sub(r"[\W_]", "", _fold(unit.text).lower())[:12]
        found = None
        for anchored in (True, False):
            for i in range(cursor, min(len(keys), cursor + reach)):
                if not keys[i]:
                    continue
                at = spans[i].find(probe)
                if (at == 0) if anchored else (0 <= at < len(keys[i])):
                    found = i
                    break
            if found is not None or not probe:
                break
        if found is not None:
            cursor = found
        unit.line = cursor + 1
        reach = SOURCE_WINDOW + unit.text.count("\n")


def _units(text: str, suffix: str) -> list[Unit]:
    """Markdown is rendered and HTML is parsed, so each block is a unit. Plain text is one unit per line."""
    text = LINE_ENDS.sub("\n", text)
    if suffix in MARKDOWN_SUFFIXES:
        # LINE is the renderer's own mark, so a literal one in the source can't fake a line break.
        units = _walk(_render(text.replace(LINE, "")))
        _source_lines(text, units)
        return units
    if suffix in HTML_SUFFIXES:
        return _walk(text)
    return [Unit(n, line, tuple(m for c in COMMENT.findall(line) for m in MARKER.findall(c)), False)
            for n, line in enumerate(text.splitlines(), 1)]


def _seen(text: str, suffix: str) -> str:
    """The matching copy of a unit, by the reader its suffix names.

    Rendered Markdown can still hold emphasis and code marks as text inside raw HTML, which CommonMark leaves
    unrendered, so those marks are dropped too. Underscores follow EDGE_UNDERSCORE in every reader.
    """
    if suffix in MARKDOWN_SUFFIXES:
        return _fold(text.translate(MARKUP))
    if suffix in HTML_SUFFIXES:
        return _fold(text)
    return _normalize(text)


def _sentences(unit: Unit) -> list[tuple[str, tuple[str, ...]]]:
    """Each sentence of a unit with the markers bound to it.

    A marker binds to every sentence that touches its own source line, before or after it, and never to a sentence
    on another line. A marker alone on its line binds the next line that holds text, and a marker alone in a table
    cell binds its whole row. Plain-text units are one line each, so they stay whole.
    """
    if LINE not in unit.text or not unit.marks:
        return [(unit.text, unit.markers)]
    # Comment text is blanked for splitting, so a marker after a sentence's end doesn't open the next sentence.
    mask = unit.text
    for a, b in unit.comments:
        mask = mask[:a] + re.sub(r"[^\ue000]", " ", mask[a:b]) + mask[b:]
    # Invisible characters draw nothing, so they can't hide a sentence end or a line break from the binder. Each is
    # blanked in place, which keeps every offset.
    mask = "".join(" " if _invisible(ch) else ch for ch in mask)
    lines = mask.split(LINE)
    bound: list[tuple[int | None, str]] = []
    for at, ident, whole in unit.marks:
        line = unit.text.count(LINE, 0, at)
        if not whole and not lines[line].strip():
            line = next((n for n in range(line + 1, len(lines)) if lines[n].strip()), line)
        bound.append((None if whole else line, ident))
    out = []
    start = 0
    for end in [m.start(1) for m in SENTENCE_END.finditer(mask)] + [len(mask)]:
        piece = mask[start:end]
        # The same whitespace SENTENCE_END matches, so a no-break space after a period can't hide the line break.
        lead = re.match("[\\s\ue000]*", piece).end()
        first = unit.text.count(LINE, 0, start + lead)
        last = unit.text.count(LINE, 0, end)
        out.append((unit.text[start:end], tuple(i for line, i in bound if line is None or first <= line <= last)))
        start = end
    return out


def _check(unit: Unit, suffix: str, ledger: Ledger, banned: re.Pattern[str], triggers: re.Pattern[str],
           excused: dict[str, frozenset[str]]) -> list[tuple[str, str]]:
    found = [("unknown_id", f"claim:{m}") for m in unit.markers if m not in ledger.ids]
    # A retired id stays in the ledger so nothing renumbers, but it backs no claim, so its marker is a finding and
    # never clears a trigger or a banned phrase (review round 4, I2).
    found += [("retired_id", f"claim:{m}") for m in unit.markers if m in ledger.retired]
    # kind -> the first sentence that earns it. A unit gets one claim finding, banned first.
    kinds: dict[str, str] = {}
    pieces = _sentences(unit)
    # The finding quotes the text a reader sees, never a marker comment, which would read as if it marked that text.
    plain = unit.text
    for a, b in unit.comments:
        if MARKER.search(plain[a:b]):
            plain = plain[:a] + " " * (b - a) + plain[b:]
    if not unit.comments:
        # A plain-text line keeps its comments as written. Blanking keeps the length, so offsets still line up.
        plain = COMMENT.sub(lambda m: " " * len(m.group()) if MARKER.search(m.group(1)) else m.group(), plain)
    start = 0
    for text, markers in pieces:
        shown_piece = plain[start:start + len(text)]
        start += len(text)
        seen = _seen(text, suffix)
        valid = [m for m in markers if m in ledger.ids and m not in ledger.retired]
        # Only a Not claimed marker excuses a banned phrase, because a banned phrase asserted under a claim row is the
        # defect. It excuses only the phrases its own row names.
        allowed = frozenset().union(*(excused.get(m, frozenset()) for m in valid))
        hits = {_key(m.group()) for m in banned.finditer(seen)}
        if hits - allowed:
            # A banned phrase written inside a marker comment is quoted from the comment, never an empty quote.
            if not banned.search(_seen(shown_piece, suffix)) or not shown_piece.strip():
                shown_piece = MARKER.sub(" ", text) if MARKER.sub("", text).strip() else text
            kinds.setdefault("banned", shown_piece)
        elif not hits and not unit.code and triggers.search(seen) and not valid:
            kinds.setdefault("unledgered", shown_piece)
    if kinds:
        kind = "banned" if "banned" in kinds else "unledgered"
        # The finding shows the text as written or rendered, not the folded copy, so the author can find it. When
        # markers split a unit, it shows the sentence that needs one.
        found.append((kind, " ".join(kinds[kind].replace(LINE, "").split())))
    return found


def _decode(raw: bytes) -> str | None:
    """The text of a prose file, or None when it isn't UTF-8 and no byte order mark names its encoding."""
    for bom, codec in BOMS:
        if raw.startswith(bom):
            try:
                return raw[len(bom):].decode(codec)
            except UnicodeDecodeError:
                return None
    # Strict UTF-8 and a NUL test over the whole file (MAX_BYTES bounds it), so a Windows-1252 or UTF-16 file without
    # a mark is named rather than read as text with holes in it.
    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _scan(root: Path, ledger: Ledger, ledger_path: Path | None) -> tuple[list[Finding], int, list[Finding]]:
    """Findings, the count of files scanned, and every skip, each named with its reason."""
    root = Path(root)
    excluded = [_glob_regex(g) for g in ledger.exclude]
    skip = ledger_path.resolve() if ledger_path else None
    banned = _phrase_regex(ledger.banned, whole_word=True)
    triggers = _phrase_regex(ledger.triggers, whole_word=False)
    excused = {row: frozenset(_key(p) for p in phrases) for row, phrases in ledger.excuses}
    findings: list[Finding] = []
    skips: list[Finding] = []
    scanned = 0

    def unlisted(error: OSError) -> None:
        rel = Path(error.filename).relative_to(root).as_posix() if error.filename else "."
        skips.append(Finding(rel, 0, "unlistable", escape_text(f"can't list the directory: {error.strerror}")))

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=unlisted):
        dirnames.sort()
        for name in list(dirnames):
            rel = (Path(dirpath) / name).relative_to(root).as_posix()
            if any(rx.match(rel + "/") for rx in excluded):
                # The ledger excludes it, so the walk never enters it, and nothing under it can fail the gate.
                dirnames.remove(name)
            elif (Path(dirpath) / name).is_symlink():
                skips.append(Finding(rel, 0, "symlink", "a directory symlink, never followed"))
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            suffix = _reader(path)
            if suffix is None:
                continue
            if any(rx.match(rel) for rx in excluded):
                continue
            try:
                # lstat, so a symlink or a FIFO is skipped before anything opens it. Opening a FIFO blocks forever.
                info = path.lstat()
            except OSError as e:
                findings.append(Finding(rel, 0, "unreadable", escape_text(str(e))))
                continue
            if stat.S_ISLNK(info.st_mode):
                skips.append(Finding(rel, 0, "symlink", "a symlink, never followed"))
                continue
            if not stat.S_ISREG(info.st_mode):
                skips.append(Finding(rel, 0, "not_regular", "not a regular file"))
                continue
            if skip and path.resolve() == skip:
                continue
            if info.st_size > MAX_BYTES:
                skips.append(Finding(rel, 0, "too_large", f"larger than {MAX_BYTES} bytes"))
                continue
            try:
                raw = path.read_bytes()
            except OSError as e:
                findings.append(Finding(rel, 0, "unreadable", escape_text(str(e))))
                continue
            text = _decode(raw)
            if text is None:
                skips.append(Finding(rel, 0, "undecodable", "not UTF-8 text, and no byte order mark names another"))
                continue
            scanned += 1
            for unit in _units(text, suffix):
                for kind, shown in _check(unit, suffix, ledger, banned, triggers, excused):
                    findings.append(Finding(rel, unit.line, kind, escape_text(shown.strip()[:SNIPPET_CHARS])))
    return findings, scanned, skips


def scan(root: Path, ledger: Ledger, ledger_path: Path | None = None) -> list[Finding]:
    """Scan every text file under root. Symlinks and other non-regular files are skipped, and so is the ledger."""
    return _scan(root, ledger, ledger_path)[0]


def main(argv: list[str] | None = None) -> int:
    """Exit 0 clean, 1 findings, 2 the ledger or the path can't be read, a prose file can't be read as text, or the
    check stopped on an unexpected error. Every skipped file or directory is named, and under --require-signed any
    skip exits 2.

    --require-signed also fails on a sign-off row that is empty or stale, on each claim row still marked
    Unconfirmed or holding empty or placeholder evidence, on each cited evidence path the repository lacks, and on a
    ledger with no claim rows.
    """
    parser = argparse.ArgumentParser(prog="lab_claims", description="Hold lab text to the claims ledger.")
    parser.add_argument("path", nargs="?", help="directory to scan, default the directory holding the ledger")
    parser.add_argument("--ledger", help="ledger file, default CLAIMS.md beside the cli directory")
    parser.add_argument("--require-signed", action="store_true",
                        help="fail while the sign-off is empty or stale or any claim row is unconfirmed")
    parser.add_argument("--digest", action="store_true", help="print the digest the sign-off row records, then exit")
    args = parser.parse_args(argv)
    try:
        return _run(args)
    except Exception as e:  # noqa: BLE001 - any crash must read as "can't check", never as the findings code 1.
        print(f"ERROR: the check stopped: {type(e).__name__}: {escape_text(str(e))}", file=sys.stderr)
        return 2


def _run(args: argparse.Namespace) -> int:
    """main's body after argument parsing, so a crash anywhere in it, the ledger load included, exits 2."""
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
    if markdown_it is None:
        print(f"ERROR: {RENDERER_MISSING}", file=sys.stderr)
        return 2
    return _report(root, ledger, ledger_path, args.require_signed)


def _report(root: Path, ledger: Ledger, ledger_path: Path, require_signed: bool) -> int:
    findings, scanned, skips = _scan(root, ledger, ledger_path)
    if require_signed:
        if not ledger.signed:
            why = "the ledger changed after it was signed" if ledger.stale else "the sign-off row is empty"
            findings.append(Finding(ledger_path.name, 0, "unsigned", why))
        if not any(i.startswith("C-") for i in ledger.ids):
            findings.append(Finding(ledger_path.name, 0, "no_claims", "the ledger holds no claim rows"))
        # Signing a ledger that says a row can't be confirmed would sign a claim nobody checked.
        findings += [Finding(ledger_path.name, 0, "unconfirmed", row) for row in ledger.unconfirmed]
        # Evidence that names a file the tree doesn't hold checks nothing.
        findings += [Finding(ledger_path.name, 0, "missing_evidence", f"{row} {path}")
                     for row, path in missing_evidence(ledger)]
        # A skipped token isn't a failure, but the signer should know the gate didn't check it.
        notes = [f"NOTE: {ledger_path.name}:0 skipped {row} {token}, not a path the sign gate checks"
                 for row, token in ledger.skipped]
        # A retired row is neither confirmed nor unconfirmed, so the signer sees each one by name.
        notes += [f"NOTE: {ledger_path.name}:0 retired {row}, which claims nothing" for row in ledger.retired]
    else:
        notes = []
    for f in findings:
        print(f"NOT YET: {f.path}:{f.line} {f.kind} {f.text}")
    if any(f.kind == "unledgered" for f in findings):
        print(MARKER_HINT)
    # An unlistable scan root means nothing was read, so it fails like a root that doesn't exist.
    stop = any(f.kind in FATAL_SKIPS or (f.kind == "unlistable" and f.path == ".") for f in skips) \
        or (require_signed and bool(skips))
    if not findings and not stop:
        print(f"DONE: lab text holds to the ledger ({scanned} files)")
    for f in skips:
        print(f"SKIPPED: {f.path} {f.kind}: {f.text}")
    for note in notes:
        print(note)
    if stop:
        print(f"ERROR: {len(skips)} skipped, so the check can't vouch for this tree", file=sys.stderr)
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
