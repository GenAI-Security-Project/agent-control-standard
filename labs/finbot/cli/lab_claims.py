"""Holds the FinBot lab's text to its claims ledger (issue #587, LAB-14).

Version 1.3.0. Owner: ACS lab maintainers.

The ledger (CLAIMS.md) is Markdown for people with four fenced machine blocks. This module parses it and
scans a tree. It loads by path, so the root test suite and the lab wrapper can both run it. Markdown is rendered
with Python-Markdown and pymdown-extensions' superfences, which the root environment already carries through mkdocs.
Without either one the check refuses.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import os
import re
import stat
import string
import sys
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path

# Up to three spaces may lead a table row, as in CommonMark, so an indented row is still read.
ID_ROW = re.compile(r"^ {0,3}\|\s*([CN]-\d{2})\s*\|", re.M)
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
# A backticked token in an Evidence cell that names a file or directory in the repository: a relative path ending in
# a slash or a known file suffix. Tokens like acs-lab-keys/1 or ACS_RESPONSE_SIGNING name no path.
EVIDENCE_TOKEN = re.compile(r"`([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*/?)`")
PATH_SUFFIXES = frozenset({".py", ".md", ".json", ".txt", ".toml", ".yml", ".yaml", ".lock", ".rego", ".sh", ".js",
                           ".html", ".css"})
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
    # The sign-off row is filled in but its digest no longer matches the ledger text above it.
    stale: bool = False
    # (Not claimed id, the banned phrases that row excuses), from the claims-not-claimed block.
    excuses: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # (claim id, repository path) for each path a claim row's evidence cites before any Unconfirmed note.
    evidence: tuple[tuple[str, str], ...] = ()


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


def _excuses(text: str, ids: frozenset[str], banned: tuple[str, ...]) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Parse the claims-not-claimed block. Every Not claimed row needs a line, and each phrase must be banned.

    A marker excuses only the phrases its own row names, so one N marker can't carry a different banned phrase.
    """
    known = {_key(b) for b in banned}
    rows: dict[str, tuple[str, ...]] = {}
    for line in _block(text, "claims-not-claimed"):
        row, _, rest = line.partition(":")
        phrases = tuple(p.strip() for p in rest.split("|") if p.strip())
        if row not in ids or not row.startswith("N-") or row in rows or not phrases:
            raise ValueError(f"claims-not-claimed line {line!r} doesn't name a Not claimed row and its phrases")
        for phrase in phrases:
            if _key(phrase) not in known:
                raise ValueError(f"{row} excuses {phrase!r}, which isn't on the banned list")
        rows[row] = phrases
    missing = sorted(i for i in ids if i.startswith("N-") and i not in rows)
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
    name the gap later. An empty or placeholder evidence cell is refused too, since it says nothing was checked.
    """
    rows = []
    for line in text.splitlines():
        cells = _cells(line) if re.match(r" {0,3}\|", line) else []
        if len(cells) >= 3 and re.fullmatch(r"C-\d{2}", cells[0]):
            # The gate reads cells as a reader sees them, so an entity or emphasis can't hide a word from it.
            shown = [_cell_text(c) for c in cells]
            if "unconfirmed" in " ".join(shown).lower() or _placeholder(shown[2]):
                rows.append(cells[0])
    return tuple(rows)


def _evidence(text: str) -> tuple[tuple[str, str], ...]:
    """The repository paths each claim row's evidence cites.

    Text after Unconfirmed names what this tree can't show yet, so its paths aren't required to exist. Once the row
    is confirmed, every path it cites must.
    """
    paths = []
    for line in text.splitlines():
        cells = _cells(line) if re.match(r" {0,3}\|", line) else []
        if len(cells) >= 3 and re.fullmatch(r"C-\d{2}", cells[0]):
            cited = re.split(r"unconfirmed", cells[2], maxsplit=1, flags=re.I)[0]
            for token in EVIDENCE_TOKEN.findall(cited):
                if token.endswith("/") and "/" in token[:-1] or Path(token).suffix in PATH_SUFFIXES:
                    paths.append((cells[0], token))
    return tuple(paths)


def missing_evidence(ledger: Ledger, root: Path = REPO_ROOT) -> list[tuple[str, str]]:
    """Cited evidence paths that don't exist under root. A path that climbs out of root counts as missing."""
    return [(row, path) for row, path in ledger.evidence
            if ".." in Path(path).parts or not (root / path).exists()]


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
    found = ID_ROW.findall(above)
    duplicates = sorted({i for i in found if found.count(i) > 1})
    if duplicates:
        raise ValueError(f"the ledger repeats the ids {duplicates}")
    ids = frozenset(found)
    banned = _block(above, "claims-banned")
    return Ledger(
        ids=ids,
        banned=banned,
        triggers=_block(above, "claims-triggers"),
        exclude=_block(above, "claims-exclude"),
        signed=signed,
        unconfirmed=_unconfirmed(above),
        stale=stale,
        excuses=_excuses(above, ids, banned),
        evidence=_evidence(above),
    )


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    # "banned", "unledgered", "unknown_id", "unreadable", or at the sign gate
    # "unsigned", "unconfirmed", "missing_evidence" and "no_claims".
    kind: str
    text: str


# The one allowlist of scanned file types: prose an attendee reads. Code comments and identifiers make no claim to
# attendees, so code is never scanned, and neither are test directories (the ledger's exclusion list names them).
# Each prose suffix belongs to exactly one reader. Routing uses these sets in every place, so a new spelling can't be
# rendered one way and matched another.
MARKDOWN_SUFFIXES = frozenset({".md", ".markdown"})
HTML_SUFFIXES = frozenset({".html", ".htm"})
SCANNED = MARKDOWN_SUFFIXES | HTML_SUFFIXES | {".txt"}
COMMENT = re.compile(r"<!--(.*?)-->", re.S)
MARKER = re.compile(r"claim:([A-Za-z]+-\d+)")
TAG = re.compile(r"</?[A-Za-z][^>]*>")
LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
SNIFF_BYTES = 8192
RENDERER_MISSING = ("Python-Markdown and pymdown-extensions must both be installed, or Markdown files can't be "
                    "checked")
# Printed once under any unledgered finding, so an author knows where a marker counts.
MARKER_HINT = ("A claim marker such as <!-- claim:C-03 --> goes in the same paragraph, list item, table row or "
               "heading as the claim, before or after the sentence on the same line.")
SNIPPET_CHARS = 100
DASHES = dict.fromkeys(list(range(0x2010, 0x2016)) + [0x2212], "-")
QUOTES = {0x2018: "'", 0x2019: "'", 0x201A: "'", 0x201B: "'", 0x02BC: "'", 0x2032: "'",
          0x201C: '"', 0x201D: '"', 0x201E: '"'}
# Underscores read as spaces, so words joined by one in an identifier still meet a phrase. Tildes go, because GitHub
# draws ~~text~~ as struck text and Python-Markdown leaves the marks in place.
JOINERS = {ord("_"): " ", ord("~"): None}
# Emphasis and code marks. An underscore isn't here: JOINERS reads it as a space, because an intraword underscore
# isn't emphasis in CommonMark and deleting it would join window_size into one word.
MARKUP = dict.fromkeys(map(ord, "*`~"))
# Unicode Default_Ignorable_Code_Point (DerivedCoreProperties.txt, Unicode 15.1), which unicodedata doesn't expose.
# These draw nothing or nothing visible, so they are dropped before matching.
IGNORABLE = ((0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
             (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
             (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
             (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF))
# The Braille blank draws as a space but isn't default-ignorable, so it is listed on its own.
BLANKS = frozenset({0x2800})
# The Markdown extensions that change what a reader sees. Python-Markdown ships all but superfences, which comes from
# pymdown-extensions, the package mkdocs.yml already uses. superfences reads a fence inside a list item or a block
# quote as code, as GitHub does, where Python-Markdown's own fenced_code reads it as prose.
# md_in_html renders Markdown inside a raw HTML block that carries a markdown attribute, which _prepare adds.
# GitHub shows each footnote as its own item, so footnotes makes each its own unit.
MARKDOWN_EXTENSIONS = ("tables", "pymdownx.superfences", "admonition", "attr_list", "md_in_html", "footnotes")
# A block-quote prefix may lead any line.
QUOTE_PREFIX = re.compile(r"^((?: {0,3}> ?)*)")
# A fence opener at any indent. _prepare decides from the enclosing list item whether the indent makes it a fence.
FENCE_OPEN = re.compile(r"( *)(`{3,}|~{3,})")
# A list marker with text after it, at any indent. _prepare applies CommonMark's rules on top: indent, interruption.
LIST_ITEM = re.compile(r"( *)([-*+]|(\d{1,9})[.)])([ \t]+)\S")
# A claim marker comment that opens a line, after any list marker, with text following it on the same line.
LEADING_MARKER = re.compile(r"^( *(?:(?:[-*+]|\d{1,9}[.)])[ \t]+)?)(<!--(?:(?!-->).)*?claim:(?:(?!-->).)*?-->)"
                            r"[ \t]*([^\s<].*)$")
# Block-level HTML whose content GitHub renders as Markdown after a blank line.
MD_HTML_BLOCKS = ("address|article|aside|blockquote|center|dd|details|dialog|div|dl|dt|fieldset|figcaption|figure|"
                  "footer|form|header|hgroup|li|main|nav|ol|p|section|summary|table|tbody|td|th|thead|tr|ul")
HTML_OPEN = re.compile(rf"^ {{0,3}}<(?:{MD_HTML_BLOCKS})(?=[\s>])", re.I)
# Every block-level opening tag on a line that starts one, so <table><tr> on one line both render their content.
# md_in_html leaves a child raw when its parent carries no markdown attribute.
HTML_BLOCK_TAG = re.compile(rf"<({MD_HTML_BLOCKS})(?=[\s>])(?![^>]*\bmarkdown\s*=)([^>]*)>", re.I)
# Each of these elements is one unit, so one marker clears only the block it sits in.
BLOCKS = frozenset(
    "address article aside blockquote body caption dd details dialog div dl dt fieldset figcaption figure footer "
    "form h1 h2 h3 h4 h5 h6 head header hgroup hr html legend li main nav ol option p pre section summary table "
    "tbody tfoot thead title tr ul".split())
# Table cells and line breaks stay inside their unit but keep the words on each side apart.
SPACERS = frozenset({"td", "th", "br"})
# Script and style in a page are code, which makes no claim to attendees, so their content is skipped.
CODE_ELEMENTS = frozenset({"script", "style"})
# Attributes a reader sees. Alt text stands in for an image where it sits. A title shows on hover, so it joins the
# end of its unit rather than splitting the words around its element.
INLINE_ATTRS = frozenset({"alt"})
TRAILING_ATTRS = frozenset({"title"})

# Inline raw HTML as CommonMark reads it: a quoted attribute value may hold a closing angle bracket. Python-Markdown's
# own pattern ends the tag there, which leaves the rest of the tag as text and swallows the words after it.
INLINE_HTML = (r"""(<(?:/?[A-Za-z][A-Za-z0-9-]*(?:\s+[A-Za-z_:][\w.:-]*(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*"""
               r"""\s*/?|!--(?:(?!<!--|-->).)*--|[?](?:(?!<[?]|[?]>).)*[?]|!\[CDATA\[(?:(?!<!\[CDATA\[|\]\]>).)*\]\])>)""")

try:
    import markdown
    from markdown.inlinepatterns import HtmlInlineProcessor
except ImportError:  # The lab wrapper may run outside the root environment. main() refuses rather than skip files.
    markdown = None
try:
    import pymdownx.superfences as superfences
except ImportError:  # Without it a fence inside a list reads as prose. main() refuses rather than misread.
    superfences = None


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
    text = "".join(ch for ch in text if not _invisible(ch))
    text = text.translate(DASHES).translate(QUOTES).translate(JOINERS)
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


class _Walker(HTMLParser):
    """Split HTML into units of visible text, reading markers only from real comment nodes."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.units: list[Unit] = []
        self._text: list[str] = []
        self._markers: list[str] = []
        self._trailing: list[str] = []
        self._line = 0
        self._code = 0
        self._in_code_element = False

    def _add(self, text: str) -> None:
        if not self._line and text.strip():
            lead = text[: len(text) - len(text.lstrip())]
            self._line = self.getpos()[0] + lead.count("\n")
        self._text.append(text)

    def _flush(self) -> None:
        text = "".join(self._text + [f" {t} " for t in self._trailing])
        if text.strip() or self._markers:
            self.units.append(Unit(self._line or self.getpos()[0], text, tuple(self._markers), self._code > 0))
        self._text, self._markers, self._trailing, self._line = [], [], [], 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in BLOCKS:
            self._flush()
            self._code += tag == "pre"
        elif tag in SPACERS:
            self._add(" ")
        if tag in CODE_ELEMENTS:
            self._flush()
            self._in_code_element = True
        for name, value in attrs:
            if name in INLINE_ATTRS and value:
                self._add(f" {value} ")
            elif name in TRAILING_ATTRS and value:
                self._trailing.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag in BLOCKS:
            self._flush()
            self._code = max(0, self._code - (tag == "pre"))
        elif tag in SPACERS:
            self._add(" ")
        if tag in CODE_ELEMENTS:
            self._in_code_element = False

    def handle_data(self, data: str) -> None:
        if not self._in_code_element:
            self._add(data)

    def handle_comment(self, data: str) -> None:
        # The comment's text is still matched, so a banned phrase can't hide in one.
        self._markers += MARKER.findall(data)
        self._add(f" {data} ")

    def close(self) -> None:
        super().close()
        self._flush()


def _walk(html_text: str) -> list[Unit]:
    walker = _Walker()
    walker.feed(html_text)
    walker.close()
    return walker.units


def _renders_markdown(lines: list[str], i: int, tag: str) -> bool:
    """True when GitHub renders Markdown inside the raw HTML block that opens on line i.

    GitHub's HTML block runs to the first blank line, and only text after a blank line renders as Markdown. With no
    blank line before the element closes, the whole element is raw HTML, so its text stays one unit.
    """
    close = re.compile(rf"</{tag}\s*>", re.I)
    if close.search(lines[i]):
        return False
    for line in lines[i + 1:]:
        if not line[len(QUOTE_PREFIX.match(line).group(1)):].strip():
            return True
        if close.search(line):
            return False
    return False


def _prepare(source: str) -> str:
    """Pre-render steps where Python-Markdown reads differently from GitHub. Fenced code is left alone.

    Lists follow CommonMark. A marker is a list item only when it sits less than four columns past the content of the
    item that holds it. Right after paragraph text, only a bullet or 1. starts a new list, and Python-Markdown needs
    a blank line before it. Any other marker there is paragraph text, so its punctuation is escaped to keep
    Python-Markdown from starting a list. A claim marker that opens a line moves to the end of that line, so it binds
    to the sentence it is written beside. Markdown inside a raw HTML block renders on GitHub only after a blank line,
    so only then does each block-level opening tag get markdown="block" for md_in_html.
    """
    lines = source.splitlines()
    out: list[str] = []
    fence: str | None = None
    # (marker column, content column) for each open list item, outermost first.
    items: list[tuple[int, int]] = []
    # What the previous line was: blank, para (paragraph text, which a list item's own text is), or other.
    previous = "blank"
    quote = ""
    for i, line in enumerate(lines):
        prefix = QUOTE_PREFIX.match(line).group(1)
        body = line[len(prefix):]
        if fence is not None:
            closer = FENCE_OPEN.match(body)
            if closer and closer.group(2)[0] == fence[0] and len(closer.group(2)) >= len(fence) \
                    and not body[closer.end():].strip():
                fence = None
            out.append(line)
            continue
        if prefix.strip() != quote:
            # A different quote depth is a different container, so open list items don't carry into it.
            quote, items = prefix.strip(), []
        if not body.strip():
            previous = "blank"
            out.append(line)
            continue
        indent = len(body) - len(body.lstrip(" "))
        if previous == "blank":
            # A line after a blank line ends every item it isn't indented into.
            items = [it for it in items if it[1] <= indent]
        holders = [it for it in items if it[1] <= indent]
        base = holders[-1][1] if holders else 0
        opener = FENCE_OPEN.match(body)
        # A backtick fence's info string holds no backtick, or the line is inline code, as in CommonMark.
        if opener and indent - base < 4 and not (opener.group(2)[0] == "`" and "`" in body[opener.end():]):
            fence = opener.group(2)
            out.append(line)
            previous = "other"
            continue
        moved = LEADING_MARKER.match(body)
        if moved:
            body = f"{moved.group(1)}{moved.group(3)} {moved.group(2)}"
        marker = LIST_ITEM.match(body)
        if marker and indent - base < 4:
            # A sibling continues a list already open at this level. Anything else starts a new list.
            sibling = any(col <= indent < content for col, content in items if (col, content) not in holders)
            first = marker.group(3)
            if not sibling and previous == "para" and first is not None and first.lstrip("0") != "1":
                # An ordered list past 1 can't interrupt a paragraph, so this line is text, such as a wrapped year.
                body = body[:marker.end(2) - 1] + "\\" + body[marker.end(2) - 1:]
                previous = "para"
            else:
                if not sibling and previous == "para":
                    out.append(prefix.rstrip())
                spaces = len(marker.group(4))
                width = marker.end(2) - marker.start(2) + (spaces if spaces <= 4 else 1)
                items = [it for it in items if it[1] <= indent] + [(indent, indent + width)]
                previous = "para"
                item_fence = FENCE_OPEN.match(body[marker.end(4):])
                if item_fence and not item_fence.group(1):
                    # GitHub opens a code block when an item starts with a fence. superfences only sees a fence on a
                    # line of its own, so the fence moves to the next line under an empty comment, which shows nothing.
                    out.append(prefix + body[:marker.end(4)] + "<!-- -->")
                    body = " " * (indent + width) + body[marker.end(4):]
                    fence = item_fence.group(2)
                    previous = "other"
        elif marker and previous == "para":
            # Four or more columns past the item's content, after paragraph text, a marker is that paragraph's text.
            body = body[:marker.end(2) - 1] + "\\" + body[marker.end(2) - 1:]
        elif previous == "blank" and indent - base >= 4:
            previous = "other"
        else:
            tag = HTML_OPEN.match(body)
            if tag:
                name = re.match(r" *<([A-Za-z]+)", body).group(1)
                if _renders_markdown(lines, i, name):
                    # "block" rather than "1": md_in_html reads p, summary and td as inline by default, which would
                    # join two paragraphs GitHub shows apart into one unit.
                    body = HTML_BLOCK_TAG.sub(r'<\1 markdown="block"\2>', body)
                previous = "other"
            else:
                previous = "other" if re.match(r" *(?:#|\||<)", body) else "para"
        out.append(prefix + body)
    return "\n".join(out) + "\n"


def _render(source: str) -> str:
    if markdown is None or superfences is None:
        raise RuntimeError(RENDERER_MISSING)
    md = markdown.Markdown(extensions=list(MARKDOWN_EXTENSIONS))
    # CommonMark, which GitHub renders, lets a backslash escape any ASCII punctuation. Python-Markdown escapes
    # fewer, and would keep a real comment after a backslash-escaped angle bracket.
    md.ESCAPED_CHARS = list(string.punctuation)
    md.inlinePatterns.register(HtmlInlineProcessor(INLINE_HTML, md), "html", 90)
    return md.convert(source)


def _source_lines(source: str, units: list[Unit]) -> None:
    """Point each rendered Markdown unit at the source line it starts on.

    Rendering drops positions, so the line is found by the unit's first letters and digits, searched forward from
    the previous unit. A line that can't be found keeps the previous unit's line. It is a pointer for the author.
    """
    keys = [re.sub(r"[\W_]", "", _fold(ln).lower()) for ln in source.splitlines()]
    cursor = 0
    for unit in units:
        probe = re.sub(r"[\W_]", "", _fold(unit.text).lower())[:12]
        found = None
        for anchored in (True, False):
            for i in range(cursor, len(keys)):
                if not keys[i]:
                    continue
                at = (keys[i] + "".join(keys[i + 1:i + 4])).find(probe)
                if (at == 0) if anchored else (0 <= at < len(keys[i])):
                    found = i
                    break
            if found is not None or not probe:
                break
        if found is not None:
            cursor = found
        unit.line = cursor + 1


def _units(text: str, suffix: str) -> list[Unit]:
    """Markdown is rendered and HTML is parsed, so each block is a unit. Plain text is one unit per line."""
    if suffix in MARKDOWN_SUFFIXES:
        units = _walk(_render(_prepare(text)))
        _source_lines(text, units)
        return units
    if suffix in HTML_SUFFIXES:
        return _walk(text)
    return [Unit(n, line, tuple(m for c in COMMENT.findall(line) for m in MARKER.findall(c)), False)
            for n, line in enumerate(text.splitlines(), 1)]


def _seen(text: str, suffix: str) -> str:
    """The matching copy of a unit, by the reader its suffix names.

    Rendered Markdown can still hold emphasis and code marks as text, where Python-Markdown leaves raw HTML content
    unrendered and GitHub renders it, so those marks are dropped too. Underscores read as spaces in every reader.
    """
    if suffix in MARKDOWN_SUFFIXES:
        return _fold(text.translate(MARKUP))
    if suffix in HTML_SUFFIXES:
        return _fold(text)
    return _normalize(text)


def _check(unit: Unit, seen: str, ledger: Ledger, banned: re.Pattern[str], triggers: re.Pattern[str],
           excused: dict[str, frozenset[str]]) -> list[tuple[str, str]]:
    valid = [m for m in unit.markers if m in ledger.ids]
    found = [("unknown_id", f"claim:{m}") for m in unit.markers if m not in ledger.ids]
    # Only a Not claimed marker excuses a banned phrase, because a banned phrase asserted under a claim row is the
    # defect. It excuses only the phrases its own row names.
    allowed = frozenset().union(*(excused.get(m, frozenset()) for m in valid))
    hits = {_key(m.group()) for m in banned.finditer(seen)}
    # The finding shows the unit as written or rendered, not the folded copy, so the author can find it.
    shown = " ".join(unit.text.split())
    if hits - allowed:
        found.append(("banned", shown))
    elif not hits and not unit.code and triggers.search(seen) and not valid:
        found.append(("unledgered", shown))
    return found


def _scan(root: Path, ledger: Ledger, ledger_path: Path | None) -> tuple[list[Finding], int]:
    root = Path(root)
    excluded = [_glob_regex(g) for g in ledger.exclude]
    skip = ledger_path.resolve() if ledger_path else None
    banned = _phrase_regex(ledger.banned, whole_word=True)
    triggers = _phrase_regex(ledger.triggers, whole_word=False)
    excused = {row: frozenset(_key(p) for p in phrases) for row, phrases in ledger.excuses}
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
            suffix = path.suffix.lower()
            for unit in _units(text, suffix):
                seen = _seen(unit.text, suffix)
                for kind, shown in _check(unit, seen, ledger, banned, triggers, excused):
                    findings.append(Finding(rel, unit.line, kind, escape_text(shown.strip()[:SNIPPET_CHARS])))
    return findings, scanned


def scan(root: Path, ledger: Ledger, ledger_path: Path | None = None) -> list[Finding]:
    """Scan every text file under root. Symlinks and other non-regular files are skipped, and so is the ledger."""
    return _scan(root, ledger, ledger_path)[0]


def main(argv: list[str] | None = None) -> int:
    """Exit 0 clean, 1 findings, 2 the ledger or the path can't be read.

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
    if markdown is None or superfences is None:
        print(f"ERROR: {RENDERER_MISSING}", file=sys.stderr)
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
        # Evidence that names a file the tree doesn't hold checks nothing.
        findings += [Finding(ledger_path.name, 0, "missing_evidence", f"{row} {path}")
                     for row, path in missing_evidence(ledger)]
    if findings:
        for f in findings:
            print(f"NOT YET: {f.path}:{f.line} {f.kind} {f.text}")
        if any(f.kind == "unledgered" for f in findings):
            print(MARKER_HINT)
        return 1
    print(f"DONE: lab text holds to the ledger ({scanned} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
