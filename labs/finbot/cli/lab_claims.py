"""Holds the FinBot lab's text to its claims ledger (issue #587, LAB-14).

Version 1.1.0. Owner: ACS lab maintainers.

The ledger (CLAIMS.md) is Markdown for people with four fenced machine blocks. This module parses it and
scans a tree. It loads by path, so the root test suite and the lab wrapper can both run it. Markdown is rendered
with Python-Markdown, which the root environment already carries through mkdocs. Without it the check refuses.
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
    )


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    # "banned", "unledgered", "unknown_id", "unreadable", or at the sign gate
    # "unsigned", "unconfirmed" and "no_claims".
    kind: str
    text: str


# The one allowlist of scanned file types: prose an attendee reads. Code comments and identifiers make no claim to
# attendees, so code is never scanned, and neither are test directories (the ledger's exclusion list names them).
SCANNED = frozenset({".md", ".markdown", ".html", ".htm", ".txt"})
COMMENT = re.compile(r"<!--(.*?)-->", re.S)
MARKER = re.compile(r"claim:([A-Za-z]+-\d+)")
TAG = re.compile(r"</?[A-Za-z][^>]*>")
LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
SNIFF_BYTES = 8192
SNIPPET_CHARS = 100
DASHES = dict.fromkeys(list(range(0x2010, 0x2016)) + [0x2212], "-")
QUOTES = {0x2018: "'", 0x2019: "'", 0x201A: "'", 0x201B: "'", 0x02BC: "'", 0x2032: "'",
          0x201C: '"', 0x201D: '"', 0x201E: '"'}
# Underscores read as spaces, so words joined by one in an identifier still meet a phrase. Tildes go, because GitHub
# draws ~~text~~ as struck text and Python-Markdown leaves the marks in place.
JOINERS = {ord("_"): " ", ord("~"): None}
MARKUP = dict.fromkeys(map(ord, "*_`~"))
# Unicode Default_Ignorable_Code_Point (DerivedCoreProperties.txt, Unicode 15.1), which unicodedata doesn't expose.
# These draw nothing or nothing visible, so they are dropped before matching.
IGNORABLE = ((0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
             (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
             (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
             (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF))
# The Braille blank draws as a space but isn't default-ignorable, so it is listed on its own.
BLANKS = frozenset({0x2800})
# The Markdown extensions mkdocs.yml enables that ship with Python-Markdown and change what a reader sees.
# md_in_html renders Markdown inside a raw HTML block that carries markdown="1", which _prepare adds.
MARKDOWN_EXTENSIONS = ("tables", "fenced_code", "admonition", "attr_list", "md_in_html")
# Fence lines, so the pre-render steps never touch code. A block-quote prefix may lead them.
QUOTE_PREFIX = re.compile(r"^((?: {0,3}> ?)*)")
FENCE_OPEN = re.compile(r" {0,3}(`{3,}|~{3,})")
# A line GitHub reads as a list item. Only a bullet or an ordered list starting at 1 may interrupt a paragraph.
LIST_MARKER = re.compile(r" {0,3}(?:[-*+]|\d{1,9}[.)])[ \t]+\S")
INTERRUPTS = re.compile(r" {0,3}(?:[-*+]|1[.)])[ \t]+\S")
# Block-level HTML whose content GitHub renders as Markdown after a blank line.
MD_HTML_BLOCKS = ("address|article|aside|blockquote|center|dd|details|dialog|div|dl|dt|fieldset|figcaption|figure|"
                  "footer|form|header|hgroup|li|main|nav|ol|p|section|summary|ul")
HTML_OPEN = re.compile(rf"^( {{0,3}})<({MD_HTML_BLOCKS})(?=[\s>])(?![^>]*\bmarkdown\s*=)([^>]*)>", re.I)
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


def _prepare(source: str) -> str:
    """Two pre-render steps where Python-Markdown reads less than GitHub shows. Fenced code is left alone.

    A list item right after a paragraph line starts a list on GitHub, while Python-Markdown folds it into the
    paragraph, so a blank line goes before it. Markdown inside a raw HTML block renders on GitHub, while
    Python-Markdown keeps it as raw text, so each block-level opening tag gets markdown="1" for md_in_html.
    """
    out: list[str] = []
    fence: str | None = None
    previous = ""
    in_list = False
    for line in source.splitlines():
        prefix = QUOTE_PREFIX.match(line).group(1)
        body = line[len(prefix):]
        opener = FENCE_OPEN.match(body)
        if fence is not None:
            if opener and opener.group(1)[0] == fence[0] and len(opener.group(1)) >= len(fence):
                fence = None
            out.append(line)
            previous = line
            continue
        if opener:
            fence = opener.group(1)
        elif not body.strip():
            in_list = False
        elif LIST_MARKER.match(body):
            prev_body = previous[len(QUOTE_PREFIX.match(previous).group(1)):]
            if (not in_list and INTERRUPTS.match(body) and prev_body.strip() and not prev_body.startswith("    ")
                    and not re.match(r" {0,3}(?:#|\||<)", prev_body)):
                out.append(prefix.rstrip())
            in_list = True
        else:
            line = prefix + HTML_OPEN.sub(r'\1<\2 markdown="1"\3>', body)
        out.append(line)
        previous = line
    return "\n".join(out) + "\n"


def _render(source: str) -> str:
    if markdown is None:
        raise RuntimeError("Python-Markdown isn't installed, so Markdown files can't be checked")
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
    if suffix == ".md":
        units = _walk(_render(_prepare(text)))
        _source_lines(text, units)
        return units
    if suffix == ".html":
        return _walk(text)
    return [Unit(n, line, tuple(m for c in COMMENT.findall(line) for m in MARKER.findall(c)), False)
            for n, line in enumerate(text.splitlines(), 1)]


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
                seen = _normalize(unit.text) if suffix not in (".md", ".html") else _fold(unit.text)
                for kind, shown in _check(unit, seen, ledger, banned, triggers, excused):
                    findings.append(Finding(rel, unit.line, kind, escape_text(shown.strip()[:SNIPPET_CHARS])))
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
    if markdown is None:
        print("ERROR: Python-Markdown isn't installed, so Markdown files can't be checked", file=sys.stderr)
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
