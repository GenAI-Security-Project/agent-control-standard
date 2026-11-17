"""Shared guards that keep the published site from contacting a third party.

The guard has been found incomplete five times. Every earlier version enumerated the
attributes that fetch, and each new construct was a fresh gap: a poster attribute, an
unquoted value, a stylesheet, a base element, an inline script body. So this one
enumerates the positions that do not fetch instead. Anything else carrying an absolute
URL counts as a fetch, which makes an unanticipated construct a failure rather than a
silent pass.

Never accept a change to this file on a green suite. Inject a third-party host into a fixture and watch `tests/test_third_party_guard.py` fail first.
"""
import hashlib
import html.parser
import json
import re
from pathlib import Path

import pytest
import _docs_build

# Positions a browser resolves but never fetches from. Everything else is a fetch.
# Form action is deliberately absent. A form needs no click: a script calling submit()
# fires the request on load, and the URL never appears in the script text.
NON_FETCHING = frozenset({
    ("a", "href"), ("area", "href"),
    ("blockquote", "cite"), ("q", "cite"), ("ins", "cite"), ("del", "cite"),
})
# A namespace URI names a vocabulary. No browser resolves it, and the built site
# carries several hundred of them on inline SVG.
NON_FETCHING_ATTRS = frozenset({"xmlns"})
# These link types make an anchor fetch or open a connection with no click, so the
# anchor exemption does not apply when one of them is present.
SPECULATIVE_REL = frozenset({
    "prefetch", "preconnect", "dns-prefetch", "preload", "modulepreload",
})

# The URL parser strips ASCII tab and newline before resolving, so a scheme broken
# across one still fetches. Strip them before matching rather than after.
_NOISE = re.compile(r"[\t\r\n]")
# In an attribute, a protocol-relative value is a fetch.
_IN_ATTR = re.compile(r"""(?:[a-z][a-z0-9+.-]*:)?//([^\s/?#'\"),<>]+)""", re.I)
# In script text, require a scheme. A bare // opens a JavaScript comment far more
# often than a protocol-relative URL, and a false positive here is the kind of noise
# that gets a guard switched off.
_IN_TEXT = re.compile(r"""\bhttps?://([^\s/?#'\"),<>]+)""", re.I)
# Markup a script writes fetches like any other. Requiring an attribute name keeps
# this from matching the // that opens a JavaScript comment.
_IN_SCRIPT_MARKUP = re.compile(
    r"""\b(?:src|href|data|poster|action|srcset)\s*=\s*['\"]?(?:[a-z][a-z0-9+.-]*:)?//([^\s/?#'\"),<>]+)""",
    re.I,
)
# Script and style bodies are taken from the raw markup rather than from parser
# events. HTML honors a self-closing slash only on void and foreign elements, so
# <script/>body</script> runs in a browser, and Python's parser reports it through a
# handler that never enters raw-text mode. Tracking capture across events therefore
# either misses the body or sweeps whatever follows until some later closing tag.
# Matching the element outright has neither failure.
# Script and style bodies come from one left-to-right pass over the raw markup.
# HTML tokenization is context sensitive: inside these elements the text is raw, so
# <!-- opens no comment there and a browser runs whatever follows, while outside one
# a comment hides everything to its terminator. Four earlier attempts scanned for
# comments and elements with separate patterns, and every pairing hid something real.
_TAG_NAME = re.compile(r"<([a-zA-Z][^\s/>]*)")
# A tag name ends at whitespace, a slash, or a bracket, so </scripty> closes nothing.
_NAME_END = r"(?=[\t\n\f\r />])"
# Everything that moves the tokenizer between a script's data, escaped, and double-escaped
# states. A browser leaves <!-- ... --> escaped, and a <script inside that enters double
# escape, where a </script only steps back out and closes nothing.
_SCRIPT_MARK = re.compile(rf"<!--|-->|<script{_NAME_END}|</script{_NAME_END}", re.I)
# A browser reads these as text, so a comment delimiter inside one hides nothing. Inside svg,
# though, a title holds real markup, and the walker cannot tell which it is in.
_TEXT_ONLY = ("title", "textarea", "xmp", "iframe", "noembed", "noframes", "noscript")
_CLOSE = {name: re.compile(rf"</{name}{_NAME_END}", re.I) for name in ("style", *_TEXT_ONLY)}

# CSS reaches the network only through url(), image-set(), and @import. That set is
# closed, unlike the HTML one, so enumerating it here is safe. Comments are stripped
# first because a vendor licence banner carries URLs that fetch nothing, and data:
# payloads are skipped because an inlined SVG carries an xmlns that is not a request.
_CSS_FETCH = re.compile(
    r"""(?:url\(\s*|@import\s*(?:url\(\s*)?)['"]?([^'")\s]+)""", re.I
)
# An image-set lists several URLs, so its whole argument list is read, not its first word.
# This also matches -webkit-image-set.
_CSS_IMAGE_SET = re.compile(r"image-set\(", re.I)
_CSS_SET_TOKEN = re.compile(r"""(?P<quote>["'])(?P<text>(?:\\.|(?!(?P=quote)).)*)(?P=quote)|[^\s,"'()]+""", re.S)
_CSS_HOST = re.compile(r"""^(?:[a-z][a-z0-9+.-]*:)?//([^/?#]+)""", re.I)

# Scripts come from the installed theme, pinned by uv.lock. The path is relative to
# the mkdocs output root, which is the directory built_site builds into and
# _site/docs in the deploy workflow.
VENDORED_PREFIX = "assets/javascripts/"


def write_schema(root: Path, rel: str, sid: str, body: dict | None = None) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"$id": sid}
    doc.update(body or {})
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


class _Scanner(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.attr_values: list[str] = []
        self.bases: list[str] = []

    def _collect(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        seen = dict(attrs)
        if tag == "base":
            self.bases.append(seen.get("href") or "")
        speculative = bool(set((seen.get("rel") or "").lower().split()) & SPECULATIVE_REL)
        for name, value in attrs:
            if not value:
                continue
            if name.split(":")[0] in NON_FETCHING_ATTRS:
                continue
            if (tag, name) in NON_FETCHING and not speculative:
                continue
            self.attr_values.append(value)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._collect(tag, attrs)

    handle_startendtag = handle_starttag


def _scan(markup: str) -> _Scanner:
    scanner = _Scanner()
    scanner.feed(markup)
    return scanner


def _strip_css_comments(css: str) -> str:
    """Remove CSS comments, leaving comment delimiters that sit inside strings.

    The shipped theme stylesheet declares content:"/*" and content:"*/" for its
    critic-markup rules. Treating those as a comment blanked everything between
    them, which is where a url() could hide.
    """
    out: list[str] = []
    index, quote = 0, ""
    while index < len(css):
        char = css[index]
        if quote:
            out.append(char)
            if char == "\\" and index + 1 < len(css):
                out.append(css[index + 1])
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
        elif char in "\"'":
            quote = char
            out.append(char)
            index += 1
        elif css.startswith("/*", index):
            end = css.find("*/", index + 2)
            out.append(" ")
            index = len(css) if end == -1 else end + 2
        else:
            out.append(char)
            index += 1
    return "".join(out)


def _tag_end(markup: str, start: int) -> int:
    """Return the offset past the tag opening at start, respecting quoted values.

    Quote state begins only where a quote opens a value, after an equals sign. An
    apostrophe inside an unquoted value, as in data-x=it's, is a character rather
    than a delimiter, and treating it as one consumed the rest of the document.
    """
    quote, expecting_value = "", False
    for index in range(start + 1, len(markup)):
        char = markup[index]
        if quote:
            if char == quote:
                quote = ""
        elif char == "=":
            expecting_value = True
        elif char in "\"'" and expecting_value:
            quote, expecting_value = char, False
        elif char == ">":
            return index + 1
        elif not char.isspace():
            expecting_value = False
    return len(markup)


def _comment_end(markup: str, start: int) -> int:
    """Return the offset past a comment terminator. A browser accepts --> and --!>."""
    plain = markup.find("-->", start)
    bang = markup.find("--!>", start)
    if plain == -1 and bang == -1:
        return len(markup)
    if bang == -1 or (plain != -1 and plain < bang):
        return plain + 3
    return bang + 4


def _end_tag(name: str, markup: str, start: int) -> int | None:
    """Return the offset of the end tag that closes this element, or None if none does."""
    if name != "script":
        closing = _CLOSE[name].search(markup, start)
        return closing.start() if closing else None
    state, position = "data", start
    while (mark := _SCRIPT_MARK.search(markup, position)) is not None:
        token = mark.group().lower()
        # Step back onto the dashes of <!-- so that <!--> reads as opened and closed.
        position = mark.start() + 2 if token == "<!--" else mark.end()
        if token == "<!--":
            state = "escaped" if state == "data" else state
        elif token == "-->":
            state = "data"
        elif token == "<script":
            state = "double" if state == "escaped" else state
        elif state == "double":
            state = "escaped"
        else:
            return mark.start()
    return None


def _element_bodies(markup: str) -> list[tuple[str, str]]:
    """Return the tag and body of every script and style element a browser would run.

    One left-to-right pass, because HTML tokenization is context sensitive. Inside
    these elements the text is raw, so a comment delimiter opens nothing there.
    Outside one, a comment hides everything to its terminator.

    A text-only element's span is scanned with its comment openers removed instead of
    being skipped. In HTML the scripts found there never run, which costs a false positive
    on a page nobody writes. Skipping would hide a script that runs inside an svg title.
    """
    bodies: list[tuple[str, str]] = []
    position = 0
    while position < len(markup):
        opening = markup.find("<", position)
        if opening == -1:
            break
        if markup.startswith("<!--", opening):
            position = _comment_end(markup, opening + 4)
            continue
        following = markup[opening + 1 : opening + 2]
        if following in ("!", "?") or (following == "/" and not markup[opening + 2 : opening + 3].isalpha()):
            # A bogus comment ends at the first bracket, whatever quotes it holds.
            end = markup.find(">", opening)
            position = end + 1 if end != -1 else len(markup)
            continue
        named = _TAG_NAME.match(markup, opening)
        if named is None and following != "/":
            # A less-than sign before anything else is text, and opens no tag.
            position = opening + 1
            continue
        after = _tag_end(markup, opening)
        name = named.group(1).lower() if named else ""
        if name in ("script", "style"):
            end = _end_tag(name, markup, after)
            if end is None:
                # No end tag, so the element owns the rest of the document and runs.
                bodies.append((name, markup[after:]))
                break
            bodies.append((name, markup[after:end]))
            position = _tag_end(markup, end)
            continue
        if name in _TEXT_ONLY:
            end = _end_tag(name, markup, after)
            span_end = len(markup) if end is None else end
            bodies += _element_bodies(markup[after:span_end].replace("<!--", ""))
            position = len(markup) if end is None else _tag_end(markup, end)
            continue
        position = after
    return bodies


def third_party_hosts(markup: str, self_hosts: set[str]) -> set[str]:
    """Return every third-party host the markup would fetch from.

    A base element counts, because it redirects every relative URL on the page. It is
    folded in here rather than offered as a second function each caller has to
    remember, since coverage a call site opts into is how this guard came to be
    incomplete five times.
    """
    scanner = _scan(markup)
    hosts: set[str] = set()
    for value in scanner.attr_values + scanner.bases:
        hosts |= {m.group(1).lower() for m in _IN_ATTR.finditer(_NOISE.sub("", value))}
    for tag, body in _element_bodies(markup):
        if tag == "style":
            # CSS in the markup is still CSS. Feeding it to the script matcher, which
            # requires an explicit scheme, silently dropped every protocol-relative
            # url() an inline style carries.
            hosts |= stylesheet_hosts(body, self_hosts)
        else:
            text = _NOISE.sub("", body)
            hosts |= {m.group(1).lower() for m in _IN_TEXT.finditer(text)}
            hosts |= {m.group(1).lower() for m in _IN_SCRIPT_MARKUP.finditer(text)}
    return hosts - {host.lower() for host in self_hosts}


def external_bases(markup: str) -> list[str]:
    """Return every base element href, for a test that names the construct directly."""
    return [href for href in _scan(markup).bases if href]


def _image_set_values(css: str) -> list[str]:
    """Return every string and bare word in every image-set argument list.

    The brackets are counted outside strings, so a nested url() stays inside the list
    and a bracket in a string does not end it.
    """
    values: list[str] = []
    for opening in _CSS_IMAGE_SET.finditer(css):
        position, depth = opening.end(), 1
        while depth and position < len(css):
            token = _CSS_SET_TOKEN.match(css, position)
            if token:
                values.append(token.group("text") if token.group("quote") else token.group())
                position = token.end()
                continue
            depth += {"(": 1, ")": -1}.get(css[position], 0)
            position += 1
    return values


def stylesheet_hosts(css: str, self_hosts: set[str]) -> set[str]:
    """Return every third-party host a stylesheet would fetch from."""
    css = _strip_css_comments(css)
    hosts: set[str] = set()
    for value in [match.group(1) for match in _CSS_FETCH.finditer(css)] + _image_set_values(css):
        if value.lower().startswith("data:"):
            continue
        host = _CSS_HOST.match(value)
        if host:
            hosts.add(host.group(1).lower())
    return hosts - {host.lower() for host in self_hosts}


def theme_script_digests() -> set[str]:
    """Return a digest of every script the installed theme ships.

    Names are not enough. A path check cannot tell our own file from the theme's,
    and a name check cannot tell the theme's file from one edited in place.
    """
    import material

    root = Path(material.__file__).parent / "templates" / "assets" / "javascripts"
    return {hashlib.sha256(path.read_bytes()).hexdigest() for path in root.rglob("*.js")}


def first_party_script_digests() -> set[str]:
    """Return a digest of every script this repository serves from its own source tree.

    mkdocs copies docs/assets/ into the same output directory as the theme's bundle, so
    a path check cannot tell the two apart. Comparing digests against the source tree
    proves a built script is byte-identical to the one committed here, which is the
    property that matters: it catches a script altered or injected during the build,
    while still allowing the library this project deliberately vendors.
    """
    root = Path(__file__).resolve().parent.parent / "docs" / "assets" / "javascripts"
    if not root.is_dir():
        return set()
    return {hashlib.sha256(path.read_bytes()).hexdigest() for path in root.rglob("*.js")}


def stray_scripts(built_site: Path) -> list[str]:
    """Return every built script neither the pinned theme nor this repository ships."""
    digests = theme_script_digests() | first_party_script_digests()
    stray: list[str] = []
    for path in built_site.rglob("*.js"):
        rel = path.relative_to(built_site).as_posix()
        if hashlib.sha256(path.read_bytes()).hexdigest() not in digests:
            stray.append(rel)
    return stray


@pytest.fixture(scope="session")
def built_docs(tmp_path_factory):
    return _docs_build.build_docs(tmp_path_factory.mktemp("docs"))
