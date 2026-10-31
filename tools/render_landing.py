#!/usr/bin/env python3
"""Fill the landing page's placeholders from repository state.

Injection happens at build time, so the published page stays static and renders with
JavaScript disabled.

GOVERNANCE.md is a build input and its contents reach an HTML attribute position. Treat
every value from it as untrusted text, because a roster pull request is reviewed for
names and handles rather than for quoting.

mkdocs.yml is a build input too. Its nav and its extra.acs_nav block become the page's
left pane, so every value from it is validated against the patterns in site_nav and then
escaped. A value that fails stops the build. Dropping one link would ship a pane that
differs from the docs site with no error anywhere.
"""
from __future__ import annotations

import base64
import hashlib
import html
import posixpath
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from mkdocs.exceptions import ConfigurationError
from mkdocs.utils.yaml import yaml_load

from publish_schemas import SchemaError, load_schemas, target_for
from site_nav import ANCHOR, DOC_PATH, EXTERNAL, EXTERNAL_URL, TITLE

# Tolerant of case and spacing so a formatter cannot break the build.
WORKSTREAM_HEADING = re.compile(r"^##\s+workstream\s+leads\s*$", re.IGNORECASE)
PRIORITY_SCOPE_HEADING = re.compile(r"^##\s+current\s+priority\s+scope\s*$", re.IGNORECASE)
ANY_HEADING = re.compile(r"^#{2,6}\s")
MD_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
PLACEHOLDER = re.compile(r"<!--ACS:[A-Z_]+-->")
SPLIT_CELLS = re.compile(r"(?<!\\)\|")
ALLOWED_SCHEMES = ("https://", "http://", "mailto:")

REQUIRED_PLACEHOLDERS = (
    "<!--ACS:SPEC_VERSION-->",
    "<!--ACS:SCHEMA_COUNT-->",
    "<!--ACS:SCHEMA_HREF-->",
    "<!--ACS:WORKSTREAMS-->",
    "<!--ACS:PRIORITY_SCOPE-->",
    "<!--ACS:STARBURST-->",
    "<!--ACS:NAV-->",
    "<!--ACS:CSP-->",
)

REPAIR = "Edit `mkdocs.yml` on a branch from `integration`."
# A browser deletes these from a URL before parsing it, so "java\nscript:" runs as
# "javascript:". Classification sees the value the browser will see.
URL_NOISE = re.compile(r"[\t\r\n]")
# The characters RFC 3986 allows in a URL. A quote, a space, or an angle bracket is
# none of them, and each one is how a value leaves an attribute.
URL_CHARS = re.compile(r"\A[A-Za-z0-9._~:/?#\[\]!$&'()*+,;=%-]*\Z")
SCHEME = "https:"

# The raw-text rule of tests/conftest.py's _element_bodies, which the renderer cannot
# import. A test holds the two equal on the real page.
_TAG_NAME = re.compile(r"<([a-zA-Z][^\s/>]*)")
_CLOSE_RAWTEXT = {name: re.compile(rf"</{name}[^>]*>", re.I) for name in ("script", "style")}


class RenderError(Exception):
    """Repository state does not supply what the template asks for."""


def _version_key(version: str) -> tuple[int, ...]:
    """Order versions numerically, so v0.10.0 sorts above v0.2.0 rather than below it."""
    return tuple(int(part) for part in version.lstrip("v").split("."))


def _versions(source: Path) -> dict[str, int]:
    """Map each spec version present to the number of schemas it publishes."""
    try:
        docs = load_schemas(source)
        counts: dict[str, int] = {}
        for path, doc in docs.items():
            version = target_for(doc, path, source).split("/")[0]
            counts[version] = counts.get(version, 0) + 1
        return counts
    except SchemaError as error:
        raise RenderError(str(error)) from error


def _schema_facts(source: Path) -> tuple[str, int]:
    """Return the newest spec version and how many schemas that version publishes.

    Old versions stay published so their $id URIs keep resolving, so more than one
    version is the expected steady state. Counting across all of them would print a
    total beside a single version name and say something false about that version.
    """
    counts = _versions(source)
    if not counts:
        raise RenderError(f"no schemas found under {source}")
    version = max(counts, key=_version_key)
    return version, counts[version]


def spec_version(source: Path) -> str:
    return _schema_facts(source)[0]


def schema_count(source: Path) -> int:
    return _schema_facts(source)[1]


def parse_workstreams(text: str) -> list[tuple[str, str]]:
    """Read the two-column table under the Workstream leads heading."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if WORKSTREAM_HEADING.match(line)), None)
    if start is None:
        raise RenderError("GOVERNANCE.md: no '## Workstream leads' section")

    rows: list[tuple[str, str]] = []
    table_lines = 0
    for line in lines[start + 1 :]:
        if ANY_HEADING.match(line):
            break  # any heading level ends the section, not only level two
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        table_lines += 1
        cells = [cell.strip() for cell in SPLIT_CELLS.split(stripped.strip("|"))]
        if cells[0].lower() == "workstream" or set(cells[0]) <= set("-: "):
            continue
        if len(cells) != 2:
            raise RenderError(
                f"GOVERNANCE.md: workstream row has {len(cells)} cells, expected 2: {stripped!r}"
            )
        rows.append((cells[0].replace("\\|", "|"), cells[1].replace("\\|", "|")))

    if not rows:
        raise RenderError("GOVERNANCE.md: the workstream table is empty")
    # A silently dropped row is worse than a loud failure, so account for every line.
    if len(rows) != table_lines - 2:
        raise RenderError(
            f"GOVERNANCE.md: parsed {len(rows)} workstreams from {table_lines} table lines. "
            "Expected a header, a separator, then one line per workstream."
        )
    return rows


def parse_priority_scope(text: str) -> str:
    """Read the committed-outcome blockquote under the Current Priority Scope heading.

    The heading is followed by review-cadence prose before the quote starts, so this
    skips lines until the first '> ' line rather than requiring the quote immediately
    below the heading.
    """
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if PRIORITY_SCOPE_HEADING.match(line)), None)
    if start is None:
        raise RenderError("CONTRIBUTING.md: no '## Current Priority Scope' section")

    quote_lines: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith(">"):
            quote_lines.append(line[1:].strip())
        elif quote_lines:
            break  # the blockquote has ended
        elif ANY_HEADING.match(line):
            break  # the section ended before any blockquote appeared

    if not quote_lines:
        raise RenderError(
            "CONTRIBUTING.md: no blockquote follows '## Current Priority Scope'"
        )
    return " ".join(quote_lines)


def _to_html(markdown: str) -> str:
    """Escape everything, then rebuild links from an allowlisted scheme."""

    def link(match: re.Match[str]) -> str:
        label, url = match.group(1), match.group(2)
        if not url.startswith(ALLOWED_SCHEMES):
            return label  # drop the link, keep the text
        return f'<a href="{url}">{label}</a>'

    # quote=True so a quote in the source cannot break out of the href attribute.
    return MD_LINK.sub(link, html.escape(markdown, quote=True))


def render_workstreams(rows: list[tuple[str, str]]) -> str:
    return "".join(
        f"<tr><td>{_to_html(name)}</td><td>{_to_html(leads)}</td></tr>" for name, leads in rows
    )


def render_priority_scope(scope: str) -> str:
    # The blockquote sits in a text position in the template, not an attribute, but
    # it is a build input like GOVERNANCE.md, so it is escaped for the same reason.
    return html.escape(scope)


@dataclass(frozen=True)
class NavConfig:
    """The parts of mkdocs.yml the pane is built from, unvalidated until render_nav."""

    nav: tuple
    landing_sections: tuple[dict, ...]
    external_resources: tuple[dict, ...]
    out_of_nav_prefixes: tuple[str, ...]
    repo_url: str


def read_nav_config(path: Path) -> NavConfig:
    """Read the pane's inputs from mkdocs.yml without building a mkdocs config object.

    A config object would validate plugins and the theme, which needs the whole docs
    toolchain. The landing render only needs these keys.
    """
    try:
        with path.open(encoding="utf-8") as handle:
            cfg = yaml_load(handle)
    except ConfigurationError as error:
        raise RenderError(f"{path.name}: {error}. {REPAIR}") from error
    try:
        # page_url implements the directory-URL rule only. A build with it off would
        # publish pages at other addresses than the pane links to.
        if cfg.get("use_directory_urls", True) is not True:
            raise RenderError(f"{path.name}: use_directory_urls must be true. {REPAIR}")
        acs_nav = cfg["extra"]["acs_nav"]
        nav = cfg["nav"]
        if not isinstance(nav, list):
            raise RenderError(f"{path.name}: nav must be a list. {REPAIR}")
        return NavConfig(
            nav=tuple(nav),
            landing_sections=tuple(acs_nav["landing_sections"]),
            external_resources=tuple(acs_nav["external_resources"]),
            out_of_nav_prefixes=tuple(acs_nav["out_of_nav_prefixes"]),
            repo_url=cfg["repo_url"],
        )
    except (KeyError, TypeError) as error:
        raise RenderError(f"{path.name}: missing or malformed key {error}. {REPAIR}") from error


def page_url(path: str) -> str:
    """Return the URL mkdocs gives a page under use_directory_urls, relative to the docs root.

    README.md and index.md publish as their directory. Any other page publishes as a
    directory named after it. Case is kept, and the result is percent-quoted as mkdocs
    quotes it.
    """
    directory, name = posixpath.split(path)
    stem = posixpath.splitext(name)[0]
    if stem in ("index", "README"):
        url = f"{directory}/" if directory else "./"
    else:
        url = f"{directory}/{stem}/" if directory else f"{stem}/"
    return quote(url)


def _invalid(entry: str, value: object, rule: str) -> RenderError:
    return RenderError(f"mkdocs.yml: {entry} {value!r} {rule}. {REPAIR}")


def _title(value: object, entry: str) -> str:
    if not isinstance(value, str) or not TITLE.fullmatch(value):
        raise _invalid(entry, value, f"is not a title matching {TITLE.pattern}")
    return html.escape(value, quote=True)


def _anchor(value: object, entry: str) -> str:
    if not isinstance(value, str) or not ANCHOR.fullmatch(value):
        raise _invalid(entry, value, f"is not an anchor matching {ANCHOR.pattern}")
    return html.escape(value, quote=True)


def _external_url(value: object, entry: str) -> str:
    """Admit an https URL on one of the two allowed hosts, in a shape a parser cannot misread."""
    if not isinstance(value, str):
        raise _invalid(entry, value, "is not a URL string")
    if URL_NOISE.search(value):
        raise _invalid(entry, value, "contains a tab or line break, which a browser deletes before parsing")
    # EXTERNAL_URL is a prefix check by design, so match rather than fullmatch.
    if not EXTERNAL_URL.match(value):
        raise _invalid(entry, value, f"is not a URL matching {EXTERNAL_URL.pattern}")
    if "\\" in value or "@" in value or ":" in value[len(SCHEME):]:
        # A backslash reads as a slash and @ ends userinfo, so either can move the host
        # away from the one the prefix matched. A port or a second scheme has no use here.
        raise _invalid(entry, value, "contains a backslash, an @, or a colon after the scheme")
    if not URL_CHARS.match(value):
        raise _invalid(entry, value, f"contains a character outside {URL_CHARS.pattern}")
    return html.escape(value, quote=True)


def _nav_href(value: str, entry: str) -> str:
    """Return the escaped href for a nav leaf: an allowed external URL or a docs page."""
    if EXTERNAL.match(URL_NOISE.sub("", value)):
        return _external_url(value, entry)
    if not DOC_PATH.fullmatch(value):
        raise _invalid(entry, value, f"is not a page path matching {DOC_PATH.pattern}")
    url = page_url(value)
    return html.escape("docs/" + ("" if url == "./" else url), quote=True)


def _nav_items(entries, trail: str) -> str:
    out = []
    for entry in entries:
        if isinstance(entry, str):
            raise _invalid(f"nav entry under {trail}", entry, "is a bare string. Give it a title")
        if not isinstance(entry, dict) or len(entry) != 1:
            raise _invalid(f"nav entry under {trail}", entry, "is untitled. Write it as {Title: value}")
        ((title, value),) = entry.items()
        if title is None:
            raise _invalid(f"nav entry under {trail}", entry, "is untitled. Write it as {Title: value}")
        label = _title(title, f"nav title under {trail}")
        where = f"{trail} > {title}"
        if isinstance(value, list):
            children = _nav_items(value, where)
            out.append(f"<li><details><summary>{label}</summary><ul>\n{children}</ul></details></li>\n")
        elif isinstance(value, str):
            out.append(f'<li><a href="{_nav_href(value, f"nav entry {where}")}">{label}</a></li>\n')
        else:
            raise _invalid(f"nav entry {where}", value, "is neither a page path, a URL, nor a group")
    return "".join(out)


def _field(item: object, key: str, entry: str) -> object:
    if not isinstance(item, dict) or key not in item:
        raise _invalid(entry, item, f"has no {key}")
    return item[key]


def render_nav(config: NavConfig) -> str:
    """Emit the landing page's left pane: Home, the docs nav, then External resources.

    Groups are details elements so they open and close without JavaScript. No link
    carries target or rel, because every one of them navigates in place.
    """
    sections = []
    for item in config.landing_sections:
        title = _title(_field(item, "title", "landing_sections entry"), "landing_sections title")
        anchor = _anchor(_field(item, "anchor", f"landing_sections entry {title}"),
                         f"landing_sections anchor for {title}")
        sections.append(f'<li><a href="#{anchor}">{title}</a></li>\n')
    resources = []
    for item in config.external_resources:
        title = _title(_field(item, "title", "external_resources entry"), "external_resources title")
        url = _external_url(_field(item, "url", f"external_resources entry {title}"),
                            f"external_resources url for {title}")
        resources.append(f'<li><a href="{url}">{title}</a></li>\n')
    return (
        '<nav id="site-nav" aria-label="Navigation"><ul>\n'
        # href="./" rather than "/": the site is served from a project subpath.
        '<li><details open><summary><a href="./" aria-current="page">Home</a></summary><ul>\n'
        + "".join(sections)
        + "</ul></details></li>\n"
        + _nav_items(config.nav, "nav")
        + '<li class="nav-section"><h2>External resources</h2><ul>\n'
        + "".join(resources)
        + "</ul></li>\n"
        "</ul></nav>"
    )


def _tag_end(markup: str, start: int) -> int:
    """Return the offset past the tag opening at start, respecting quoted values."""
    quote_char, expecting_value = "", False
    for index in range(start + 1, len(markup)):
        char = markup[index]
        if quote_char:
            if char == quote_char:
                quote_char = ""
        elif char == "=":
            expecting_value = True
        elif char in "\"'" and expecting_value:
            quote_char, expecting_value = char, False
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


def _inline_bodies(page: str) -> list[tuple[str, str]]:
    """Return the tag and raw body of every script and style element a browser would run.

    The body is every character between the end of the start tag and the start of the
    end tag, unstripped, because that is the text the browser hashes.
    """
    bodies: list[tuple[str, str]] = []
    position = 0
    while position < len(page):
        opening = page.find("<", position)
        if opening == -1:
            break
        if page.startswith("<!--", opening):
            position = _comment_end(page, opening + 4)
            continue
        named = _TAG_NAME.match(page, opening)
        after = _tag_end(page, opening)
        if named and named.group(1).lower() in ("script", "style"):
            tag = named.group(1).lower()
            closing = _CLOSE_RAWTEXT[tag].search(page, after)
            if closing is None:
                bodies.append((tag, page[after:]))
                break
            bodies.append((tag, page[after:closing.start()]))
            position = closing.end()
            continue
        position = after
    return bodies


def _sha256(body: str) -> str:
    return base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii")


def render_csp(page: str) -> str:
    """Return a meta policy that allows exactly the page's one inline script and one style.

    The page's other resources are its own files, so 'self' covers them. A meta policy
    cannot carry frame-ancestors or reporting, so this contains injection and no more.
    """
    bodies = _inline_bodies(page)
    scripts = [body for tag, body in bodies if tag == "script"]
    styles = [body for tag, body in bodies if tag == "style"]
    if len(scripts) != 1:
        raise RenderError(f"the landing page must carry one inline script, found {len(scripts)}")
    if len(styles) != 1:
        raise RenderError(f"the landing page must carry one inline style, found {len(styles)}")
    # The style lives in the inline SVG, which is foreign content. A browser decodes
    # entities there before hashing, so a body with & or < would hash differently from
    # this text and the style would be blocked.
    if "&" in styles[0] or "<" in styles[0]:
        raise RenderError("the inline style body contains & or <, so its hash cannot be computed from source")
    policy = (
        "default-src 'none'; "
        f"script-src 'sha256-{_sha256(scripts[0])}'; "
        f"style-src 'self' 'sha256-{_sha256(styles[0])}'; "
        "img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'"
    )
    return f'<meta http-equiv="Content-Security-Policy" content="{policy}">'


def render(
    template: str, source: Path, governance: str, contributing: str, starburst: str, nav: NavConfig
) -> str:
    """Replace every placeholder. Fail if one is missing from the template or survives it.

    Both directions matter. A surviving token means the renderer did not know about it.
    A missing token means the template dropped a section, which would otherwise ship a
    page with a blank hero and no error anywhere.
    """
    missing = [token for token in REQUIRED_PLACEHOLDERS if token not in template]
    if missing:
        raise RenderError(f"template is missing placeholder: {', '.join(missing)}")

    version, count = _schema_facts(source)
    out = template.replace("<!--ACS:SPEC_VERSION-->", html.escape(version))
    out = out.replace("<!--ACS:SCHEMA_COUNT-->", str(count))
    out = out.replace("<!--ACS:SCHEMA_HREF-->", html.escape(f"schema/{version}/acs_schema.json"))
    out = out.replace("<!--ACS:WORKSTREAMS-->", render_workstreams(parse_workstreams(governance)))
    out = out.replace(
        "<!--ACS:PRIORITY_SCOPE-->", render_priority_scope(parse_priority_scope(contributing))
    )
    # Inlining is required: an SVG loaded through <img> cannot read the page's CSS
    # custom properties, so the diagram would ignore the theme.
    out = out.replace("<!--ACS:STARBURST-->", starburst)
    out = out.replace("<!--ACS:NAV-->", render_nav(nav))
    # Last, so the hashes cover the bodies as they ship. The placeholder is a comment,
    # which the body scan skips.
    out = out.replace("<!--ACS:CSP-->", render_csp(out))

    survivors = PLACEHOLDER.findall(out)
    if survivors:
        raise RenderError(f"unfilled placeholder: {', '.join(sorted(set(survivors)))}")
    return out


def main(argv: list[str]) -> int:
    landing = Path(argv[1]) if len(argv) > 1 else Path("landing")
    out = Path(argv[2]) if len(argv) > 2 else Path("_site")
    repo = Path(__file__).resolve().parents[1]
    try:
        page = render(
            (landing / "index.html").read_text(encoding="utf-8"),
            repo / "specification",
            (repo / "GOVERNANCE.md").read_text(encoding="utf-8"),
            (repo / "CONTRIBUTING.md").read_text(encoding="utf-8"),
            (landing / "assets" / "starburst.svg").read_text(encoding="utf-8"),
            read_nav_config(repo / "mkdocs.yml"),
        )
    except (RenderError, SchemaError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"error: cannot read a landing page source: {error}", file=sys.stderr)
        return 1
    try:
        out.mkdir(parents=True, exist_ok=True)
        (out / "index.html").write_text(page, encoding="utf-8")
        shutil.copytree(
            landing / "assets",
            out / "assets",
            dirs_exist_ok=True,
            # The diagram is inlined into the page, so publishing it again would ship a
            # second copy that nothing references and that can drift from the inlined one.
            ignore=shutil.ignore_patterns("starburst.svg"),
        )
    except OSError as error:
        print(f"error: cannot write the rendered site: {error}", file=sys.stderr)
        return 1
    print(f"rendered landing page to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
