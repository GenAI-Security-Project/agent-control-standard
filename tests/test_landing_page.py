"""Content guards on the page that ships.

These run against render() output, not the template. The template is hand-reviewed,
but the injected sections are not.
"""
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import _docs_build
from render_landing import _inline_bodies
from site_nav import ancestor_labels, landing_open_labels, walk_landing

REPO = Path(__file__).resolve().parents[1]
LANDING = REPO / "landing"
LANDING_ROOT = "https://example.org/agent-control-standard/"


@pytest.fixture(scope="module")
def page() -> str:
    return _docs_build.render_landing_page()


def test_the_hero_diagram_is_present(page):
    assert "<svg" in page
    for label in ["LLM", "Tool", "Output", "Sub", "Memory", "Code", "ACS"]:
        assert label in page


def test_no_root_relative_links(page):
    """A project Pages site serves from /agent-control-standard/, so /docs/ would 404."""
    assert not re.search(r"""(href|src)\s*=\s*['"]/(?!/)""", page)


def test_no_retired_project_links(page):
    assert "aos.owasp.org" not in page


def test_the_only_email_is_the_approved_one(page):
    found = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", page))
    assert found == {"rock.lambros@owasp.org"}


def test_page_loads_no_third_party_resource(page):
    """The page and the stylesheet it loads must both fetch nothing external."""
    from conftest import stylesheet_hosts, third_party_hosts

    hosts = third_party_hosts(page, set())
    hosts |= stylesheet_hosts((LANDING / "assets" / "acs.css").read_text(encoding="utf-8"), set())
    assert not hosts, f"third-party resource loads: {hosts}"


def test_no_inline_event_handlers(page):
    """Parsed, not grepped. An escaped payload contains the text `onfocus=` inside an
    attribute value while being entirely inert, so a regex reports a false positive."""
    from html.parser import HTMLParser

    from conftest import _NOISE

    class Collector(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.handlers: list[str] = []
            self.schemes: list[str] = []

        def handle_starttag(self, tag, attrs):
            for name, value in attrs:
                if name.startswith("on"):
                    self.handlers.append(f"<{tag} {name}>")
                # A browser drops tabs and newlines inside a URL before reading its
                # scheme, so "java\tscript:" runs unless the check strips them first.
                if name in ("href", "src") and value:
                    scheme = _NOISE.sub("", value).strip().lower()
                    if scheme.startswith(("javascript:", "data:", "vbscript:")):
                        self.schemes.append(f"<{tag} {name}={value[:40]}>")

    collector = Collector()
    collector.feed(page)
    assert not collector.handlers, collector.handlers
    assert not collector.schemes, collector.schemes


def test_no_em_dash(page):
    assert "—" not in page


def test_the_title_has_no_em_dash_and_is_present(page):
    match = re.search(r"<title>(.*?)</title>", page)
    assert match and "—" not in match.group(1)


def test_footer_links_the_governing_documents(page):
    for doc in ["GOVERNANCE.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "LICENSING.md"]:
        assert doc in page


def test_license_names_are_linked(page):
    assert "apache.org/licenses/LICENSE-2.0" in page
    assert "creativecommons.org/licenses/by-sa/4.0" in page


def test_dark_theme_and_reduced_motion_are_defined():
    css = (LANDING / "assets" / "acs.css").read_text(encoding="utf-8")
    assert 'data-theme="dark"' in css
    assert "prefers-color-scheme: dark" in css
    assert "prefers-reduced-motion: reduce" in css
    svg = (LANDING / "assets" / "starburst.svg").read_text(encoding="utf-8")
    # `animation: none` does not reach SMIL, so the SVG carries its own guard.
    assert "prefers-reduced-motion: reduce" in svg


def test_focus_ring_and_muted_text_meet_contrast():
    """Encodes the measurements that four inherited token values failed."""
    css = (LANDING / "assets" / "acs.css").read_text(encoding="utf-8")

    def luminance(hex_color: str) -> float:
        h = hex_color.lstrip("#")
        channels = []
        for i in (0, 2, 4):
            c = int(h[i : i + 2], 16) / 255
            channels.append(c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4)
        return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]

    def ratio(a: str, b: str) -> float:
        la, lb = luminance(a), luminance(b)
        hi, lo = max(la, lb), min(la, lb)
        return (hi + 0.05) / (lo + 0.05)

    def token(name: str, block: str) -> str:
        section = css.split(block, 1)[1]
        return re.search(rf"{name}:\s*(#[0-9a-fA-F]{{6}})", section).group(1)

    light_ring = token("--acs-focus-ring", ":root {")
    assert ratio(light_ring, "#ffffff") >= 3.0
    dark_ring = token("--acs-focus-ring", ':root[data-theme="dark"]')
    assert ratio(dark_ring, "#0a0a0a") >= 3.0
    dark_muted = token("--acs-text-muted", ':root[data-theme="dark"]')
    assert ratio(dark_muted, "#161616") >= 4.5
    light_hex = token("--acs-hex-stroke", ":root {")
    assert ratio(light_hex, "#f4f5f7") >= 3.0


def test_built_with_section_names_the_standards(page):
    """The section carries named standards with a stated relationship, not a logo wall."""
    for standard in ["OWASP ASI", "AIVSS", "OpenTelemetry", "OCSF", "CycloneDX", "SPDX", "MCP", "A2A"]:
        assert standard in page


def test_no_dead_a2a_link(page):
    """The documentation still links a google-a2a.github.io path that now returns 404."""
    assert "google-a2a.github.io" not in page


def test_vendored_font_matches_its_recorded_checksum():
    """The checksum documents provenance. Verifying it makes the record load-bearing."""
    import hashlib

    fonts = LANDING / "assets" / "fonts"
    recorded = {}
    for line in (fonts / "CHECKSUMS.txt").read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, name = line.split()
            recorded[name.lstrip("*")] = digest
    assert recorded, "CHECKSUMS.txt is empty"
    for name, digest in recorded.items():
        actual = hashlib.sha256((fonts / name).read_bytes()).hexdigest()
        assert actual == digest, f"{name}: recorded {digest}, actual {actual}"


def test_font_license_ships_with_the_font():
    """OFL-1.1 conditions redistribution on shipping the notice and the license text."""
    text = (LANDING / "assets" / "fonts" / "OFL.txt").read_text(encoding="utf-8")
    assert "SIL Open Font License" in text
    assert "The Inter Project Authors" in text


def test_the_theme_control_is_an_icon_with_an_accessible_name(page):
    """A text button was replaced by the sun and moon readers already recognize.

    The icons are decorative, so the control carries its own accessible name and a
    visually hidden label rather than relying on the glyph.
    """
    assert 'id="theme-toggle"' in page
    assert "Switch theme" not in page.split('id="theme-toggle"')[1].split("</button>")[0].replace(
        '<span class="visually-hidden">Switch theme</span>', ""
    )
    assert 'aria-label="Switch to dark theme"' in page
    assert 'class="icon-sun"' in page and 'class="icon-moon"' in page
    assert page.count('aria-hidden="true"') >= 2


def test_only_one_theme_mark_shows_at_a_time():
    css = (LANDING / "assets" / "acs.css").read_text(encoding="utf-8")
    assert "#theme-toggle .icon-sun { display: none; }" in css
    assert ':root[data-theme="dark"] #theme-toggle .icon-moon { display: none; }' in css
    assert ".visually-hidden" in css


def test_the_sidebar_shows_the_same_mark_as_the_documentation(page):
    """The two surfaces drew the same file differently, text here and an image there."""
    assert 'src="assets/icon.svg"' in page
    assert '<img src="assets/icon.svg" alt=""' in page


def test_the_starburst_sets_its_font_on_the_root_element():
    """On the root, not merely present once.

    A declaration on the wrong element satisfies a count while leaving labels
    without a fallback stack.
    """
    starburst = (LANDING / "assets" / "starburst.svg").read_text(encoding="utf-8")
    root = ET.fromstring(starburst)
    assert "font-family" in root.attrib
    assert "sans-serif" in root.attrib["font-family"], "needs a fallback, not Inter alone"
    assert starburst.count("font-family") == 1, "the per-element copies should be gone"


def test_the_specification_is_not_listed_as_an_external_resource(page):
    """It is served from this site, so it belongs with the sections rather than beside
    GitHub and Slack."""
    rows = walk_landing(page, LANDING_ROOT)
    start = next(i for i, row in enumerate(rows) if row[1] == "External resources")
    assert rows[start][4], "External resources is a section row"
    external = []
    for depth, _label, url, _group, _section in rows[start + 1 :]:
        if depth <= rows[start][0]:
            break
        external.append(url)
    assert not [url for url in external if url.startswith(LANDING_ROOT + "docs/")], external
    hosts = {url.split("/")[2] for url in external}
    assert hosts == {"github.com", "owasp.slack.com"}, external
    docs_root = [row for row in rows[:start] if row[2] == LANDING_ROOT + "docs/"]
    assert [row[0] for row in docs_root] == [1], "the docs root sits at the top of the pane"


class _Tags:
    """Every start tag on the page, in order, with the stack of elements enclosing it."""

    def __init__(self, markup: str) -> None:
        from html.parser import HTMLParser

        void = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
                "source", "track", "wbr"}
        self.tags: list[tuple[str, dict[str, str | None], tuple[str, ...]]] = []
        stack: list[str] = []
        tags = self.tags

        class Parser(HTMLParser):
            def handle_starttag(self, tag, attrs):
                attributes = dict(attrs)
                tags.append((tag, attributes, tuple(stack)))
                if tag not in void:
                    # The pane's id rides on the stack so a test can ask what is inside it.
                    stack.append(f"{tag}#{attributes['id']}" if attributes.get("id") else tag)

            def handle_startendtag(self, tag, attrs):
                tags.append((tag, dict(attrs), tuple(stack)))

            def handle_endtag(self, tag):
                for index in range(len(stack) - 1, -1, -1):
                    if stack[index].split("#")[0] == tag:
                        del stack[index:]
                        break

        Parser().feed(markup)


def test_the_pane_is_the_only_primary_navigation(page):
    """One navigation landmark labeled Navigation. The footer's document links stay a
    separate, differently labeled landmark, and no aside wraps the pane, because a
    complementary landmark around it would announce the pane twice."""
    tags = _Tags(page).tags
    navs = [attrs.get("aria-label") for tag, attrs, _ in tags if tag == "nav"]
    assert navs == ["Navigation", "Project documents"], navs
    assert [attrs.get("id") for tag, attrs, _ in tags if tag == "nav"][0] == "site-nav"
    assert not [tag for tag, attrs, _ in tags if attrs.get("role") == "navigation"]
    assert not [tag for tag, _attrs, _ in tags if tag == "aside"]


def test_csp_meta_precedes_every_link_and_script(page):
    """A policy delivered by meta covers only what the parser reaches after it."""
    metas = [m.start() for m in re.finditer(r'<meta http-equiv="Content-Security-Policy"', page)]
    assert len(metas) == 1, metas
    assert metas[0] < page.index("</head>")
    later = [m.group(0) for m in re.finditer(r"<(link|script|style)\b", page, re.I) if m.start() < metas[0]]
    assert not later, f"loaded before the policy: {later}"


def test_csp_hashes_match_the_page_and_nothing_else_is_inline(page):
    import base64
    import hashlib

    from conftest import _NOISE, _element_bodies

    def digest(body: str) -> str:
        return base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii")

    bodies = _element_bodies(page)
    assert _inline_bodies(page) == bodies
    scripts = [body for tag, body in bodies if tag == "script"]
    styles = [body for tag, body in bodies if tag == "style"]
    assert len(scripts) == 1 and len(styles) == 1, [tag for tag, _ in bodies]
    policy = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)">', page).group(1)
    directives = {part.split()[0]: part.split()[1:] for part in policy.split(";") if part.strip()}
    assert directives["script-src"] == [f"'sha256-{digest(scripts[0])}'"]
    assert directives["style-src"] == ["'self'", f"'sha256-{digest(styles[0])}'"]

    tags = _Tags(page).tags
    assert not [tag for tag, attrs, _ in tags if "style" in attrs], "a style attribute needs unsafe-inline"
    data_uris = [f"<{tag} {name}>" for tag, attrs, _ in tags for name, value in attrs.items()
                 if value and _NOISE.sub("", value).strip().lower().startswith("data:")]
    assert not data_uris, data_uris
    assert not re.search(r"url\(\s*['\"]?\s*data:", styles[0], re.I)


def test_rendered_element_bodies_equal_the_starburst_plus_the_template(page):
    """The only inline bodies are the diagram's style and the template's script, in
    document order. Anything else came from an injected section."""
    from conftest import _element_bodies

    starburst = (LANDING / "assets" / "starburst.svg").read_text(encoding="utf-8")
    template = (LANDING / "index.html").read_text(encoding="utf-8")
    assert [tag for tag, _ in _element_bodies(starburst)] == ["style"]
    assert [tag for tag, _ in _element_bodies(template)] == ["script"]
    assert _element_bodies(page) == _element_bodies(starburst) + _element_bodies(template)


def test_menu_button_contract(page):
    """The phone strip carries a real button wired by listeners, and the skip link is
    the first thing a keyboard reaches."""
    from conftest import _element_bodies

    assert re.search(r"<body>\s*<a class=\"skip-link\" href=\"#main\">", page)
    assert '<main id="main">' in page
    assert re.search(
        r'<header class="topbar">\s*<a class="wordmark" href="\.">.*?</a>\s*'
        r'<button id="menu-toggle" type="button" aria-expanded="false" aria-controls="site-nav">'
        r"Menu</button>\s*</header>",
        page,
        re.S,
    )
    assert page.count('id="site-nav"') == 1
    scripts = [body for tag, body in _element_bodies(page) if tag == "script"]
    assert len(scripts) == 1
    script = scripts[0]
    for needle in ('getElementById("menu-toggle")', '"aria-expanded"', '"nav-open"', '"Escape"',
                   ".focus()", 'addEventListener("click"', 'addEventListener("keydown"',
                   'document.addEventListener("click"', 'addEventListener("focusout"'):
        assert needle in script, needle


def test_phone_strip_paints_above_the_open_panel():
    """The open panel overlaps the Menu button on a phone, so the strip must stack
    above the panel or the button that closes it is unreachable."""
    css = re.sub(r"/\*.*?\*/", "", (LANDING / "assets" / "acs.css").read_text(encoding="utf-8"), flags=re.S)
    phone = css[css.index("@media (max-width: 1024px)"):]
    strip = " ".join(re.search(r"\.topbar\s*\{(.*?)\}", phone, re.S).group(1).split())
    panel = " ".join(re.search(r"\.has-drawer \.sidebar\s*\{(.*?)\}", phone, re.S).group(1).split())
    assert "position: relative;" in strip, strip
    strip_z = int(re.search(r"z-index: (\d+);", strip).group(1))
    panel_z = int(re.search(r"z-index: (\d+);", panel).group(1))
    assert strip_z > panel_z, (strip_z, panel_z)
    # The strip now covers the panel's top, so the first row must start below it.
    assert "padding-top: calc(40px + 3rem);" in panel, panel


def test_pane_row_ceilings(page):
    """A row is visible when every group above it is open. A section never closes."""
    from test_site_nav import CEILING_WITH_EVERY_GROUP_CLOSED, CEILING_WITH_PAGE_OPEN_SET, REPAIR

    rows = walk_landing(page, LANDING_ROOT)
    assert rows
    sections = {label for _depth, label, _url, _group, is_section in rows if is_section}

    def visible(opened: frozenset[str]) -> int:
        always = opened | sections
        return sum(all(label in always for label in ancestor_labels(rows, index))
                   for index in range(len(rows)))

    shown = visible(landing_open_labels(page))
    assert shown <= CEILING_WITH_PAGE_OPEN_SET, REPAIR["ceiling"].format(n=shown)
    closed = visible(frozenset())
    assert closed <= CEILING_WITH_EVERY_GROUP_CLOSED, REPAIR["ceiling"].format(n=closed)


def test_sidebar_keeps_its_own_scroll(page):
    """The column scrolls by itself, so the theme toggle below the pane stays reachable
    when the open pane is taller than the viewport."""
    css = re.sub(r"/\*.*?\*/", "", (LANDING / "assets" / "acs.css").read_text(encoding="utf-8"), flags=re.S)
    top_level, depth, start = [], 0, 0
    for index, char in enumerate(css):
        if char == "{":
            if depth == 0:
                selector, start = css[start:index].strip(), index + 1
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                top_level.append((selector, css[start:index]))
                start = index + 1
    rules = [" ".join(body.split()) for selector, body in top_level if selector == ".sidebar"]
    assert len(rules) == 1, rules
    assert "height: 100vh;" in rules[0] and "overflow-y: auto;" in rules[0], rules[0]
    sidebar = page[page.index('<div class="sidebar">'):page.index("<main")]
    assert sidebar.index('id="site-nav"') < sidebar.index('id="theme-toggle"')


def test_no_pane_link_has_target_or_rel(page):
    """Every pane link navigates in place. A target opens a window the policy does not
    govern, and a rel can make a link prefetch."""
    links = [attrs for tag, attrs, stack in _Tags(page).tags if tag == "a" and "nav#site-nav" in stack]
    assert len(links) >= 12
    assert not [attrs for attrs in links if "target" in attrs or "rel" in attrs]
