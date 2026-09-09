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
from render_landing import render

REPO = Path(__file__).resolve().parents[1]
LANDING = REPO / "landing"


@pytest.fixture(scope="module")
def page() -> str:
    return render(
        (LANDING / "index.html").read_text(encoding="utf-8"),
        REPO / "specification",
        (REPO / "GOVERNANCE.md").read_text(encoding="utf-8"),
        (LANDING / "assets" / "starburst.svg").read_text(encoding="utf-8"),
    )


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

    class Collector(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.handlers: list[str] = []
            self.schemes: list[str] = []

        def handle_starttag(self, tag, attrs):
            for name, value in attrs:
                if name.startswith("on"):
                    self.handlers.append(f"<{tag} {name}>")
                if name in ("href", "src") and value and value.lower().startswith("javascript:"):
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
    # "External resources" names both the <h2> and the nav's aria-label, so the nav
    # content follows the last occurrence, not the first.
    external = page.split("External resources")[-1].split("</nav>")[0]
    assert "docs/" not in external
    assert "github.com" in external and "owasp.slack.com" in external
    sections = page.split('aria-label="Sections"')[1].split("</nav>")[0]
    assert 'href="docs/"' in sections
