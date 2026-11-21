"""Guards on the documentation site's theme and its published URLs.

The canonical bug these cover was invisible to every earlier test, because none of them
compared the URL a page declares against the path it is published at.
"""
import re
from pathlib import Path

import pytest
from _docs_build import DOCS_BASE

REPO = Path(__file__).resolve().parents[1]


def test_every_canonical_matches_the_page_path(built_docs):
    """A canonical that omits /docs/ names a URL that does not exist."""
    wrong = []
    for page in built_docs.rglob("index.html"):
        match = re.search(r'rel="canonical" href="([^"]+)"', page.read_text(encoding="utf-8"))
        if not match:
            continue
        relative = page.parent.relative_to(built_docs).as_posix()
        expected = DOCS_BASE if relative == "." else f"{DOCS_BASE}{relative}/"
        if match.group(1) != expected:
            wrong.append((relative, match.group(1)))
    assert not wrong, f"canonical does not match publish path: {wrong[:5]}"


def test_sitemap_urls_sit_under_the_docs_path(built_docs):
    sitemap = built_docs / "sitemap.xml"
    if not sitemap.exists():
        import gzip
        text = gzip.open(built_docs / "sitemap.xml.gz", "rt").read()
    else:
        text = sitemap.read_text(encoding="utf-8")
    urls = re.findall(r"<loc>([^<]+)</loc>", text)
    assert urls, "sitemap has no entries"
    assert all(u.startswith(DOCS_BASE) for u in urls), [u for u in urls if not u.startswith(DOCS_BASE)][:5]


def test_docs_stylesheet_declares_the_acs_tokens():
    css = (REPO / "docs" / "stylesheets" / "extra.css").read_text(encoding="utf-8")
    for token in ['[data-md-color-scheme="default"]', '[data-md-color-scheme="slate"]',
                  "--md-text-font", "--md-typeset-a-color"]:
        assert token in css


def test_docs_use_the_same_mark_as_the_landing_page():
    config = (REPO / "mkdocs.yml").read_text(encoding="utf-8")
    assert "logo: assets/icon.svg" in config
    assert "favicon: assets/icon.svg" in config
    assert (REPO / "docs" / "assets" / "icon.svg").is_file()


def test_the_two_copies_of_the_mark_stay_identical():
    """MkDocs needs the logo inside docs_dir, so the file exists twice. Nothing else
    keeps the copies in step."""
    assert (REPO / "docs" / "assets" / "icon.svg").read_bytes() == \
        (REPO / "landing" / "assets" / "icon.svg").read_bytes()


def test_docs_do_not_call_the_github_api_at_runtime(built_docs):
    """Material fetches star counts from api.github.com when this hook is present.

    A runtime fetch is invisible to the markup-scanning guards, so this asserts the
    trigger is absent rather than trying to find the request.
    """
    for page in built_docs.rglob("*.html"):
        assert 'data-md-component="source"' not in page.read_text(encoding="utf-8")


def test_repository_link_survives_the_override(built_docs):
    """Dropping the fetch must not drop the link it decorated."""
    index = (built_docs / "index.html").read_text(encoding="utf-8")
    assert 'class="md-source"' in index
    assert "github.com/GenAI-Security-Project/agent-control-standard" in index


def test_the_header_keeps_its_repository_icon(built_docs):
    """The icon vanished once when this partial was rewritten and a person had to catch it.

    Asserting the mark is inlined turns a silent regression into a failing build. The
    fetch hook staying absent is covered separately, and both have to hold together.
    """
    index = (built_docs / "index.html").read_text(encoding="utf-8")
    match = re.search(r'class="md-source__icon md-icon">\s*(<svg.*?</svg>)', index, re.S)
    assert match, "the repository icon is not inlined in the header"
    assert "viewBox" in match.group(1)
    assert 'data-md-component="source"' not in index


def test_the_theme_still_styles_the_override():
    """The override uses the theme's class names, which the theme's stylesheet supplies.

    Writing the partial for this project means nothing tracks upstream markup. What still
    has to hold is that these classes exist, because a rename upstream would leave the
    header rendering unstyled with every other test passing.
    """
    import material

    stylesheets = Path(material.__file__).parent / "templates" / "assets" / "stylesheets"
    css = "".join(p.read_text(encoding="utf-8") for p in stylesheets.glob("main.*.css"))
    if not css:
        pytest.skip("installed Material layout differs, nothing to compare")
    for klass in [".md-source", ".md-source__repository", ".md-nav__container", ".md-nav__toggle",
                  ".md-nav__item--section"]:
        assert klass in css, f"{klass} is gone from the installed theme"


def test_docs_palette_is_a_two_state_sun_and_moon_toggle():
    """Three states and a switch glyph did not match the landing page's control."""
    config = (REPO / "mkdocs.yml").read_text(encoding="utf-8")
    assert "material/weather-night" in config
    assert "material/weather-sunny" in config
    assert "toggle-switch" not in config
    assert config.count("media: \"(prefers-color-scheme") == 2


def test_link_colour_survives_the_theme_default_palette(built_docs):
    """Material's palette sets --md-typeset-a-color from its default indigo primary.

    The scheme rules alone tie with it at equal specificity, so the ACS value only wins
    when the selector also matches the primary attribute the built pages always carry.
    """
    css = (REPO / "docs" / "stylesheets" / "extra.css").read_text(encoding="utf-8")
    assert '[data-md-color-scheme="slate"][data-md-color-primary]' in css
    assert '[data-md-color-scheme="default"][data-md-color-primary]' in css
    # The pages must still carry the attribute the fix depends on.
    index = (built_docs / "index.html").read_text(encoding="utf-8")
    assert "data-md-color-primary=" in index


def test_docs_contrast_tokens_meet_wcag_aa():
    """Verify light syntax tokens, footer tokens, and search status bar all meet 4.5:1."""
    css = (REPO / "docs" / "stylesheets" / "extra.css").read_text(encoding="utf-8")

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

    def block(selector: str) -> str:
        start = css.index(selector)
        return css[start : css.index("}", start)]

    def token(section: str, name: str) -> str:
        match = re.search(rf"(?<![-\w]){re.escape(name)}:\s*(#[0-9a-fA-F]{{6}})", section)
        assert match, f"missing {name} in {section!r}"
        return match.group(1)

    light = block('[data-md-color-scheme="default"] {')
    code_bg = token(light, "--md-code-bg-color")
    for name in (
        "--md-code-hl-number-color",
        "--md-code-hl-special-color",
        "--md-code-hl-function-color",
        "--md-code-hl-constant-color",
        "--md-code-hl-keyword-color",
        "--md-code-hl-string-color",
        "--md-code-hl-comment-color",
        "--md-default-fg-color--lighter",
    ):
        color = token(light, name)
        assert ratio(color, code_bg) >= 4.5, f"{name} ({color}) on {code_bg} < 4.5:1"

    for scheme in ('[data-md-color-scheme="default"] {', '[data-md-color-scheme="slate"] {'):
        sec = block(scheme)
        bg_dark = token(sec, "--md-footer-bg-color--dark")
        for fg_name in ("--md-footer-fg-color", "--md-footer-fg-color--light", "--md-footer-fg-color--lighter"):
            fg = token(sec, fg_name)
            assert ratio(fg, bg_dark) >= 4.5, f"{scheme} {fg_name} ({fg}) on {bg_dark} < 4.5:1"

    light_meta = block('[data-md-color-scheme="default"] .md-search-result__meta')
    assert ratio(token(light_meta, "color"), token(light_meta, "background-color")) >= 4.5
    dark_meta = block('[data-md-color-scheme="slate"] .md-search-result__meta')
    assert ratio(token(dark_meta, "color"), token(dark_meta, "background-color")) >= 4.5


def test_docs_accessibility_rules_and_keyboard_controls(built_docs):
    """Pin prose underlines, mobile drawer/search visibility, search wrapping, and header triggers."""
    css = (REPO / "docs" / "stylesheets" / "extra.css").read_text(encoding="utf-8")
    assert "text-decoration: underline;" in css
    assert ".md-sidebar--primary" in css and "visibility: hidden;" in css
    assert ".md-search__inner" in css
    assert ".md-search-result__article pre > code" in css and "white-space: pre-wrap;" in css

    index = (built_docs / "index.html").read_text(encoding="utf-8")
    assert 'class="md-header__button md-icon acs-drawer-toggle"' in index
    assert 'aria-label="Menu"' in index and 'aria-expanded="false"' in index
    assert 'for="__search" role="button" tabindex="0" aria-label="Search"' in index

    mermaid_init = (REPO / "docs" / "assets" / "javascripts" / "mermaid-init.js").read_text(encoding="utf-8")
    assert 'edgeLabelBackground: "#161616"' in mermaid_init
    assert 'textColor: "#f7f7f7"' in mermaid_init
