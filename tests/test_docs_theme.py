"""Guards on the documentation site's theme and its published URLs.

The canonical bug these cover was invisible to every earlier test, because none of them
compared the URL a page declares against the path it is published at.
"""
import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DOCS_BASE = "https://example.org/agent-control-standard/docs/"


@pytest.fixture(scope="module")
def built_docs(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("docs")
    env = dict(os.environ)
    env.pop("GOOGLE_ANALYTICS_KEY", None)
    env["GITHUB_PAGES_URL"] = DOCS_BASE
    result = subprocess.run(
        ["uv", "run", "mkdocs", "build", "--strict", "-d", str(out)],
        cwd=REPO, env=env, capture_output=True, text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"mkdocs build failed:\n{result.stdout}\n{result.stderr}")
    return out


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
    for klass in [".md-source", ".md-source__repository"]:
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
