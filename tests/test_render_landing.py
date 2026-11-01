"""Tests for build-time content injection.

Build inputs reach the page, so the escaping cases are the point.
"""
import base64
import dataclasses
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import render_landing
import site_nav
from publish_schemas import BASE
from render_landing import (
    RenderError, page_url, parse_priority_scope, read_nav_config, render,
    release_version, render_csp, render_nav, render_priority_scope, 
    schema_count, spec_version,
)

REPO = Path(__file__).resolve().parents[1]
NAV = read_nav_config(REPO / "mkdocs.yml")
# An inline SVG with one style, the shape of the real diagram, so the policy has one
# style body to hash.
STARBURST = "<svg><style>a{}</style></svg>"
REPAIR_HINT = "Edit `mkdocs.yml` on a branch from `integration`"
# Unlike the spec tree's v0.1.0, so a test cannot pass on the wrong number.
RELEASE_FILE = "9.8.7\n"

CONTRIBUTING = """# Contributing to ACS

## Current Priority Scope

Reviewed at each milestone. Current window: Day 0 to Day 30.

The project has one committed outcome:

> A runnable Guardian Agent reference implementation, benchmarked for
> interoperability against Microsoft Agent Governance Toolkit, in the hands
> of external evaluators within ninety days of the September 10, 2026
> kick-off.

Every issue and every pull request is accepted against that sentence.

## How work gets accepted

Anyone may open an issue.
"""

CONTRIBUTING_SCOPE = (
    "A runnable Guardian Agent reference implementation, benchmarked for "
    "interoperability against Microsoft Agent Governance Toolkit, in the hands "
    "of external evaluators within ninety days of the September 10, 2026 "
    "kick-off."
)



FULL_TEMPLATE = "".join(render_landing.REQUIRED_PLACEHOLDERS) + "<script>var x=1;</script>"


@pytest.fixture
def spec_tree(tmp_path: Path) -> Path:
    root = tmp_path / "specification"
    (root / "v0.1.0").mkdir(parents=True)
    for name in ("a.json", "b.json"):
        (root / "v0.1.0" / name).write_text(
            json.dumps({"$id": BASE + f"v0.1.0/{name}"}), encoding="utf-8")
    return root


def test_spec_version_reads_the_id_namespace(spec_tree):
    assert spec_version(spec_tree) == "v0.1.0"


def test_schema_count_counts_every_schema(spec_tree):
    assert schema_count(spec_tree) == 2


def test_spec_version_returns_the_highest_of_several(tmp_path):
    """Old versions stay published, so more than one is the steady state."""
    root = tmp_path / "specification"
    root.mkdir()
    for version in ("v0.1.0", "v0.2.0", "v0.10.0"):
        path = root / version / "x.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"$id": BASE + f"{version}/x.json"}), encoding="utf-8")
    assert spec_version(root) == "v0.10.0"


@pytest.fixture
def multi_version_tree(tmp_path):
    """Two versions, with the newer holding fewer schemas.

    Both numbers differ from the total, or an assertion cannot tell "count within
    the reported version" from "count everything".
    """
    from conftest import write_schema

    src = tmp_path / "spec"
    for name in ("a", "b", "c"):
        write_schema(src, f"v0.2.0/{name}.json", BASE + f"v0.2.0/{name}.json")
    for name in ("d", "e"):
        write_schema(src, f"v0.10.0/{name}.json", BASE + f"v0.10.0/{name}.json")
    return src


def test_the_count_belongs_to_the_version_it_is_printed_beside(multi_version_tree):
    version, count = render_landing._schema_facts(multi_version_tree)
    assert version == "v0.10.0"
    assert count == 2, "counting all five states a number about the wrong version"


def test_version_order_is_numeric_not_lexicographic(multi_version_tree):
    """v0.10.0 sorts above v0.2.0 only under a numeric key.

    The single-version fixture this replaced could not tell the two apart, so a
    deliberately broken comparison still passed.
    """
    assert render_landing._schema_facts(multi_version_tree)[0] == "v0.10.0"
    assert render_landing.spec_version(multi_version_tree) == "v0.10.0"


def test_main_reports_a_copy_failure_without_a_traceback(tmp_path, monkeypatch, capsys):
    """The fixture carries every placeholder, or render raises before the copy.

    main() resolves the schema source from __file__, not the working directory, so
    it reads the real specification/ tree and no chdir is needed.
    """
    landing = tmp_path / "landing"
    (landing / "assets").mkdir(parents=True)
    (landing / "index.html").write_text(FULL_TEMPLATE)
    (landing / "assets" / "starburst.svg").write_text(STARBURST)

    def boom(*args, **kwargs):
        raise OSError("assets unreadable")

    monkeypatch.setattr(render_landing.shutil, "copytree", boom)
    assert render_landing.main(["render_landing.py", str(landing), str(tmp_path / "out")]) == 1
    assert "assets unreadable" in capsys.readouterr().err


# --- priority scope parsing ------------------------------------------------

def test_parse_priority_scope_reads_the_committed_outcome():
    assert parse_priority_scope(CONTRIBUTING) == CONTRIBUTING_SCOPE


def test_parse_priority_scope_fails_without_the_heading():
    with pytest.raises(RenderError, match="Current Priority Scope"):
        parse_priority_scope("# Contributing to ACS\n\nNothing here.\n")


def test_parse_priority_scope_fails_without_a_blockquote():
    """A heading with prose but no committed-outcome quote must not render silently."""
    text = CONTRIBUTING.replace(
        "> A runnable Guardian Agent reference implementation, benchmarked for\n"
        "> interoperability against Microsoft Agent Governance Toolkit, in the hands\n"
        "> of external evaluators within ninety days of the September 10, 2026\n"
        "> kick-off.\n",
        "",
    )
    with pytest.raises(RenderError, match="blockquote"):
        parse_priority_scope(text)


def test_parse_priority_scope_handles_the_real_file():
    scope = parse_priority_scope((REPO / "CONTRIBUTING.md").read_text(encoding="utf-8"))
    assert scope.startswith("A runnable Guardian Agent reference implementation")
    assert "Microsoft Agent Governance Toolkit" in scope


# --- escaping -------------------------------------------------------------

def parse_attributes(markup: str) -> list[tuple[str, list[tuple[str, str | None]]]]:
    """Return (tag, attributes) for every start tag.

    String matching is the wrong tool here. A safely escaped payload still contains the
    literal text `onfocus=` inside an attribute value, so grepping for it reports a
    breakout that does not exist. Only a parser answers whether an attribute is real.
    """
    from html.parser import HTMLParser

    class Collector(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.tags: list[tuple[str, list[tuple[str, str | None]]]] = []

        def handle_starttag(self, tag, attrs):
            self.tags.append((tag, attrs))

    collector = Collector()
    collector.feed(markup)
    return collector.tags


def test_render_priority_scope_escapes_raw_html():
    """The blockquote is a build input, reviewed for wording, not markup."""
    scope = parse_priority_scope(CONTRIBUTING.replace(
        "A runnable Guardian Agent reference implementation,",
        "A runnable Guardian Agent <script>alert(1)</script> reference implementation,",
    ))
    out = render_priority_scope(scope)
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


# --- placeholders ---------------------------------------------------------

def test_render_fills_every_placeholder(spec_tree):
    out = render(FULL_TEMPLATE, spec_tree, CONTRIBUTING, STARBURST, NAV, RELEASE_FILE)
    assert "v0.1.0" in out and "Identity" in out and STARBURST in out
    assert 'aria-label="Navigation"' in out and "Content-Security-Policy" in out
    assert CONTRIBUTING_SCOPE in out


def test_render_fills_the_release_from_version_txt(spec_tree):
    template = FULL_TEMPLATE + "<!--ACS:RELEASE_VERSION-->"
    out = render(template, spec_tree, CONTRIBUTING, STARBURST, NAV, RELEASE_FILE)
    assert out.count("9.8.7") == 2
    assert "<!--ACS:" not in out


def test_render_fails_when_the_template_drops_the_release(spec_tree):
    without = FULL_TEMPLATE.replace("<!--ACS:RELEASE_VERSION-->", "")
    with pytest.raises(RenderError, match="RELEASE_VERSION"):
        render(without, spec_tree, CONTRIBUTING, STARBURST, NAV, RELEASE_FILE)


@pytest.mark.parametrize("text", ["", "0.1", "v0.1.4", '0.1.4"><script>', "0.1.4\n0.1.5\n"])
def test_release_version_refuses_anything_but_a_semantic_version(text):
    with pytest.raises(RenderError, match="version.txt"):
        release_version(text)


@pytest.mark.parametrize("text, expected", [("0.1.4\n", "0.1.4"), (" 1.2.3-rc.1 ", "1.2.3-rc.1")])
def test_release_version_trims_the_file(text, expected):
    assert release_version(text) == expected


def test_main_fails_when_version_txt_is_missing(tmp_path, monkeypatch, capsys):
    real_read_text = Path.read_text

    def read_text(self, *args, **kwargs):
        if self.name == "version.txt":
            raise FileNotFoundError(str(self))
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read_text)
    assert render_landing.main(["render_landing.py", str(REPO / "landing"), str(tmp_path)]) == 1
    assert "version.txt" in capsys.readouterr().err


def test_render_derives_the_schema_href_from_the_version(spec_tree):
    out = render(FULL_TEMPLATE, spec_tree, CONTRIBUTING, STARBURST, NAV, RELEASE_FILE)
    assert "schema/v0.1.0/acs_schema.json" in out


def test_render_fails_when_the_template_drops_a_placeholder(spec_tree):
    """A template missing the hero would otherwise ship a blank div with no error."""
    without = FULL_TEMPLATE.replace("<!--ACS:STARBURST-->", "")
    with pytest.raises(RenderError, match="STARBURST"):
        render(without, spec_tree, CONTRIBUTING, STARBURST, NAV, RELEASE_FILE)


def test_header_values_are_escaped_and_validated(spec_tree):
    """site_name reaches attributes, so a quote must not end one, and a markup character
    stops the build rather than reaching the page."""
    quoted = dataclasses.replace(NAV, site_name='A"B')
    template = FULL_TEMPLATE + '<a title="<!--ACS:SITE_NAME-->">'
    assert '<a title="A&quot;B">' in render(template, spec_tree, CONTRIBUTING, STARBURST, quoted, RELEASE_FILE)
    for field, value in (("site_name", "<b>"), ("repo_name", "a&b"), ("repo_url", "https://evil.example/")):
        with pytest.raises(RenderError, match=field):
            render(FULL_TEMPLATE, spec_tree, CONTRIBUTING, STARBURST,
                   dataclasses.replace(NAV, **{field: value}), RELEASE_FILE)


def test_render_fails_when_an_unknown_placeholder_survives(spec_tree):
    with pytest.raises(RenderError, match="unfilled placeholder"):
        render(FULL_TEMPLATE + "<!--ACS:UNKNOWN-->", spec_tree, CONTRIBUTING, STARBURST, NAV, RELEASE_FILE)


def test_main_does_not_republish_the_inlined_diagram(tmp_path):
    """The diagram is inlined, so publishing it again ships a second copy that can drift."""
    import render_landing

    assert render_landing.main(["render_landing.py", str(REPO / "landing"), str(tmp_path)]) == 0
    assert not (tmp_path / "assets" / "starburst.svg").exists()
    assert (tmp_path / "assets" / "acs.css").is_file()


def test_main_publishes_the_demo_the_page_points_at(tmp_path):
    assert render_landing.main(["render_landing.py", str(REPO / "landing"), str(tmp_path)]) == 0
    page = (tmp_path / "index.html").read_text(encoding="utf-8")
    for name in ("demo.mp4", "demo-poster.jpg"):
        assert f'"assets/video/{name}"' in page
        assert (tmp_path / "assets" / "video" / name).stat().st_size > 0
    assert (tmp_path / "assets" / "icon.svg").is_file()


# --- navigation pane --------------------------------------------------------

LANDING_ROOT = "https://example.org/agent-control-standard/"


def with_nav(*entries) -> render_landing.NavConfig:
    return dataclasses.replace(NAV, nav=tuple(entries))


def raises_naming(entry: str, pattern: str | None = None):
    """Every validation failure names the entry, the rule, and where to fix it."""

    class Check:
        def __enter__(self):
            self.inner = pytest.raises(RenderError)
            self.info = self.inner.__enter__()
            return self.info

        def __exit__(self, *exc):
            handled = self.inner.__exit__(*exc)
            message = str(self.info.value)
            assert entry in message, message
            assert REPAIR_HINT in message, message
            if pattern is not None:
                assert pattern in message, message
            return handled

    return Check()


@pytest.mark.parametrize("path, url", [
    ("README.md", "./"),
    ("index.md", "./"),
    ("concepts/README.md", "concepts/"),
    ("concepts/index.md", "concepts/"),
    ("topics/faq.md", "topics/faq/"),
    ("spec/trace/OCSF/implementation_examples.md", "spec/trace/OCSF/implementation_examples/"),
    ("topics/my page.md", "topics/my%20page/"),
])
def test_page_url_matches_mkdocs_rule(path, url):
    assert page_url(path) == url


def _expected_rows(nav, depth):
    for entry in nav:
        ((title, value),) = entry.items()
        if isinstance(value, list):
            yield depth, title, None
            yield from _expected_rows(value, depth + 1)
        else:
            yield depth, title, LANDING_ROOT + "docs/" + ("" if page_url(value) == "./" else page_url(value))


def test_render_nav_emits_the_pane_in_order():
    rows = site_nav.walk_landing(render_nav(NAV), LANDING_ROOT)
    expected = [(1, "Home", LANDING_ROOT)]
    expected += [(2, s["title"], LANDING_ROOT + "#" + s["anchor"]) for s in NAV.landing_sections]
    expected += list(_expected_rows(NAV.nav, 1))
    expected += [(1, "External resources", None)]
    expected += [(2, r["title"], r["url"]) for r in NAV.external_resources]
    assert [(depth, label, url) for depth, label, url, _group, _section in rows] == expected
    # The design's count, so a walker and a renderer that drop the same row still fail.
    assert len(rows) == 52
    by_label = {row[1]: row for row in rows}
    assert by_label["Trustworthy Agents"][2] == LANDING_ROOT + "docs/"
    assert by_label["FAQ"][2] == LANDING_ROOT + "docs/topics/faq/"
    assert by_label["Home"][3] is True and by_label["External resources"][4] is True
    assert site_nav.landing_open_labels(render_nav(NAV)) == {"Home"}
    assert site_nav.aria_current_links(render_nav(NAV)) == [("a", "./")]


def test_render_nav_emits_no_target_or_rel():
    attrs = [name for _, pairs in parse_attributes(render_nav(NAV)) for name, _ in pairs]
    assert "target" not in attrs and "rel" not in attrs
    assert 'href="/"' not in render_nav(NAV)


@pytest.mark.parametrize("title", ["Trace & Inspect", "<code>hooks</code>", "a > b", "Title\n"])
def test_title_with_markup_raises_naming_the_entry(title):
    """Review Focus 1: a split pane is worse than a failed build."""
    nav = with_nav({"Specification": [{title: "spec/conformance.md"}]})
    with raises_naming(repr(title), site_nav.TITLE.pattern):
        render_nav(nav)


def test_section_and_resource_titles_are_validated():
    sections = ({"title": "<b>x</b>", "anchor": "problem"},)
    with raises_naming("'<b>x</b>'", site_nav.TITLE.pattern):
        render_nav(dataclasses.replace(NAV, landing_sections=sections))
    resources = ({"title": "a & b", "url": site_nav.REPO_URL},)
    with raises_naming("'a & b'", site_nav.TITLE.pattern):
        render_nav(dataclasses.replace(NAV, external_resources=resources))


@pytest.mark.parametrize("anchor", ["", "1st", "has space", 'x" onfocus="a', "problem\n", "#problem"])
def test_bad_anchor_raises(anchor):
    sections = ({"title": "The problem", "anchor": anchor},)
    with raises_naming(repr(anchor), site_nav.ANCHOR.pattern):
        render_nav(dataclasses.replace(NAV, landing_sections=sections))


@pytest.mark.parametrize("url", [
    "javascript:alert(1)",
    "JavaScript:alert(1)",
    "java\nscript:alert(1)",
    "java\tscript:alert(1)",
    "https://github.com/x\n",
    "https://github.com/\rx",
    "data:text/html,x",
])
def test_url_with_javascript_scheme_or_newline_raises(url):
    # A browser deletes tabs and line breaks before parsing, so they get their own rule.
    reason = "tab or line break" if any(c in url for c in "\t\r\n") else None
    with raises_naming(repr(url), reason):
        render_nav(with_nav({"Bad": url}))
    resources = ({"title": "Bad", "url": url},)
    with raises_naming(repr(url), reason):
        render_nav(dataclasses.replace(NAV, external_resources=resources))


@pytest.mark.parametrize("url", [
    "https://github.com/\\evil.example",
    "https://github.com/x\\y",
    "https://github.com/@evil.example/",
    "https://github.com/user@evil.example",
    "https://github.com/a:b",
])
def test_url_with_backslash_or_userinfo_raises(url):
    reason = "backslash, an @, or a colon after the scheme"
    with raises_naming(repr(url), reason):
        render_nav(with_nav({"Bad": url}))
    resources = ({"title": "Bad", "url": url},)
    with raises_naming(repr(url), reason):
        render_nav(dataclasses.replace(NAV, external_resources=resources))


@pytest.mark.parametrize("url", [
    "https://evil.example/",
    "http://github.com/",
    "https://github.com.evil.example/",
    "https://owasp.slack.com.evil.example",
    "//github.com/x",
    "/docs/",
    "ftp://github.com/",
])
def test_external_url_outside_the_two_hosts_raises(url):
    with raises_naming(repr(url), site_nav.EXTERNAL_URL.pattern):
        render_nav(with_nav({"Bad": url}))
    resources = ({"title": "Bad", "url": url},)
    with raises_naming(repr(url), site_nav.EXTERNAL_URL.pattern):
        render_nav(dataclasses.replace(NAV, external_resources=resources))


@pytest.mark.parametrize("url", [
    'https://github.com/x" onmouseover="alert(1)',
    "https://github.com/x' onmouseover='alert(1)",
    "https://github.com/x><script>alert(1)</script>",
    "https://github.com/x onmouseover=alert(1)",
])
def test_attribute_breakout_in_an_external_url_is_rejected(url):
    """The host prefix matches, so only the character rule stands between the value
    and a new attribute. Escaping would make it inert. Rejecting keeps a review honest."""
    reason = render_landing.URL_CHARS.pattern
    with raises_naming(repr(url), reason):
        render_nav(with_nav({"Bad": url}))
    resources = ({"title": "Bad", "url": url},)
    with raises_naming(repr(url), reason):
        render_nav(dataclasses.replace(NAV, external_resources=resources))


def test_a_doc_path_outside_the_pattern_raises():
    for path in ("../secrets.md", "a/../../b.md", "page.html", 'x".md'):
        with raises_naming(repr(path), site_nav.DOC_PATH.pattern):
            render_nav(with_nav({"Bad": path}))


def test_bare_string_entry_raises():
    with raises_naming("'about.md'", "bare string"):
        render_nav(with_nav({"ACS": "acs.md"}, "about.md"))
    with raises_naming("untitled"):
        render_nav(with_nav({"ACS": "acs.md"}, ["about.md"]))
    with raises_naming("untitled"):
        render_nav(with_nav({None: [{"ACS": "acs.md"}]}))


def test_every_value_is_escaped():
    """Quotes pass every pattern but must not close the attribute or the text node."""
    nav = with_nav({'Say "hi" it\'s': "acs.md"})
    out = render_nav(nav)
    assert "Say &quot;hi&quot; it&#x27;s" in out


# --- content security policy --------------------------------------------------

def _hash(body: str) -> str:
    return base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii")


def test_csp_hashes_the_one_script_and_one_style():
    page = (
        "<!-- <script>not this</script> --><svg><style>\n a{fill:red} \n</style></svg>"
        "<p>x</p><script>\n  var x = 1;\n</script>"
    )
    assert render_csp(page) == (
        '<meta http-equiv="Content-Security-Policy" content="'
        "default-src 'none'; "
        f"script-src 'sha256-{_hash(chr(10) + '  var x = 1;' + chr(10))}'; "
        f"style-src 'self' 'sha256-{_hash(chr(10) + ' a{fill:red} ' + chr(10))}'; "
        "img-src 'self'; media-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'"
        '">'
    )


def test_csp_raises_on_two_scripts():
    with pytest.raises(RenderError, match="script"):
        render_csp("<style>a{}</style><script>a</script><script>b</script>")
    with pytest.raises(RenderError, match="style"):
        render_csp("<style>a{}</style><style>b{}</style><script>a</script>")
    with pytest.raises(RenderError, match="script"):
        render_csp("<style>a{}</style>")


@pytest.mark.parametrize("body", ["a{content:'&amp;'}", "a{content:'&#60;'}", "a{} <!-- x -->"])
def test_csp_raises_on_an_entity_in_the_style_body(body):
    """An SVG style is foreign content, decoded before the browser hashes it."""
    with pytest.raises(RenderError, match="style"):
        render_csp(f"<svg><style>{body}</style></svg><script>a</script>")


def test_render_succeeds_with_no_built_docs_present(tmp_path, monkeypatch):
    """The landing render runs before the docs build in no particular order, so it must
    read nothing a docs build produces."""
    read: list[Path] = []
    original_read_text, original_open = Path.read_text, Path.open

    def spy_read_text(self, *args, **kwargs):
        read.append(self.resolve())
        return original_read_text(self, *args, **kwargs)

    def spy_open(self, *args, **kwargs):
        read.append(self.resolve())
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", spy_read_text)
    monkeypatch.setattr(Path, "open", spy_open)
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "out"
    assert render_landing.main(["render_landing.py", str(REPO / "landing"), str(out)]) == 0
    assert (REPO / "mkdocs.yml").resolve() in read
    built = [path for path in read if {"site", "_site"} & set(path.relative_to(path.anchor).parts)]
    assert not built, built
    page = (out / "index.html").read_text(encoding="utf-8")
    assert 'aria-label="Navigation"' in page


def test_inline_bodies_match_conftests_rule_on_the_real_page():
    from conftest import _element_bodies

    page = render(
        (REPO / "landing" / "index.html").read_text(encoding="utf-8"),
        REPO / "specification",
        (REPO / "CONTRIBUTING.md").read_text(encoding="utf-8"),
        (REPO / "landing" / "assets" / "starburst.svg").read_text(encoding="utf-8"),
        NAV,
        (REPO / "version.txt").read_text(encoding="utf-8"),
    )
    bodies = render_landing._inline_bodies(page)
    assert bodies == _element_bodies(page)
    assert sorted(tag for tag, _ in bodies) == ["script", "style"]
