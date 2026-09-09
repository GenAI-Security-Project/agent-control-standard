"""Tests for build-time content injection.

GOVERNANCE.md reaches an HTML attribute position, so the escaping cases are the point.
A roster pull request is reviewed for names and handles, not for quoting.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import render_landing
from publish_schemas import BASE
from render_landing import (
    RenderError, parse_workstreams, render, render_workstreams, schema_count, spec_version,
)

REPO = Path(__file__).resolve().parents[1]

GOVERNANCE = """# Governance

## Project lead

| Role | Name |
| --- | --- |
| Project Lead | Rock Lambros ([@rocklambros](https://github.com/rocklambros)) |

## Workstream leads

Prose that must not be parsed as a row.

| Workstream | Leads |
| --- | --- |
| Identity | Eva Benn ([@evabenn](https://github.com/evabenn)) |
| Spec | Bar Kaduri ([@bar-capsule](https://github.com/bar-capsule)) |

## Origins

Not a workstream.
"""

FULL_TEMPLATE = (
    "<!--ACS:SPEC_VERSION--><!--ACS:SCHEMA_COUNT--><!--ACS:SCHEMA_HREF-->"
    "<tbody><!--ACS:WORKSTREAMS--></tbody><div><!--ACS:STARBURST--></div>"
)


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
    (landing / "index.html").write_text("".join(render_landing.REQUIRED_PLACEHOLDERS))
    (landing / "assets" / "starburst.svg").write_text("<svg></svg>")

    def boom(*args, **kwargs):
        raise OSError("assets unreadable")

    monkeypatch.setattr(render_landing.shutil, "copytree", boom)
    assert render_landing.main(["render_landing.py", str(landing), str(tmp_path / "out")]) == 1
    assert "assets unreadable" in capsys.readouterr().err


# --- governance parsing ---------------------------------------------------

def test_parse_workstreams_reads_only_the_workstream_table():
    assert [name for name, _ in parse_workstreams(GOVERNANCE)] == ["Identity", "Spec"]


def test_parse_workstreams_accepts_heading_case_and_spacing():
    """A formatter or a title-case edit must not take the site down."""
    for heading in ("## Workstream Leads", "## Workstream leads ", "##  Workstream leads"):
        text = GOVERNANCE.replace("## Workstream leads", heading)
        assert len(parse_workstreams(text)) == 2


def test_parse_workstreams_stops_at_any_heading_level():
    text = GOVERNANCE.replace("## Origins", "### Emeritus\n\n| Old | Thing |\n| --- | --- |\n| A | B |\n\n## Origins")
    assert [name for name, _ in parse_workstreams(text)] == ["Identity", "Spec"]


def test_parse_workstreams_keeps_an_escaped_pipe():
    text = GOVERNANCE.replace("| Identity |", r"| Identity \| IAM |")
    assert [name for name, _ in parse_workstreams(text)] == ["Identity | IAM", "Spec"]


def test_parse_workstreams_raises_on_a_wrong_width_row():
    """A silently dropped workstream is worse than a loud failure."""
    text = GOVERNANCE.replace("| Spec |", "| Spec | extra |")
    with pytest.raises(RenderError, match="cells"):
        parse_workstreams(text)


def test_parse_workstreams_fails_without_the_section():
    with pytest.raises(RenderError, match="Workstream leads"):
        parse_workstreams("# Governance\n\nNothing here.\n")


def test_parse_workstreams_handles_the_real_file():
    assert len(parse_workstreams((REPO / "GOVERNANCE.md").read_text(encoding="utf-8"))) == 5


# --- escaping -------------------------------------------------------------

def test_render_workstreams_converts_markdown_links_to_html():
    html = render_workstreams([("Identity", "Eva Benn ([@evabenn](https://example.com))")])
    assert '<a href="https://example.com">@evabenn</a>' in html


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


def test_render_workstreams_blocks_attribute_breakout():
    html = render_workstreams([("X", '[@ok](https://x" autofocus onfocus="alert(1))')])
    attributes = [name for _, attrs in parse_attributes(html) for name, _ in attrs]
    assert not [name for name in attributes if name.startswith("on")]
    assert "autofocus" not in attributes
    # The quote survives as an entity inside the value rather than as a delimiter.
    assert "&quot;" in html


def test_render_workstreams_drops_a_javascript_scheme():
    html = render_workstreams([("X", "[@x](javascript:alert(1))")])
    assert "javascript:" not in html
    assert "@x" in html  # the label survives, the link does not


def test_render_workstreams_escapes_raw_html():
    html = render_workstreams([("<script>alert(1)</script>", "safe")])
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# --- placeholders ---------------------------------------------------------

def test_render_fills_every_placeholder(spec_tree):
    out = render(FULL_TEMPLATE, spec_tree, GOVERNANCE, "<svg id='sb'/>")
    assert "v0.1.0" in out and "Identity" in out and "<svg id='sb'/>" in out


def test_render_derives_the_schema_href_from_the_version(spec_tree):
    out = render(FULL_TEMPLATE, spec_tree, GOVERNANCE, "<svg/>")
    assert "schema/v0.1.0/acs_schema.json" in out


def test_render_fails_when_the_template_drops_a_placeholder(spec_tree):
    """A template missing the hero would otherwise ship a blank div with no error."""
    without = FULL_TEMPLATE.replace("<!--ACS:STARBURST-->", "")
    with pytest.raises(RenderError, match="STARBURST"):
        render(without, spec_tree, GOVERNANCE, "<svg/>")


def test_render_fails_when_an_unknown_placeholder_survives(spec_tree):
    with pytest.raises(RenderError, match="unfilled placeholder"):
        render(FULL_TEMPLATE + "<!--ACS:UNKNOWN-->", spec_tree, GOVERNANCE, "<svg/>")


def test_main_does_not_republish_the_inlined_diagram(tmp_path):
    """The diagram is inlined, so publishing it again ships a second copy that can drift."""
    import render_landing

    assert render_landing.main(["render_landing.py", str(REPO / "landing"), str(tmp_path)]) == 0
    assert not (tmp_path / "assets" / "starburst.svg").exists()
    assert (tmp_path / "assets" / "acs.css").is_file()
    assert (tmp_path / "assets" / "icon.svg").is_file()
