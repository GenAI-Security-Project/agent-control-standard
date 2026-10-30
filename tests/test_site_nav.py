"""Tests for the site navigation that mkdocs.yml defines for both surfaces.

mkdocs.yml is pull-request-writable and feeds HTML on the landing page and the docs
site, so these tests hold its shape, its values, and the keys that run code in the
build job.
"""
import re
import sys
from pathlib import Path

import pytest
import yaml
from mkdocs.utils.yaml import yaml_load

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from site_nav import ANCHOR, DOC_PATH, EXTERNAL, EXTERNAL_URL, REPO_URL, TITLE

REPO = Path(__file__).resolve().parents[1]
MKDOCS = REPO / "mkdocs.yml"
LANDING = REPO / "landing" / "index.html"


def load_mkdocs() -> dict:
    with MKDOCS.open() as handle:
        return yaml_load(handle)


def nav_entries(nav):
    """Yield (title, value) for every entry, recursing into groups."""
    if not isinstance(nav, list):
        raise AssertionError(f"nav list expected, got {type(nav).__name__}")
    for entry in nav:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise AssertionError(f"nav entry must be a one-key mapping: {entry!r}")
        ((title, value),) = entry.items()
        yield title, value
        if isinstance(value, list):
            yield from nav_entries(value)


def acs_nav() -> dict:
    return load_mkdocs()["extra"]["acs_nav"]


def test_every_nav_entry_is_a_titled_mapping():
    entries = list(nav_entries(load_mkdocs()["nav"]))
    assert entries
    for title, value in entries:
        assert isinstance(title, str)
        assert isinstance(value, (str, list)), f"{title!r} has a {type(value).__name__} value"


def test_titles_anchors_paths_and_urls_match_their_patterns():
    cfg = load_mkdocs()
    for title, value in nav_entries(cfg["nav"]):
        assert TITLE.match(title), title
        if isinstance(value, list):
            continue
        if EXTERNAL.match(value):
            assert EXTERNAL_URL.match(value), value
        else:
            assert DOC_PATH.match(value), value
    nav = cfg["extra"]["acs_nav"]
    for section in nav["landing_sections"]:
        assert TITLE.match(section["title"]), section["title"]
        assert ANCHOR.match(section["anchor"]), section["anchor"]
    for resource in nav["external_resources"]:
        assert TITLE.match(resource["title"]), resource["title"]
        assert EXTERNAL_URL.match(resource["url"]), resource["url"]


def test_repo_url_and_the_three_resources_are_the_literals():
    cfg = load_mkdocs()
    assert cfg["repo_url"] == REPO_URL
    urls = {item["title"]: item["url"] for item in cfg["extra"]["acs_nav"]["external_resources"]}
    assert urls == {
        "GitHub": REPO_URL,
        "Roadmap": REPO_URL + "/milestones",
        "Slack": "https://owasp.slack.com",
    }


PYTHON_NAME = "tag:yaml.org,2002:python/name:"
# (tag, depth, key the tagged value sits under). Depth 1 is a top-level key.
ALLOWED_TAGS = {
    ("!ENV", 1, "site_url"),
    (PYTHON_NAME + "material.extensions.emoji.twemoji", 4, "emoji_index"),
    (PYTHON_NAME + "material.extensions.emoji.to_svg", 4, "emoji_generator"),
    (PYTHON_NAME + "pymdownx.superfences.fence_code_format", 6, "format"),
}


def explicit_tags(text: str) -> set[tuple[str, int, str | None]]:
    """Return every explicit tag in the YAML text as (tag, depth, owning key).

    This reads parser events, not raw text, so it sees exactly the tags the loader would
    act on. Comments and prose never reach it, and a tag spelled any way (!!, !, or
    !<uri>) arrives as one resolved string.
    """
    found = set()
    stack: list[list] = []  # per open container: [is_mapping, next_is_key, last_key]

    def settle() -> str | None:
        # A finished node is a key or a value of the container that holds it.
        if not stack:
            return None
        top = stack[-1]
        key = top[2]
        if top[0]:
            top[1] = not top[1]
        return key

    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            key = stack[-1][2] if stack else None
            if event.tag is not None:
                found.add((event.tag, len(stack), key))
            settle()
            stack.append([isinstance(event, yaml.MappingStartEvent), True, key])
        elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
            stack.pop()
        elif isinstance(event, yaml.ScalarEvent):
            top = stack[-1] if stack else None
            if top is not None and top[0] and top[1]:
                top[2] = event.value
                settle()
                continue
            if event.tag is not None:
                found.add((event.tag, len(stack), top[2] if top else None))
            settle()
    return found


def test_yaml_tags_are_allowlisted():
    # tools/render_landing.py reads this file with a loader that cannot resolve
    # !relative, and the mkdocs version pinned in uv.lock decides which tags it
    # resolves at all. Every tag is code or environment access in the build job,
    # so only the four the file needs today are allowed.
    assert explicit_tags(MKDOCS.read_text()) == ALLOWED_TAGS


@pytest.mark.parametrize("line", [
    "extra_x: !!python/object/apply:os.system [x]",
    "extra_x: !!map {a: b}",
    "extra_x: !<tag:example.com,2000:x> y",
    "extra_x: !ENV OTHER",
    "extra_x: !relative $docs_dir",
    "extra_x: ! plain",
])
def test_yaml_tag_scan_rejects_unlisted_tags(line):
    assert explicit_tags(MKDOCS.read_text() + "\n" + line + "\n") != ALLOWED_TAGS


def test_yaml_tag_scan_ignores_comments():
    text = "# !ENV reads the environment, !!python/name:x too\n" + MKDOCS.read_text()
    assert explicit_tags(text) == ALLOWED_TAGS


def test_landing_sections_anchors_match_the_landing_sections_in_order():
    sections = acs_nav()["landing_sections"]
    assert [s["anchor"] for s in sections] == [
        "problem", "solution", "architecture", "why-now",
        "built-with", "status", "workstreams", "contribute",
    ]
    assert [s["title"] for s in sections] == [
        "The problem", "The solution", "How it works", "Why now",
        "Built with the community", "Spec status", "Workstreams", "Contribute",
    ]
    ids = re.findall(r'<section[^>]*\bid="([^"]+)"', LANDING.read_text())
    assert [a for a in ids if a in {s["anchor"] for s in sections}] == [s["anchor"] for s in sections]


def test_out_of_nav_prefixes_are_declared_and_end_with_a_slash():
    prefixes = acs_nav()["out_of_nav_prefixes"]
    assert prefixes == ["spec/instrument/a2a/hooks/"]
    assert all(p.endswith("/") for p in prefixes)


def test_nav_order_puts_faq_at_the_top_level_and_drops_acs_home():
    titles = [next(iter(entry)) for entry in load_mkdocs()["nav"]]
    assert titles == ["Trustworthy Agents", "ACS", "FAQ", "Topics", "Concepts", "Specification", "About"]


def test_mkdocs_build_surface_is_pinned():
    cfg = load_mkdocs()
    message = (
        "mkdocs.yml runs code in the build job through these keys. Change them in a pull "
        "request a project lead approves and update this test in the same commit."
    )
    assert "hooks" not in cfg, message
    assert cfg["plugins"] == ["search"], message
    assert cfg["extra_javascript"] == [
        "assets/javascripts/mermaid.min.js", "assets/javascripts/mermaid-init.js",
    ], message
    assert cfg["extra_css"] == ["stylesheets/extra.css"], message
    assert cfg["theme"]["name"] == "material", message
    assert cfg["theme"]["custom_dir"] == "overrides", message
