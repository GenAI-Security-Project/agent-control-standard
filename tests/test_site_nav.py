"""Tests for the site navigation that mkdocs.yml defines for both surfaces.

mkdocs.yml is pull-request-writable and feeds HTML on the landing page and the docs
site, so these tests hold its shape, its values, and the keys that run code in the
build job.
"""
import re
import sys
from pathlib import Path

import pytest
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


def test_yaml_tags_are_allowlisted():
    text = MKDOCS.read_text()
    # tools/render_landing.py reads this file with a loader that cannot resolve
    # !relative, and the mkdocs version pinned in uv.lock decides which tags it
    # resolves at all. Every tag is code or environment access in the build job,
    # so only the ones the file needs today are allowed.
    for line in text.splitlines():
        if "!ENV" in line:
            assert line.startswith("site_url:"), line
    python_tags = [line.split("!!python/name:")[1].strip() for line in text.splitlines() if "!!python/name:" in line]
    assert sorted(python_tags) == [
        "material.extensions.emoji.to_svg",
        "material.extensions.emoji.twemoji",
        "pymdownx.superfences.fence_code_format",
    ]
    remaining = text.replace("!!python/name:", "").replace("!ENV", "")
    assert not re.search(r"(?<![\w!])!\w", remaining), "an unlisted YAML tag appears"
    assert "!relative" not in text


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
