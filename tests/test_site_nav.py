"""Tests for the site navigation that mkdocs.yml defines for both surfaces.

mkdocs.yml is pull-request-writable and feeds HTML on the landing page and the docs
site, so these tests hold its shape, its values, and the keys that run code in the
build job.
"""
import difflib
import json
import re
import sys
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse, urlsplit

import pytest
import yaml
from mkdocs.utils.yaml import yaml_load

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import _docs_build  # noqa: E402
from _docs_build import DOCS_BASE  # noqa: E402
from conftest import _NOISE, _strip_css_comments  # noqa: E402
from site_nav import (  # noqa: E402
    ANCHOR, DOC_PATH, EXTERNAL, EXTERNAL_URL, REPO_URL, TITLE, ancestor_labels, aria_current_links,
    docs_expanded_mismatch, docs_open_labels, landing_open_labels, walk_docs, walk_landing,
)

REPO = Path(__file__).resolve().parents[1]
MKDOCS = REPO / "mkdocs.yml"
LANDING = REPO / "landing" / "index.html"

# Each failure message names the file to edit, so a red test is repairable by the author
# of the pull request that broke it.
REPAIR = {
    "ceiling": (
        "The landing pane shows {n} rows. Re-run the fold check at 1366x768 and raise the "
        "ceiling in `tests/test_site_nav.py` in the same pull request."
    ),
    "page_not_in_nav": (
        "`{page}` is built but not in the pane. Add a titled `nav` entry for it in `mkdocs.yml`, "
        "or, if it is reachable only from its parent, add its directory to "
        "`extra.acs_nav.out_of_nav_prefixes` in `mkdocs.yml` with a comment. A pull request that "
        "adds a page targets `integration`."
    ),
    "prefix_matches_nothing": (
        "`{prefix}` in `extra.acs_nav.out_of_nav_prefixes` matches no built page. Remove it from "
        "`mkdocs.yml`."
    ),
    "rows_differ": (
        "The landing pane and `{page}` show different rows. Both read `mkdocs.yml`. The diff below "
        "says where. If the docs side is wrong, the override is `overrides/partials/nav.html`."
    ),
    "faq_keyword": (
        "`docs/topics/faq.md` line {n} carries `{word}`. The FAQ is non-normative: lowercase the "
        "word, or move the requirement to a normative page (SPEC_REVIEW_PRINCIPLES.md principle 5)."
    ),
    "faq_banner": (
        "`docs/topics/faq.md` must keep its non-normative sentence, quoted in this test from "
        "today's line 5, in its first ten lines."
    ),
    "label_contract": (
        "`overrides/partials/nav.html`: label `{id}` needs an `input` with its `for`, an `id`, and "
        "a `nav[aria-labelledby]`, or Material's sidebar script throws."
    ),
    "sample_state": (
        "No usable pane row for the sample `{state}`. The samples need a docs front page, a "
        "top-level leaf, and leaves under a group and a nested group, all read from `mkdocs.yml`. "
        "Restore that shape in `nav` or change the sample rule in `tests/test_site_nav.py`."
    ),
    "url_not_built": (
        "`{url}` is in the pane but the build has no page there. Fix its path in `nav` in "
        "`mkdocs.yml`."
    ),
    "open_groups": (
        "`{page}` opens {got} but the current row's ancestors are {want}. The docs rows come "
        "from `mkdocs.yml` and the hand-emitted ones from `overrides/partials/nav.html`."
    ),
    "aria_current": (
        "`{page}` carries {n} `aria-current=\"page\"`. An in-nav page marks exactly its own link "
        "and a 404 or out-of-nav page marks none. The docs pane is `overrides/partials/nav.html` "
        "and the landing pane renders from `mkdocs.yml`."
    ),
    "home_children": (
        "The Home row's children differ from the landing page's `section[id]` list in document "
        "order. Edit `extra.acs_nav.landing_sections` in `mkdocs.yml` to match `landing/index.html`."
    ),
    "host": (
        "`{url}` is not a reviewed pane link. Every pane URL comes from `mkdocs.yml`, is `https`, "
        "carries no port, userinfo, or backslash, and leaves the site only for github.com or "
        "owasp.slack.com. The hero's links in `landing/index.html` go only where the pane goes."
    ),
    "section_rules": (
        "The theme stylesheet lost a rule the External resources section in "
        "`overrides/partials/nav.html` needs, so the section would collapse or turn into a link. "
        "Re-derive the override against the new theme as `overrides/README.md` describes, on a "
        "branch from `integration`. Inside its `min-width:76.25em` block it no longer:\n{problems}"
    ),
    "not_found_base": (
        "`404.html` resolves against {base!r}, not the pinned docs base. Build with "
        "`GITHUB_PAGES_URL` set, as the deploy workflow does, because the Home row in "
        "`overrides/partials/nav.html` derives the landing root from it. The build fix targets "
        "`integration`."
    ),
    "handler": (
        "`{page}` carries {found}. Remove the handler or the script URL from its source page, "
        "from `mkdocs.yml`, or from `overrides/partials/nav.html`."
    ),
    "not_found_href": (
        "`404.html` carries the pane href {href!r}, which is neither absolute nor path-absolute. "
        "The page is served at whatever address missed, so a relative href breaks below the docs "
        "root. Emit it from a rooted base in `overrides/partials/nav.html`. The build fix targets "
        "`integration`."
    ),
    "bookkeeping": (
        "`{path}` is override bookkeeping published into the site. Keep the recorded copies, "
        "diffs, and deltas for `overrides/partials/nav.html` under `overrides/.upstream/`, which "
        "the build skips. The fix targets `integration`."
    ),
}
# These repairs change how the site is built rather than what a page says, so they
# target `integration`.
BUILD_SIDE = frozenset({"page_not_in_nav", "section_rules", "not_found_base", "not_found_href", "bookkeeping"})

# Row ceilings for the landing pane, enforced in tests/test_landing_page.py. They live
# here because the repair message sends the author here to raise them.
CEILING_WITH_PAGE_OPEN_SET = 20
CEILING_WITH_EVERY_GROUP_CLOSED = 12


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


# Position never decides whether a tag is allowed, only which tags exist at all. A
# tagged key, a tag behind an alias, or a tag in a list all count the same way.
ALLOWED_TAGS = Counter({
    "!ENV": 1,
    "tag:yaml.org,2002:python/name:material.extensions.emoji.twemoji": 1,
    "tag:yaml.org,2002:python/name:material.extensions.emoji.to_svg": 1,
    "tag:yaml.org,2002:python/name:pymdownx.superfences.fence_code_format": 1,
})
TAGGED_EVENTS = (yaml.ScalarEvent, yaml.SequenceStartEvent, yaml.MappingStartEvent)


def explicit_tags(text: str) -> Counter:
    """Count every explicit tag in the YAML text, in keys and values alike.

    This reads parser events, not raw text, so it sees exactly the tags the loader would
    act on. Comments and prose never reach it, and a tag spelled any way (!!, !, or
    !<uri>) arrives as one resolved string.
    """
    return Counter(event.tag for event in yaml.parse(text, Loader=yaml.SafeLoader)
                   if isinstance(event, TAGGED_EVENTS) and event.tag is not None)


def site_url_tag(text: str) -> str | None:
    """Return the tag on the root mapping's site_url value node, or None."""
    root = yaml.compose(text, Loader=yaml.SafeLoader)
    for key, value in root.value:
        if key.value == "site_url":
            return value.tag
    return None


def test_yaml_tags_are_allowlisted():
    # tools/render_landing.py reads this file with a loader that cannot resolve
    # !relative, and the mkdocs version pinned in uv.lock decides which tags it
    # resolves at all. Every tag is code or environment access in the build job,
    # so only the four the file needs today are allowed.
    text = MKDOCS.read_text()
    assert explicit_tags(text) == ALLOWED_TAGS
    assert site_url_tag(text) == "!ENV"


@pytest.mark.parametrize("line, tag", [
    ("extra_x: !!python/object/apply:os.system [x]", "tag:yaml.org,2002:python/object/apply:os.system"),
    ("extra_x: !!map {a: b}", "tag:yaml.org,2002:map"),
    ("extra_x: !<tag:example.com,2000:x> y", "tag:example.com,2000:x"),
    ("extra_x: !ENV OTHER", "!ENV"),
    ("extra_x: !relative $docs_dir", "!relative"),
    ("extra_x: ! plain", "!"),
    ("a: &x 1\nb: *x\nc: !!python/name:os.system z", "tag:yaml.org,2002:python/name:os.system"),
    ("!!python/name:os.system x: y", "tag:yaml.org,2002:python/name:os.system"),
    ("extra_x: [!!python/name:os.system z]", "tag:yaml.org,2002:python/name:os.system"),
])
def test_yaml_tag_scan_rejects_unlisted_tags(line, tag):
    found = explicit_tags(MKDOCS.read_text() + "\n" + line + "\n")
    assert found[tag] > ALLOWED_TAGS[tag]
    assert found != ALLOWED_TAGS


def test_yaml_tag_scan_rejects_env_moved_off_site_url():
    text = MKDOCS.read_text().replace("site_url: !ENV GITHUB_PAGES_URL", "site_url: x\nother: !ENV GITHUB_PAGES_URL")
    assert explicit_tags(text) == ALLOWED_TAGS
    assert site_url_tag(text) != "!ENV"


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


# The pane comparison. Every sample below is chosen from the landing pane by its state,
# never by its path, so renaming or moving a page cannot break a fixture.

LANDING_ROOT = DOCS_BASE[: -len("docs/")]
FAQ = REPO / "docs" / "topics" / "faq.md"
FAQ_BANNER = "This section is non-normative."
RFC2119 = re.compile(r"\b(MUST|MUST NOT|REQUIRED|SHALL|SHALL NOT|SHOULD|SHOULD NOT|RECOMMENDED|MAY|OPTIONAL)\b")
FENCE = re.compile(r"^\s*(```|~~~)")
REVIEWED_HOSTS = frozenset({"github.com", "owasp.slack.com"})
WIDE = "@media screen and (min-width:76.25em)"
CANONICAL = re.compile(r'<link rel="canonical" href="([^"]+)"')
CONFIG = re.compile(r'<script id="__config" type="application/json">(.*?)</script>', re.S)
NOT_FOUND_URL = DOCS_BASE + "x/y/missing/"
SECTION_ID = re.compile(r'<section[^>]*\bid="([^"]+)"')
# These states have no current row, so the pane opens nothing and marks nothing.
UNPLACED = ("not_found", "out_of_nav_")


@pytest.fixture(scope="module")
def page():
    return _docs_build.render_landing_page()


@pytest.fixture(scope="module")
def landing_rows(page):
    return walk_landing(page, LANDING_ROOT)


def _built_path(built_docs: Path, url: str) -> Path:
    return built_docs / urldefrag(url).url[len(DOCS_BASE):] / "index.html"


@pytest.fixture(scope="module")
def samples(built_docs, landing_rows) -> dict[str, Path]:
    under_docs = [row for row in landing_rows if row[2] and row[2].startswith(DOCS_BASE)]
    rules = {
        "front": lambda row: row[2] == DOCS_BASE,
        "leaf_depth_1": lambda row: row[0] == 1 and not row[3] and row[2] != DOCS_BASE,
        "leaf_under_group": lambda row: row[0] == 2 and not row[3],
        "leaf_under_nested_group": lambda row: row[0] == 3 and not row[3],
    }
    chosen: dict[str, Path] = {}
    rows: dict[str, object] = {}
    for state, rule in rules.items():
        row = next((row for row in under_docs if rule(row)), None)
        assert row is not None, REPAIR["sample_state"].format(state=state)
        chosen[state], rows[state] = _built_path(built_docs, row[2]), row
    chosen["not_found"] = rows["not_found"] = built_docs / "404.html"
    for index, prefix in enumerate(acs_nav()["out_of_nav_prefixes"]):
        found = sorted((built_docs / prefix).rglob("index.html"))
        assert found, REPAIR["prefix_matches_nothing"].format(prefix=prefix)
        chosen[f"out_of_nav_{index}"] = rows[f"out_of_nav_{index}"] = found[0]
    for state, path in chosen.items():
        assert path.is_file(), REPAIR["sample_state"].format(state=f"{state} chose {rows[state]!r}, not built")
    duplicates = [state for state, path in chosen.items() if list(chosen.values()).count(path) > 1]
    assert not duplicates, REPAIR["sample_state"].format(
        state=", ".join(f"{state} chose {rows[state]!r}" for state in duplicates) + ", the same page")
    return chosen


def _base(path: Path, markup: str) -> str:
    # 404.html carries no canonical link. GitHub Pages serves it at whatever address
    # missed, so it resolves against a deep one, where a relative href would break. That
    # makes the fixture's GITHUB_PAGES_URL load-bearing for this page.
    if path.name == "404.html":
        return NOT_FOUND_URL
    match = CANONICAL.search(markup)
    assert match, REPAIR["rows_differ"].format(page=path) + "\nThe page has no canonical link."
    return match.group(1)


def _page(samples, state: str) -> str:
    """Name a sampled page by its path in the build, which is where its source publishes."""
    return samples[state].relative_to(samples["not_found"].parent).as_posix()


def _docs_pages(samples):
    """Yield (state, markup, base, rows) for every sampled docs page."""
    for state, path in samples.items():
        markup = path.read_text(encoding="utf-8")
        base = _base(path, markup)
        yield state, markup, base, walk_docs(markup, base)


def _current_index(rows, url: str) -> int | None:
    return next((index for index, row in enumerate(rows) if row[2] == url), None)


def _expected_open(rows, index: int) -> set[str]:
    # A section is always open and has no toggle, so it never joins the open set.
    sections = {row[1] for row in rows if row[4]}
    return set(ancestor_labels(rows, index)) - sections


def test_landing_and_every_sampled_docs_page_show_the_same_rows(samples, landing_rows):
    want = [repr(row) for row in landing_rows]
    for state, _markup, _base_, rows in _docs_pages(samples):
        got = [repr(row) for row in rows]
        diff = "\n".join(difflib.unified_diff(want, got, "landing", state, lineterm=""))
        assert got == want, REPAIR["rows_differ"].format(page=_page(samples, state)) + "\n" + diff


def test_open_groups_are_the_ancestors_of_the_current_row(samples, page, landing_rows):
    home = _current_index(landing_rows, LANDING_ROOT)
    want = _expected_open(landing_rows, home) | {"Home"}
    got = set(landing_open_labels(page))
    assert got == want, REPAIR["open_groups"].format(page="the landing page", got=sorted(got), want=sorted(want))
    for state, markup, base, rows in _docs_pages(samples):
        if state.startswith(UNPLACED):
            want = set()
        else:
            index = _current_index(rows, base)
            assert index is not None, REPAIR["aria_current"].format(page=_page(samples, state), n="no row for")
            want = _expected_open(rows, index)
        got = set(docs_open_labels(markup))
        assert got == want, REPAIR["open_groups"].format(page=_page(samples, state), got=sorted(got), want=sorted(want))
        mismatch = docs_expanded_mismatch(markup)
        assert not mismatch, REPAIR["open_groups"].format(page=_page(samples, state), got=mismatch, want=[])


def test_exactly_one_aria_current_on_the_picked_link(samples, page):
    assert page.count('aria-current="page"') == 1, REPAIR["aria_current"].format(
        page="the landing page", n=page.count('aria-current="page"'))
    ((tag, href),) = aria_current_links(page)
    assert tag == "a" and urljoin(LANDING_ROOT, href) == LANDING_ROOT, REPAIR["aria_current"].format(
        page="the landing page", n=f"<{tag} href={href!r}> as")
    for state, markup, base, rows in _docs_pages(samples):
        count = markup.count('aria-current="page"')
        links = aria_current_links(markup)
        if state.startswith(UNPLACED):
            assert count == 0 and not links, REPAIR["aria_current"].format(page=_page(samples, state), n=count)
            continue
        assert count == 1 and len(links) == 1, REPAIR["aria_current"].format(page=_page(samples, state), n=count)
        ((tag, href),) = links
        # The link must resolve to the page itself, which makes it the element the walk
        # picked for the current row.
        assert tag == "a" and urljoin(base, href) == base and _current_index(rows, base) is not None, (
            REPAIR["aria_current"].format(page=_page(samples, state), n=f"<{tag} href={href!r}> as"))


def test_every_pane_docs_url_is_built_and_every_built_page_is_in_the_pane_or_declared(built_docs, landing_rows):
    pane = {urldefrag(row[2]).url for row in landing_rows if row[2] and row[2].startswith(DOCS_BASE)}
    for url in sorted(pane):
        assert _built_path(built_docs, url).is_file(), REPAIR["url_not_built"].format(url=url)
    prefixes = acs_nav()["out_of_nav_prefixes"]
    matched = dict.fromkeys(prefixes, 0)
    # 404.html is not an index.html, so the glob already leaves it out.
    for built in sorted(built_docs.rglob("index.html")):
        rel = built.parent.relative_to(built_docs).as_posix()
        url = DOCS_BASE if rel == "." else f"{DOCS_BASE}{rel}/"
        declared = [prefix for prefix in prefixes if f"{rel}/".startswith(prefix)]
        for prefix in declared:
            matched[prefix] += 1
        assert url in pane or declared, REPAIR["page_not_in_nav"].format(page=built.relative_to(built_docs).as_posix())
    for prefix, count in matched.items():
        assert count, REPAIR["prefix_matches_nothing"].format(prefix=prefix)


def _home_children(rows) -> list[str | None]:
    home = next(index for index, row in enumerate(rows) if row[0] == 1 and row[1] == "Home")
    children = []
    for row in rows[home + 1:]:
        if row[0] <= rows[home][0]:
            break
        children.append(row[2])
    return children


def test_home_children_equal_the_landing_sections_in_order(samples, page, landing_rows):
    want = [f"{LANDING_ROOT}#{anchor}" for anchor in SECTION_ID.findall(page)]
    assert want, REPAIR["home_children"]
    assert _home_children(landing_rows) == want, REPAIR["home_children"]
    for _state, _markup, _base_, rows in _docs_pages(samples):
        assert _home_children(rows) == want, REPAIR["home_children"]


class _Tags(HTMLParser):
    """Every start tag on a page with its attributes, in document order."""

    def __init__(self, markup: str) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.feed(markup)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def test_every_pane_host_is_reviewed(samples, page, landing_rows):
    rows = list(landing_rows)
    for _state, _markup, _base_, docs_rows in _docs_pages(samples):
        rows.extend(docs_rows)
    pane_hosts = set()
    for row in rows:
        url = row[2]
        if not url or not urlsplit(url).netloc:
            continue
        parts = urlsplit(url)
        page_url = urldefrag(url).url
        assert parts.scheme == "https", REPAIR["host"].format(url=url)
        assert parts.netloc == parts.hostname and "\\" not in url, REPAIR["host"].format(url=url)
        if not (page_url.startswith(DOCS_BASE) or page_url == LANDING_ROOT):
            assert parts.hostname in REVIEWED_HOSTS, REPAIR["host"].format(url=url)
        pane_hosts.add(parts.hostname)
    cta = [attrs.get("href") or "" for tag, attrs in _Tags(page).tags
           if tag == "a" and "cta" in (attrs.get("class") or "").split()]
    assert cta, REPAIR["host"].format(url="the hero's call-to-action links (none found)")
    for href in cta:
        host = urlsplit(urljoin(LANDING_ROOT, href)).hostname
        assert host in pane_hosts, REPAIR["host"].format(url=href)


def test_every_section_label_has_its_input_and_nav(samples):
    for state, markup, _base_, _rows in _docs_pages(samples):
        tags = _Tags(markup).tags
        ids = [attrs.get("id") for _tag, attrs in tags]
        labelledby = {attrs.get("aria-labelledby") for _tag, attrs in tags}
        labels = [attrs for tag, attrs in tags
                  if tag == "label" and "md-nav__link" in (attrs.get("class") or "").split()
                  and attrs.get("for") not in (None, "__toc")]
        assert labels, REPAIR["label_contract"].format(id=f"(none on {_page(samples, state)})")
        for attrs in labels:
            name = attrs.get("id") or attrs["for"]
            inputs = [a for t, a in tags if t == "input" and a.get("id") == attrs["for"]]
            assert inputs and attrs.get("id") and attrs["id"] in labelledby, (
                REPAIR["label_contract"].format(id=name) + f" ({_page(samples, state)})")
        label_ids = [attrs.get("id") for tag, attrs in tags if tag == "label"]
        for own in ("__nav_home_label", "__nav_ext_label"):
            assert label_ids.count(own) == 1 and ids.count(own) == 1, (
                REPAIR["label_contract"].format(id=own) + f" ({_page(samples, state)})")


# The one `min-width:76.25em` block that holds the section rules, copied verbatim from
# the mkdocs-material 9.8.0 wheel, material/templates/assets/stylesheets/main.57a0d79d.min.css.
MATERIAL_980_WIDE_BLOCK = (
    '@media screen and (min-width:76.25em){.md-nav{margin-bottom:-.4rem;transition:max-he'
    'ight .25s cubic-bezier(.86,0,.07,1)}.md-nav--primary .md-nav__title{position:sticky;'
    'top:0;z-index:1;background:var(--md-default-bg-color);box-shadow:0 0 .4rem .4rem var'
    '(--md-default-bg-color)}.md-nav--primary .md-nav__title[for=__drawer]{scroll-snap-al'
    'ign:start}.md-nav--primary .md-nav__title .md-nav__icon{display:none}[dir=ltr] .md-n'
    'av--primary .md-nav__list{padding-left:.6rem}[dir=rtl] .md-nav--primary .md-nav__lis'
    't{padding-right:.6rem}.md-nav--primary .md-nav__list{padding-bottom:.4rem}[dir=ltr] '
    '.md-nav--primary .md-nav__item>.md-nav__link{margin-right:.4rem}[dir=rtl] .md-nav--p'
    'rimary .md-nav__item>.md-nav__link{margin-left:.4rem}.md-nav__toggle~.md-nav{display'
    ':grid;grid-template-rows:minmax(.4rem,0fr);visibility:collapse;opacity:0;transition:'
    'grid-template-rows .25s cubic-bezier(.86,0,.07,1),opacity .25s,visibility 0s .25s}.m'
    'd-nav__toggle~.md-nav>.md-nav__list{overflow:hidden}.md-nav__toggle.md-toggle--indet'
    'erminate~.md-nav,.md-nav__toggle:checked~.md-nav{grid-template-rows:minmax(.4rem,1fr'
    ');visibility:visible;opacity:1;transition:grid-template-rows .25s cubic-bezier(.86,0'
    ',.07,1),opacity .15s .1s,visibility}.md-nav__toggle.md-toggle--indeterminate~.md-nav'
    '{transition:none}.md-nav__item--nested>.md-nav>.md-nav__title{display:none}.md-nav__'
    'item--section{display:block;margin:1.25em 0}.md-nav__item--section:last-child{margin'
    '-bottom:0}.md-nav__item--section>.md-nav__link{font-weight:700}.md-nav--lifted>.md-n'
    'av__list>.md-nav__item>[for],.md-nav__item--section>.md-nav__link[for]{color:var(--m'
    'd-default-fg-color--light)}.md-nav--lifted>.md-nav__list>.md-nav__item--active>.md-n'
    'av__link:not(.md-nav__container),.md-nav__item--section>.md-nav__link:not(.md-nav__c'
    'ontainer){pointer-events:none}.md-nav__item--section>.md-nav__link .md-icon,.md-nav_'
    '_item--section>.md-nav__link>[for]{display:none}[dir=ltr] .md-nav__item--section>.md'
    '-nav{margin-left:-.6rem}[dir=rtl] .md-nav__item--section>.md-nav{margin-right:-.6rem'
    '}.md-nav__item--section>.md-nav{display:block;visibility:visible;opacity:1}.md-nav__'
    'item--section>.md-nav>.md-nav__list>.md-nav__item{padding:0}.md-nav__icon{width:.9re'
    'm;height:.9rem;border-radius:100%;transition:background-color .25s}.md-nav__icon:hov'
    'er{background-color:var(--md-accent-fg-color--transparent)}.md-nav__icon:after{displ'
    'ay:inline-block;width:100%;height:100%;vertical-align:-.1rem;content:"";background-c'
    'olor:currentcolor;border-radius:100%;-webkit-mask-image:var(--md-nav-icon--next);mas'
    'k-image:var(--md-nav-icon--next);-webkit-mask-repeat:no-repeat;mask-repeat:no-repeat'
    ';-webkit-mask-position:center;mask-position:center;-webkit-mask-size:contain;mask-si'
    'ze:contain;transition:transform .25s}[dir=rtl] .md-nav__icon:after{transform:rotate('
    '180deg)}.md-nav__item--nested .md-nav__toggle:checked~.md-nav__link .md-nav__icon:af'
    'ter,.md-nav__item--nested .md-toggle--indeterminate~.md-nav__link .md-nav__icon:afte'
    'r{transform:rotate(90deg)}.md-nav--lifted>.md-nav__list>.md-nav__item,.md-nav--lifte'
    'd>.md-nav__title{display:none}.md-nav--lifted>.md-nav__list>.md-nav__item--active{di'
    'splay:block}.md-nav--lifted>.md-nav__list>.md-nav__item--active>.md-nav__link{positi'
    'on:sticky;top:0;z-index:1;margin-top:0;background:var(--md-default-bg-color);box-sha'
    'dow:0 0 .4rem .4rem var(--md-default-bg-color)}.md-nav--lifted>.md-nav__list>.md-nav'
    '__item--active.md-nav__item--section{margin:0}[dir=ltr] .md-nav--lifted>.md-nav__lis'
    't>.md-nav__item>.md-nav:not(.md-nav--secondary){margin-left:-.6rem}[dir=rtl] .md-nav'
    '--lifted>.md-nav__list>.md-nav__item>.md-nav:not(.md-nav--secondary){margin-right:-.'
    '6rem}.md-nav--lifted .md-nav[data-md-level="1"]{grid-template-rows:minmax(.4rem,1fr)'
    ';visibility:visible;opacity:1}[dir=ltr] .md-nav--integrated>.md-nav__list>.md-nav__i'
    'tem--active .md-nav--secondary{border-left:.05rem solid var(--md-primary-fg-color)}['
    'dir=rtl] .md-nav--integrated>.md-nav__list>.md-nav__item--active .md-nav--secondary{'
    'border-right:.05rem solid var(--md-primary-fg-color)}.md-nav--integrated>.md-nav__li'
    'st>.md-nav__item--active .md-nav--secondary{display:block;margin-bottom:1.25em;visib'
    'ility:visible;opacity:1}.md-nav--integrated>.md-nav__list>.md-nav__item--active .md-'
    'nav--secondary>.md-nav__list{padding-bottom:0;overflow:visible}.md-nav--integrated>.'
    'md-nav__list>.md-nav__item--active .md-nav--secondary>.md-nav__title{display:none}}'
)


def _skip_string(css: str, index: int) -> int:
    """Return the offset past the string that opens at index."""
    quote = css[index]
    index += 1
    while index < len(css) and css[index] != quote:
        index += 2 if css[index] == "\\" else 1
    return index + 1


def _split_top(text: str, separator: str) -> list[str]:
    """Split on separator outside strings, parentheses, and brackets."""
    parts, depth, start, index = [], 0, 0, 0
    while index < len(text):
        char = text[index]
        if char in "\"'":
            index = _skip_string(text, index)
            continue
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == separator and depth == 0:
            parts.append(text[start:index])
            start = index + 1
        index += 1
    parts.append(text[start:])
    return [part.strip() for part in parts if part.strip()]


def _block_end(css: str, opening: int) -> int:
    """Return the offset of the brace that closes the one at opening."""
    depth, index = 0, opening
    while index < len(css):
        char = css[index]
        if char in "\"'":
            index = _skip_string(css, index)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise ValueError(f"unclosed block at offset {opening}")


def _walk_css(css: str, header: str, out: list) -> None:
    index = 0
    while True:
        # A prelude runs to the next brace or semicolon outside strings and parentheses.
        depth, cursor = 0, index
        while cursor < len(css):
            char = css[cursor]
            if char in "\"'":
                cursor = _skip_string(css, cursor)
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char in "{;" and depth == 0:
                break
            cursor += 1
        if cursor >= len(css):
            return
        prelude = css[index:cursor].strip()
        if css[cursor] == ";":
            # A statement at-rule such as @charset or @import carries no rules.
            index = cursor + 1
            continue
        end = _block_end(css, cursor)
        body = css[cursor + 1:end]
        if prelude.startswith("@") and "{" in body:
            # A conditional group rule nests rules. Its headers join outermost first.
            _walk_css(body, f"{header} {prelude}".strip(), out)
        elif not prelude.startswith("@"):
            declarations = frozenset(
                f"{name.strip().lower()}:{value.strip()}"
                for name, _colon, value in (part.partition(":") for part in _split_top(body, ";"))
            )
            out.extend((header, selector, declarations) for selector in _split_top(prelude, ","))
        index = end + 1


def _css_rules(css: str) -> list[tuple[str, str, frozenset[str]]]:
    """Return (media header or "", member selector, declarations) for every style rule.

    A selector list yields one tuple per member, because the 9.8.0 theme merged the
    pointer-events rule into a two-member list. Lookups match a member exactly.
    """
    out: list[tuple[str, str, frozenset[str]]] = []
    _walk_css(_strip_css_comments(css), "", out)
    return out


def _wide_rule_problems(rules) -> list[str]:
    """Name each rule the External resources section needs that the wide block lacks."""
    wide = [(index, selector, declarations)
            for index, (header, selector, declarations) in enumerate(rules) if header == WIDE]

    def last(selector: str, needed: set[str]) -> int | None:
        found = [index for index, member, declarations in wide
                 if member == selector and needed <= declarations]
        return found[-1] if found else None

    problems = []
    section = last(".md-nav__item--section>.md-nav", {"display:block", "visibility:visible"})
    collapse = last(".md-nav__toggle~.md-nav", {"visibility:collapse"})
    if section is None:
        problems.append("shows .md-nav__item--section>.md-nav with display:block and visibility:visible")
    if collapse is None:
        problems.append("collapses .md-nav__toggle~.md-nav with visibility:collapse")
    if section is not None and collapse is not None and section < collapse:
        # Equal specificity, so source order decides which rule a section obeys.
        problems.append("places the section display rule after the collapse rule")
    if last(".md-nav__item--section>.md-nav__link:not(.md-nav__container)", {"pointer-events:none"}) is None:
        problems.append("makes the section label inert with pointer-events:none")
    if last(".md-nav__item--nested>.md-nav>.md-nav__title", {"display:none"}) is None:
        problems.append("hides the nested nav title with display:none")
    return problems


def test_css_walker_splits_lists_and_nests_media():
    rules = _css_rules('/* a{b:c} */@charset "x";@media a{@media b{.x,.y:not(.p,.q){c:d;e:url("a;b")}}}'
                       '.z[t=","]{f:g}@font-face{font-family:x}')
    assert rules == [
        ("@media a @media b", ".x", frozenset({"c:d", 'e:url("a;b")'})),
        ("@media a @media b", ".y:not(.p,.q)", frozenset({"c:d", 'e:url("a;b")'})),
        ("", '.z[t=","]', frozenset({"f:g"})),
    ]


def test_section_rules_hold_inside_the_wide_media_block(built_docs):
    sheets = sorted((built_docs / "assets" / "stylesheets").glob("main.*.min.css"))
    assert len(sheets) == 1, REPAIR["section_rules"].format(problems=f"ships one main stylesheet, found {sheets}")
    rules = _css_rules(sheets[0].read_text(encoding="utf-8"))
    problems = _wide_rule_problems(rules)
    top = {selector for header, selector, _declarations in rules if header == ""}
    for container in (".md-nav__container>.md-nav__link", ".md-nav__container>.md-nav__link:first-child"):
        if container not in top:
            problems.append(f"styles {container} at the top level")
    assert not problems, REPAIR["section_rules"].format(problems="\n".join(problems))
    # The same assertions hold on the next theme release, which reorders declarations
    # and merges the pointer-events rule into a selector list.
    problems = _wide_rule_problems(_css_rules(MATERIAL_980_WIDE_BLOCK))
    assert not problems, REPAIR["section_rules"].format(problems="\n".join(problems))


def test_404_sample_resolves_against_the_pinned_base(samples):
    markup = samples["not_found"].read_text(encoding="utf-8")
    config = CONFIG.search(markup)
    assert config, REPAIR["not_found_base"].format(base="no #__config script")
    base = json.loads(config.group(1)).get("base")
    assert base == urlparse(DOCS_BASE).path, REPAIR["not_found_base"].format(base=base)
    rows = walk_docs(markup, NOT_FOUND_URL)
    home = [row for row in rows if row[0] == 1 and row[1] == "Home"]
    assert [row[2] for row in home] == [LANDING_ROOT], REPAIR["not_found_base"].format(base=home)
    # An empty base leaves each href as written, so this reads the raw pane hrefs.
    for _depth, _label, href, _group, _section in walk_docs(markup, ""):
        rooted = href is None or href.startswith("https://") or (href.startswith("/") and not href.startswith("//"))
        assert rooted, REPAIR["not_found_href"].format(href=href)


def _handlers_and_schemes(markup: str) -> list[str]:
    found = []
    for tag, attrs in _Tags(markup).tags:
        for name, value in attrs.items():
            if name.startswith("on"):
                found.append(f"<{tag} {name}>")
            # A browser drops tabs and newlines inside a URL before reading its scheme.
            if name in ("href", "src") and value and \
                    _NOISE.sub("", value).strip().lower().startswith(("javascript:", "data:", "vbscript:")):
                found.append(f"<{tag} {name}={value[:40]}>")
    return found


def test_built_pages_carry_no_handler_or_script_scheme(built_docs, page):
    found = _handlers_and_schemes(page)
    assert not found, REPAIR["handler"].format(page="the landing page", found=found)
    for built in sorted(built_docs.rglob("*.html")):
        found = _handlers_and_schemes(built.read_text(encoding="utf-8"))
        assert not found, REPAIR["handler"].format(page=built.relative_to(built_docs).as_posix(), found=found)


def test_built_site_carries_no_override_bookkeeping(built_docs):
    for built in sorted(built_docs.rglob("*")):
        rel = built.relative_to(built_docs).as_posix()
        assert "partials" not in rel.split("/"), REPAIR["bookkeeping"].format(path=rel)
        assert not rel.endswith((".upstream", ".diff", ".delta")), REPAIR["bookkeeping"].format(path=rel)


def test_faq_is_non_normative_by_banner_and_vocabulary():
    lines = FAQ.read_text(encoding="utf-8").splitlines()
    assert any(FAQ_BANNER in line.replace("**", "") for line in lines[:10]), REPAIR["faq_banner"]
    fenced = False
    for number, line in enumerate(lines, start=1):
        if FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue
        match = RFC2119.search(line)
        assert not match, REPAIR["faq_keyword"].format(n=number, word=match.group(0) if match else "")


def test_every_repair_message_names_its_file():
    files = ("mkdocs.yml", "docs/topics/faq.md", "overrides/partials/nav.html")
    for key, message in REPAIR.items():
        # The ceiling's repair edits this module, so only it may name this file instead.
        allowed = files + (("tests/test_site_nav.py",) if key == "ceiling" else ())
        assert any(name in message for name in allowed), key
    assert BUILD_SIDE <= REPAIR.keys()
    for key in BUILD_SIDE:
        assert "integration" in REPAIR[key], key
