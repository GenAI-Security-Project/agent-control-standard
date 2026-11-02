"""Tests for the pane walkers that turn either surface's left navigation into rows.

The landing pane and the docs pane must show the same rows, and the only way to hold
them equal is to read both into one shape. These tests pin that shape on markup copied
from a Material 9.7.7 build and on the two rows the docs override emits by hand.

The two hand-emitted blocks below are a byte contract. The docs override reproduces
them, so edit them only together with the override.
"""
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from site_nav import (  # noqa: E402
    ANCHOR, DOC_PATH, EXTERNAL, EXTERNAL_URL, REPO_URL, TITLE, WalkError, ancestor_labels,
    aria_current_links, docs_expanded_mismatch, docs_open_labels, landing_open_labels,
    walk_docs, walk_landing,
)

TOOLS = Path(__file__).resolve().parents[1] / "tools"
DOCS_BASE = "https://example.org/agent-control-standard/docs/"
LANDING_ROOT = "https://example.org/agent-control-standard/"
IDENTITY_BASE = DOCS_BASE + "concepts/identity/"

PANE_OPEN = '<nav class="md-nav md-nav--primary" aria-label="Navigation" data-md-level="0">'
PANE_TITLE = """  <label class="md-nav__title" for="__drawer">
    <a href="../.." title="Agent Control Standard" class="md-nav__button md-logo" aria-label="Agent Control Standard" data-md-component="logo">
  <img src="../../assets/icon.svg" alt="logo">
    </a>
    Agent Control Standard
  </label>
"""
LIST_OPEN = '  <ul class="md-nav__list" data-md-scrollfix>\n'
PANE_CLOSE = "  </ul>\n</nav>\n"


def pane(rows: str) -> str:
    return PANE_OPEN + "\n" + PANE_TITLE + LIST_OPEN + rows + PANE_CLOSE


# Copied from the built front page: the active leaf with its table of contents.
FRONT_ACTIVE_LEAF = """    <li class="md-nav__item md-nav__item--active">
      <input class="md-nav__toggle md-toggle" type="checkbox" id="__toc">
        <label class="md-nav__link md-nav__link--active" for="__toc">
  <span class="md-ellipsis">
    Trustworthy Agents
  </span>
          <span class="md-nav__icon md-icon"></span>
        </label>
      <a href="." class="md-nav__link md-nav__link--active">
  <span class="md-ellipsis">
    Trustworthy Agents
  </span>
      </a>
<nav class="md-nav md-nav--secondary" aria-label="Table of contents">
    <label class="md-nav__title" for="__toc">
      <span class="md-nav__icon md-icon"></span>
      Table of contents
    </label>
    <ul class="md-nav__list" data-md-component="toc" data-md-scrollfix>
        <li class="md-nav__item">
  <a href="#read-next" class="md-nav__link">
    <span class="md-ellipsis">
        Read Next
    </span>
  </a>
</li>
    </ul>
</nav>
    </li>
"""

# Copied from the built concepts/identity/index.html, trimmed to one closed sibling
# group and the open path down to the active page.
IDENTITY_ROWS = """    <li class="md-nav__item">
      <a href="https://genai-security-project.github.io/agent-control-standard/" class="md-nav__link">
  <span class="md-ellipsis">
    ACS home
  </span>
      </a>
    </li>
    <li class="md-nav__item md-nav__item--nested">
        <input class="md-nav__toggle md-toggle " type="checkbox" id="__nav_4" >
          <label class="md-nav__link" for="__nav_4" id="__nav_4_label" tabindex="0">
  <span class="md-ellipsis">
    Topics
  </span>
            <span class="md-nav__icon md-icon"></span>
          </label>
        <nav class="md-nav" data-md-level="1" aria-labelledby="__nav_4_label" aria-expanded="false">
          <label class="md-nav__title" for="__nav_4">
            <span class="md-nav__icon md-icon"></span>
    Topics
          </label>
          <ul class="md-nav__list" data-md-scrollfix>
    <li class="md-nav__item">
      <a href="../../topics/core_concepts/" class="md-nav__link">
  <span class="md-ellipsis">
    Core concepts
  </span>
      </a>
    </li>
          </ul>
        </nav>
    </li>
    <li class="md-nav__item md-nav__item--active md-nav__item--nested">
        <input class="md-nav__toggle md-toggle " type="checkbox" id="__nav_5" checked>
          <label class="md-nav__link" for="__nav_5" id="__nav_5_label" tabindex="0">
  <span class="md-ellipsis">
    Concepts
  </span>
            <span class="md-nav__icon md-icon"></span>
          </label>
        <nav class="md-nav" data-md-level="1" aria-labelledby="__nav_5_label" aria-expanded="true">
          <label class="md-nav__title" for="__nav_5">
            <span class="md-nav__icon md-icon"></span>
    Concepts
          </label>
          <ul class="md-nav__list" data-md-scrollfix>
    <li class="md-nav__item">
      <a href="../" class="md-nav__link">
  <span class="md-ellipsis">
    Overview
  </span>
      </a>
    </li>
    <li class="md-nav__item md-nav__item--active md-nav__item--nested">
        <input class="md-nav__toggle md-toggle " type="checkbox" id="__nav_5_3" checked>
          <label class="md-nav__link" for="__nav_5_3" id="__nav_5_3_label" tabindex="0">
  <span class="md-ellipsis">
    Identity
  </span>
            <span class="md-nav__icon md-icon"></span>
          </label>
        <nav class="md-nav" data-md-level="2" aria-labelledby="__nav_5_3_label" aria-expanded="true">
          <label class="md-nav__title" for="__nav_5_3">
            <span class="md-nav__icon md-icon"></span>
    Identity
          </label>
          <ul class="md-nav__list" data-md-scrollfix>
    <li class="md-nav__item md-nav__item--active">
      <input class="md-nav__toggle md-toggle" type="checkbox" id="__toc">
        <label class="md-nav__link md-nav__link--active" for="__toc">
  <span class="md-ellipsis">
    Overview
  </span>
          <span class="md-nav__icon md-icon"></span>
        </label>
      <a href="./" class="md-nav__link md-nav__link--active">
  <span class="md-ellipsis">
    Overview
  </span>
      </a>
<nav class="md-nav md-nav--secondary" aria-label="Table of contents">
    <label class="md-nav__title" for="__toc">
      <span class="md-nav__icon md-icon"></span>
      Table of contents
    </label>
    <ul class="md-nav__list" data-md-component="toc" data-md-scrollfix>
        <li class="md-nav__item">
  <a href="#principals-and-descriptors" class="md-nav__link">
    <span class="md-ellipsis">
        Principals and descriptors
    </span>
  </a>
</li>
    </ul>
</nav>
    </li>
    <li class="md-nav__item">
      <a href="../../identity/overview/" class="md-nav__link">
  <span class="md-ellipsis">
    Identity for Agents
  </span>
      </a>
    </li>
          </ul>
        </nav>
    </li>
    <li class="md-nav__item">
      <a href="../session-lifecycle/" class="md-nav__link">
  <span class="md-ellipsis">
    Session Lifecycle
  </span>
      </a>
    </li>
          </ul>
        </nav>
    </li>
"""

# The byte contract for the container row the override emits, with PATH and the Home
# href filled in.
HOME_CONTAINER_ROW = """<li class="md-nav__item md-nav__item--nested">
  <input class="md-nav__toggle md-toggle" type="checkbox" id="__nav_home">
  <div class="md-nav__link md-nav__container">
    <a href="https://example.org/agent-control-standard/" class="md-nav__link">
      <span class="md-ellipsis">Home</span>
    </a>
    <label class="md-nav__link" for="__nav_home" id="__nav_home_label" tabindex="0">
      <span class="md-nav__icon md-icon"></span>
    </label>
  </div>
  <nav class="md-nav" data-md-level="1" aria-labelledby="__nav_home_label" aria-expanded="false">
    <label class="md-nav__title" for="__nav_home">
      <span class="md-nav__icon md-icon"></span>
      Home
    </label>
    <ul class="md-nav__list" data-md-scrollfix>
      <li class="md-nav__item"><a href="https://example.org/agent-control-standard/#problem" class="md-nav__link"><span class="md-ellipsis">The problem</span></a></li>
    </ul>
  </nav>
</li>
"""

# The byte contract for the section row the override emits.
EXTERNAL_SECTION_ROW = """<li class="md-nav__item md-nav__item--section md-nav__item--nested">
  <input class="md-nav__toggle md-toggle" type="checkbox" id="__nav_ext">
  <label class="md-nav__link" for="__nav_ext" id="__nav_ext_label" tabindex="">
    <span class="md-ellipsis">External resources</span>
    <span class="md-nav__icon md-icon"></span>
  </label>
  <nav class="md-nav" data-md-level="1" aria-labelledby="__nav_ext_label" aria-expanded="false">
    <label class="md-nav__title" for="__nav_ext">
      <span class="md-nav__icon md-icon"></span>
      External resources
    </label>
    <ul class="md-nav__list" data-md-scrollfix>
      <li class="md-nav__item"><a href="https://github.com/GenAI-Security-Project/agent-control-standard" class="md-nav__link"><span class="md-ellipsis">GitHub</span></a></li>
    </ul>
  </nav>
</li>
"""

# The landing pane in the shape the renderer emits.
LANDING_PANE = """<nav id="site-nav" aria-label="Navigation"><ul>
<li><details open><summary><a href="./" aria-current="page">Home</a></summary><ul>
<li><a href="#problem">The problem</a></li>
<li><a href="#roadmap">Roadmap</a></li>
</ul></details></li>
<li><a href="docs/">Trustworthy Agents</a></li>
<li><details><summary>Concepts</summary><ul>
<li><a href="docs/concepts/">Overview</a></li>
<li><details><summary>Identity</summary><ul>
<li><a href="docs/concepts/identity/">Overview</a></li>
</ul></details></li>
</ul></details></li>
<li class="nav-section"><h2>External resources</h2><ul>
<li><a href="https://github.com/GenAI-Security-Project/agent-control-standard">GitHub</a></li>
<li><a href="https://owasp.slack.com">Slack</a></li>
</ul></li>
</ul></nav>
"""


def test_docs_walk_skips_the_toc_label_and_picks_the_link():
    rows = walk_docs(pane(FRONT_ACTIVE_LEAF), DOCS_BASE)
    assert rows == [(1, "Trustworthy Agents", DOCS_BASE, False, False)]


def test_docs_walk_container_row_picks_the_link_not_the_toggle_label():
    rows = walk_docs(pane(HOME_CONTAINER_ROW), DOCS_BASE)
    assert rows == [
        (1, "Home", LANDING_ROOT, True, False),
        (2, "The problem", LANDING_ROOT + "#problem", False, False),
    ]


def test_docs_walk_keeps_group_labels_not_first_children():
    rows = walk_docs(pane(IDENTITY_ROWS), IDENTITY_BASE)
    assert rows == [
        (1, "ACS home", "https://genai-security-project.github.io/agent-control-standard/", False, False),
        (1, "Topics", None, True, False),
        (2, "Core concepts", DOCS_BASE + "topics/core_concepts/", False, False),
        (1, "Concepts", None, True, False),
        (2, "Overview", DOCS_BASE + "concepts/", False, False),
        (2, "Identity", None, True, False),
        (3, "Overview", IDENTITY_BASE, False, False),
        (3, "Identity for Agents", DOCS_BASE + "identity/overview/", False, False),
        (2, "Session Lifecycle", DOCS_BASE + "concepts/session-lifecycle/", False, False),
    ]


def test_docs_walk_section_row_is_section_not_group():
    rows = walk_docs(pane(EXTERNAL_SECTION_ROW), DOCS_BASE)
    assert rows == [
        (1, "External resources", None, False, True),
        (2, "GitHub", REPO_URL, False, False),
    ]


def test_docs_walk_raises_on_a_row_with_no_pick_and_on_two_links():
    empty = '<li class="md-nav__item"><span>Orphan row</span></li>\n'
    with pytest.raises(WalkError, match=r"depth 1.*Orphan row"):
        walk_docs(pane(empty), DOCS_BASE)
    two = ('<li class="md-nav__item"><a href="a/" class="md-nav__link">First</a>'
           '<a href="b/" class="md-nav__link">Second</a></li>\n')
    with pytest.raises(WalkError, match=r"depth 1.*FirstSecond"):
        walk_docs(pane(two), DOCS_BASE)
    two_labels = ('<li class="md-nav__item"><label class="md-nav__link" for="x">One</label>'
                  '<label class="md-nav__link" for="y">Two</label></li>\n')
    with pytest.raises(WalkError, match=r"depth 1.*OneTwo"):
        walk_docs(pane(two_labels), DOCS_BASE)
    with pytest.raises(WalkError, match="Navigation"):
        walk_docs("<nav><ul><li><a href='x'>x</a></li></ul></nav>", DOCS_BASE)


def test_landing_walk_home_summary_link_is_one_group_row():
    rows = walk_landing(LANDING_PANE, LANDING_ROOT)
    assert rows[:3] == [
        (1, "Home", LANDING_ROOT, True, False),
        (2, "The problem", LANDING_ROOT + "#problem", False, False),
        (2, "Roadmap", LANDING_ROOT + "#roadmap", False, False),
    ]
    assert [row for row in rows if row[1] == "Home"] == [rows[0]]


def test_landing_walk_section_row_from_heading():
    rows = walk_landing(LANDING_PANE, LANDING_ROOT)
    assert rows[-3:] == [
        (1, "External resources", None, False, True),
        (2, "GitHub", REPO_URL, False, False),
        (2, "Slack", "https://owasp.slack.com", False, False),
    ]


def test_depth_counts_enclosing_lists_on_both_surfaces():
    landing = walk_landing(LANDING_PANE, LANDING_ROOT)
    docs = walk_docs(pane(IDENTITY_ROWS), IDENTITY_BASE)
    assert [(row[0], row[1]) for row in landing[3:8]] == [
        (1, "Trustworthy Agents"), (1, "Concepts"), (2, "Overview"), (2, "Identity"), (3, "Overview"),
    ]
    assert [row[0] for row in docs] == [1, 1, 2, 1, 2, 2, 3, 3, 2]


def test_label_collapses_whitespace_and_ellipsis_span():
    rows = walk_docs(pane(FRONT_ACTIVE_LEAF + EXTERNAL_SECTION_ROW), DOCS_BASE)
    assert [row[1] for row in rows] == ["Trustworthy Agents", "External resources", "GitHub"]
    spaced = '<nav aria-label="Navigation"><ul><li><a href="x/">\n  Agent\n\t<b>Control</b>  Standard </a></li></ul></nav>'
    assert walk_landing(spaced, LANDING_ROOT) == [(1, "Agent Control Standard", LANDING_ROOT + "x/", False, False)]


def test_ancestors_skip_earlier_sibling_groups():
    rows = walk_docs(pane(IDENTITY_ROWS), IDENTITY_BASE)
    active = rows.index((3, "Overview", IDENTITY_BASE, False, False))
    assert ancestor_labels(rows, active) == ["Identity", "Concepts"]
    assert ancestor_labels(rows, rows.index((2, "Core concepts", DOCS_BASE + "topics/core_concepts/", False, False))) == ["Topics"]
    assert ancestor_labels(rows, 0) == []


def test_ancestors_of_a_section_child_are_the_section_not_an_earlier_group():
    rows = walk_landing(LANDING_PANE, LANDING_ROOT)
    assert ancestor_labels(rows, len(rows) - 1) == ["External resources"]


def test_open_labels_and_ancestors_agree_on_a_nested_page():
    markup = pane(IDENTITY_ROWS)
    rows = walk_docs(markup, IDENTITY_BASE)
    active = rows.index((3, "Overview", IDENTITY_BASE, False, False))
    assert docs_open_labels(markup) == frozenset(ancestor_labels(rows, active))
    assert landing_open_labels(LANDING_PANE) == frozenset({"Home"})
    assert aria_current_links(LANDING_PANE) == [("a", "./")]
    assert aria_current_links(markup) == []


def test_expanded_mismatch_reports_indeterminate_and_a_missing_attribute():
    assert docs_expanded_mismatch(pane(IDENTITY_ROWS)) == []
    assert docs_expanded_mismatch(pane(HOME_CONTAINER_ROW + EXTERNAL_SECTION_ROW)) == []
    missing = IDENTITY_ROWS.replace(' aria-expanded="false"', "", 1)
    assert docs_expanded_mismatch(pane(missing)) == ["Topics: nested nav has no aria-expanded"]
    odd = IDENTITY_ROWS.replace('aria-expanded="true"', 'aria-expanded="yes"', 1)
    assert docs_expanded_mismatch(pane(odd)) == ["Concepts: aria-expanded is 'yes'"]
    disagree = IDENTITY_ROWS.replace('id="__nav_5_3" checked', 'id="__nav_5_3"', 1)
    assert docs_expanded_mismatch(pane(disagree)) == [
        "Identity: aria-expanded is 'true' but the toggle is unchecked",
    ]
    indeterminate = IDENTITY_ROWS.replace('md-toggle " type="checkbox" id="__nav_4"',
                                          'md-toggle md-toggle--indeterminate" type="checkbox" id="__nav_4"', 1)
    assert docs_expanded_mismatch(pane(indeterminate)) == ["indeterminate"]


def test_patterns_accept_the_pane_and_reject_markup_and_lookalike_hosts():
    labels = [row[1] for row in walk_docs(pane(IDENTITY_ROWS + HOME_CONTAINER_ROW + EXTERNAL_SECTION_ROW), IDENTITY_BASE)]
    labels += [row[1] for row in walk_landing(LANDING_PANE, LANDING_ROOT)]
    assert all(TITLE.fullmatch(label) for label in labels)
    for bad in ("Trace & Inspect", "<code>hooks</code>", "a > b", "", "Title\n", "a\nb"):
        assert not TITLE.fullmatch(bad)
        assert not TITLE.match(bad)

    for good in ("problem", "how-it-works", "v0_1"):
        assert ANCHOR.fullmatch(good)
    for bad in ("1st", "-x", "a b", "a#b", '"x', "", "problem\n"):
        assert not ANCHOR.fullmatch(bad)
        assert not ANCHOR.match(bad)

    for external in ("https://github.com", "mailto:x@example.com", "javascript:alert(1)", "/docs/", "//evil.example"):
        assert EXTERNAL.match(external)
    for internal in ("README.md", "concepts/identity.md", "topics/faq.md"):
        assert not EXTERNAL.match(internal)

    for good in (REPO_URL, REPO_URL + "/milestones", "https://owasp.slack.com", "https://github.com"):
        assert EXTERNAL_URL.match(good)
    for bad in ("http://github.com/x", "https://github.com.evil.example/", "https://evilgithub.com/",
                "https://github.com@evil.example/", "https://owasp.slack.com.evil.example",
                "https://GITHUB.com/x", "https://example.org/", "https://github.com\n"):
        # A prefix pattern, so match() is the call. The \Z tail still refuses a newline.
        assert not EXTERNAL_URL.match(bad)

    for good in ("README.md", "concepts/README.md", "spec/trace/OCSF/implementation_examples.md", "topics/faq.md"):
        assert DOC_PATH.fullmatch(good)
    for bad in ("/README.md", "../README.md", "a/../b.md", "a/..", "x.html", "a b.md", "a\\b.md", "x.md\n"):
        assert not DOC_PATH.fullmatch(bad)
        assert not DOC_PATH.match(bad)
    assert REPO_URL == "https://github.com/GenAI-Security-Project/agent-control-standard"


def test_module_imports_on_the_bare_interpreter():
    # -I drops the current directory from sys.path, so the tools directory goes in by
    # hand. -S keeps site-packages out, which is what proves the standard library only.
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c",
         f"import sys; sys.path.insert(0, {str(TOOLS)!r}); import site_nav"],
        cwd=TOOLS, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
