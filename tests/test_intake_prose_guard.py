"""The contributor-facing text must say what the intake gate in tools/pr_intake.py does.

Each test reads the shipped file, never a copy of the string, so a later edit to the
prose or to GATE_ORDER that leaves the two disagreeing fails here rather than reaching a
contributor as a promise the bot does not keep.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import base_branch_guard  # noqa: E402
import pr_intake  # noqa: E402
from apply_governance import desired_labels  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
CLAIM = "Comment on the issue to claim it before opening the pull request."
PRECEDENCE = "If a form, a template, or a bot comment disagrees with this section, this section wins."
# The block spells the per-issue cap as a word, so the test maps the constant to it.
NUMBER_WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five"}
# One key phrase per route after `bot`, in the order the block in CONTRIBUTING.md states them.
# `held` keys on "assigned to you" because that is how the verbatim block words it.
ROUTE_PHRASES = {
    "roster": "project lead",
    "engaged": "approval",
    "record": "merged a pull request of yours",
    "editorial": "editorial",
    "held": "assigned to you",
    "help_wanted": "help wanted",
}


def flat(text: str) -> str:
    """Collapse line wrapping, so a sentence reads the same however the file wraps it."""
    return re.sub(r"\s+", " ", text)


def read(relative: str) -> str:
    return flat((REPO_ROOT / relative).read_text(encoding="utf-8"))


def read_lines(relative: str) -> list[str]:
    return (REPO_ROOT / relative).read_text(encoding="utf-8").splitlines()


def section(heading: str) -> str:
    """The body of a `## ` section of CONTRIBUTING.md, up to the next `## ` heading."""
    raw = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    start = raw.index(f"## {heading}\n")
    end = raw.find("\n## ", start + 1)
    return flat(raw[start:] if end == -1 else raw[start:end])


def test_claim_phrase_is_in_contributing_readme_template_form_and_seed():
    for relative in (
        "CONTRIBUTING.md",
        "README.md",
        ".github/pull_request_template.md",
        ".github/ISSUE_TEMPLATE/3-reference-implementation.yml",
    ):
        assert CLAIM in read(relative), relative
    seed = next(label for label in desired_labels() if label.name == pr_intake.HELP_WANTED)
    assert CLAIM in seed.description


def test_contributing_has_the_precedence_sentence():
    assert PRECEDENCE in section("How work gets accepted")


def test_editorial_sentence_names_the_whole_documentation_lane():
    # base_branch_guard.in_docs_lane admits the root notice files too. The precedence
    # sentence makes this prose binding over the bot, so it must not name less.
    body = section("How work gets accepted")
    sentence = next(part for part in body.split(". ") if part.startswith("An editorial fix"))
    assert "`docs/topics/`" in sentence and "`design/`" in sentence
    assert "the root notice files" in sentence


def test_contributing_names_every_root_notice_file_the_lane_admits():
    # The editorial sentence says "the root notice files". This sentence says which, from
    # the same list the gate reads, so the two cannot drift.
    body = section("How work gets accepted")
    sentence = next(part for part in body.split(". ") if part.startswith("The root notice files are"))
    named = set(re.findall(r"`([^`]{1,64})`", sentence))
    assert set(base_branch_guard.DOCS_LANE_FILES) == named, set(base_branch_guard.DOCS_LANE_FILES) ^ named
    assert "`DOCS_LANE_FILES`" in sentence or "DOCS_LANE_FILES" in body


def test_readme_flow_names_the_lane_on_the_editorial_node():
    node = next(line for line in read_lines("README.md") if line.strip().startswith('E["Editorial fix'))
    assert "documentation lane" in node


def test_block_numbers_match_the_gate_constants():
    body = section("How work gets accepted")
    assert f"within the last {pr_intake.FRESH_REVIEW_DAYS} days" in body
    assert f"{NUMBER_WORDS[pr_intake.HELD_CAP]} open pull requests per person per issue" in body


def test_contributing_routes_follow_gate_order():
    routes = pr_intake.GATE_ORDER
    assert routes[0] == "bot"
    assert set(routes[1:]) == set(ROUTE_PHRASES), "a route was added or renamed without its phrase"
    body = section("How work gets accepted")
    positions = [body.find(ROUTE_PHRASES[route]) for route in routes[1:]]
    assert -1 not in positions, dict(zip(routes[1:], positions))
    assert positions == sorted(positions), dict(zip(routes[1:], positions))
    # The roster route covers triage volunteers, so the roster sentence names them.
    assert "a workstream lead, a triage volunteer, or a code owner" in body


def test_what_we_need_no_longer_promises_no_triage():
    body = section("What We Need")
    assert "without waiting on triage" not in body
    assert "Comment on one to claim it, then open the pull request. The comment is the claim." in body
