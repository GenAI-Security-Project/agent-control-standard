"""Tests for the closing-choice parser that package C checks with and package D reuses.

GitHub closes an issue from text, so these cases are the spellings and shapes GitHub reads:
each closing keyword, each reference form, lists, and the markdown that renders a keyword
the parser would otherwise miss.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from closing_choice import Reference, declared_closes, normalize, parse_references  # noqa: E402

URL = "https://github.com/GenAI-Security-Project/agent-control-standard/issues/"


def kinds(text: str) -> list[tuple[int, str]]:
    return [(ref.number, ref.kind) for ref in parse_references(normalize(text))]


@pytest.mark.parametrize(
    "keyword", ["close", "closes", "closed", "fix", "fixes", "fixed", "resolve", "resolves", "resolved"]
)
@pytest.mark.parametrize("colon", ["", ":"])
def test_every_closing_keyword_closes(keyword, colon):
    assert kinds(f"{keyword}{colon} #5") == [(5, "close")]
    assert kinds(f"{keyword.upper()}{colon} #5") == [(5, "close")]


@pytest.mark.parametrize("spelling", ["Part of", "Refs", "Contributes to", "part of:", "REFS:"])
def test_every_contributing_spelling_contributes(spelling):
    assert kinds(f"{spelling} #5") == [(5, "contribute")]


@pytest.mark.parametrize(
    "reference", ["#5", "GenAI-Security-Project/agent-control-standard#5", f"{URL}5",
                  "genai-security-project/Agent-Control-Standard#5"]
)
def test_every_reference_shape(reference):
    assert kinds(f"Closes {reference}") == [(5, "close")]


def test_other_repositories_are_ignored():
    assert kinds("Closes other-org/other-repo#5") == []
    assert kinds("Fixes https://github.com/other-org/other-repo/issues/5") == []


def test_contributing_list_covers_every_reference():
    assert kinds("Part of #5, #6, and #7") == [(5, "contribute"), (6, "contribute"), (7, "contribute")]


def test_closing_list_closes_only_the_first_reference():
    assert kinds("Closes #5, #6") == [(5, "close"), (6, "none")]


def test_keyword_on_another_line_governs_nothing():
    assert kinds("Closes\n#5") == [(5, "none")]
    assert kinds("This fixes the bug in #5") == [(5, "none")]


def test_markdown_link_and_emphasis_render_as_text():
    assert kinds(f"[Closes #5]({URL}5)") == [(5, "close")]
    assert kinds("**Fixes** #5") == [(5, "close")]
    assert kinds("_Refs_ #5") == [(5, "contribute")]


def test_crlf_text_reads_like_lf_text():
    assert normalize("a\r\nb\rc") == "a\nb\nc"
    assert kinds("Intro\r\nCloses #5\r\n") == [(5, "close")]


def test_pull_request_urls_and_mid_word_hashes_are_not_issue_references():
    assert kinds("Closes https://github.com/GenAI-Security-Project/agent-control-standard/pull/7") == []
    assert kinds("Closes abc#5") == []


def test_keyword_inside_a_qualified_reference_is_not_a_keyword():
    assert kinds("fixes/repo#5 Closes #6") == [(6, "close")]


def test_declared_closes_reads_the_whole_message():
    # A squash message from before package C carries the keyword in prose, as #174 did.
    assert declared_closes("Add the adapter\n\nCloses #95.", 95) == (True, False)
    assert declared_closes("Fixes #95 (#174)\n\nPart of #95", 95) == (True, True)
    assert declared_closes("Part of #95", 95) == (False, True)
    assert declared_closes("Closes #96", 95) == (False, False)
    assert declared_closes(None, 95) == (False, False)


def test_reference_carries_its_offset():
    refs = parse_references(normalize("x Closes #5"))
    assert refs == [Reference(number=5, kind="close", start=9)]


@pytest.mark.parametrize(
    "body",
    [
        "a" * 65_536,
        "[" * 65_536,
        "#" * 65_536,
        "Closes " * 9_363,
        "#1, " * 16_384,
        "Part of #1, " * 5_461,
        "fixes/" * 10_922,
        ("[" + "a" * 499) * 131,
        "-" * 65_536,
        "https://github.com/" * 3_449,
    ],
)
def test_adversarial_body_finishes_quickly(body):
    started = time.perf_counter()
    declared_closes(body + "x" * 70_000, 1)
    assert time.perf_counter() - started < 1.0


def test_text_past_the_limit_is_ignored():
    assert kinds("a" * 65_536 + "Closes #5") == []
