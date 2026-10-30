"""Tests for the intake tool's data model: the facts hash, the data line, and the helpers."""
from __future__ import annotations

import dataclasses
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import closing_choice  # noqa: E402
import pr_intake  # noqa: E402
from pr_intake import Facts, Reference, Review, facts_hash, parse_data_line, render_data_line, safe_path  # noqa: E402

TODAY = date(2026, 11, 10)
NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
TEMPLATE = Path(__file__).resolve().parents[1] / ".github" / "pull_request_template.md"


def make_facts(**overrides) -> Facts:
    base = dict(
        number=7, state="open", draft=False, author="alice", author_is_bot=False, title="t", body="b",
        base="main", head_sha="a" * 40, created_at=NOW, updated_at=NOW, labels=frozenset(),
        paths=("docs/a.md",), paths_truncated=False, references=(), references_dropped=0, reviews=(),
        last_unlabel=None, last_author_comment_at=None, bot_comment=None, auto_merge=False,
        author_record=False, held_use={}, roster=frozenset({"bob"}), mode="enforced", sweep=False,
        event_action=None,
    )
    base.update(overrides)
    return Facts(**base)


def reference(number: int = 5) -> Reference:
    return Reference(
        number=number, kind="issue", is_pull=False, state="open", labels=frozenset({"accepted"}),
        assignees=frozenset(), milestoned=False, author_commented_at=None, unresolved=False,
    )


def test_data_line_round_trips():
    fields = {
        "reason": "no_accepted,held_cap", "route": "roster", "issues": "5,6", "since": "2026-11-01",
        "cleared": "2026-11-02", "head": "a" * 12, "cleared_head": "b" * 12, "facts": "0123456789ab",
        "claimed": "5:2026-11-01,6:2026-11-02", "seen": "2026-11-01T00:00:00Z,2026-11-02T00:00:00Z",
    }
    line = render_data_line(fields)
    assert line.startswith(pr_intake.DATA_PREFIX) and line.endswith("-->") and "\n" not in line
    assert parse_data_line(line) == fields
    assert parse_data_line(line + "\n" + pr_intake.MARKER) == fields


def test_parse_data_line_reads_line_one_only():
    body = "hello\n" + pr_intake.MARKER + "\n<!-- acs-intake-data since=2020-01-01 -->"
    assert parse_data_line(body) is None
    assert parse_data_line("") is None


@pytest.mark.parametrize(
    "line",
    [
        "<!-- acs-intake-data reason=a b -->",
        "<!-- acs-intake-data reason=a>b -->",
        "<!-- acs-intake-data bogus=1 -->",
        "<!-- acs-intake-data -->",
        "<!-- acs-intake-data reason= -->",
        "<!-- acs-intake-data reason=a --> trailing",
    ],
)
def test_data_line_rejects_bad_shapes(line):
    assert parse_data_line(line) is None


def test_render_data_line_refuses_what_it_could_not_read_back():
    with pytest.raises(ValueError):
        render_data_line({"reason": "a b"})
    with pytest.raises(ValueError):
        render_data_line({"bogus": "1"})


def test_facts_hash_changes_with_references_and_with_a_review_crossing_thirty_days_not_with_updated_at():
    base = make_facts()
    digest = facts_hash(base, TODAY)
    assert len(digest) == 12 and int(digest, 16) >= 0
    assert facts_hash(dataclasses.replace(base, updated_at=NOW + timedelta(days=1)), TODAY) == digest
    assert facts_hash(dataclasses.replace(base, references=(reference(),)), TODAY) != digest

    submitted = datetime(2026, 10, 15, tzinfo=timezone.utc)
    review = Review(login="bob", state="CHANGES_REQUESTED", association="MEMBER", submitted_at=submitted, commit_id="c" * 40)
    reviewed = dataclasses.replace(base, reviews=(review,))
    fresh = facts_hash(reviewed, submitted.date() + timedelta(days=30))
    stale = facts_hash(reviewed, submitted.date() + timedelta(days=31))
    assert fresh != stale


def test_editorial_ticked_agrees_with_closing_choice_on_the_template_line():
    line = next(l for l in TEMPLATE.read_text().splitlines() if "This is an editorial correction" in l)
    ticked = line.replace("[ ]", "[x]", 1)
    assert pr_intake.editorial_ticked(ticked) is True
    assert pr_intake.editorial_ticked(line) is False
    for text in (ticked, line, "**" + ticked + "**"):
        assert pr_intake.editorial_ticked(text) == bool(closing_choice.EDITORIAL.search(closing_choice.normalize(text)))


def test_safe_path_replaces_backtick_marker_and_at():
    cleaned = safe_path("a`b<!-- x -->@c d.md")
    assert not any(char in cleaned for char in "`<>@! ")
    assert cleaned.startswith("a?b?") and cleaned.endswith("?c?d.md")
    assert safe_path("docs/ok-1_2.md") == "docs/ok-1_2.md"
    assert len(safe_path("a" * 500)) == 200
