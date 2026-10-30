#!/usr/bin/env python3
"""Decide whether a pull request has an accepted issue behind it, and say so once.

Version 1.0. Owner: ACS project leads. This module holds the data model and the
parsing helpers. The gate logic, the collectors, and the writers join it in later
tasks of the same plan.

The workflow runs this under `python3 -I -S` from a checkout of `main`, never the pull
request's head, with the standard library and the sibling modules under `tools/` only.
Everything read from GitHub is untrusted text: titles, bodies, comments, and file paths
are attacker-controlled. Two rules follow. Free text never reaches a command line or a
log line unescaped, which is why `safe_path` exists. And the bot's own comment carries
state on its first line, the data line, which is parsed with a strict pattern so a
hostile comment cannot forge state. Every pattern here is linear, with bounded repeats
and no nested quantifiers, so a hostile body cannot stall the job.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta

import closing_choice

# The marker sits on line 2 of the bot comment. The data line sits on line 1, ahead of it.
MARKER = "<!-- acs-intake -->"
DATA_PREFIX = "<!-- acs-intake-data "
LEGACY_PREFIX = "Thanks for this. It is queued rather than ignored."
LEGACY_KEYWORD_MARKER = "<!-- acs-closing-keyword"
KNOWN_BOTS = frozenset({"dependabot[bot]", "github-actions[bot]"})

# Pull requests opened before this date are never held. The rollout commit sets the real
# value, the same pattern as roadmap_model.RULES_VERSION. This placeholder keeps the gate
# inert until then.
RULE_LANDED = date(2026, 11, 1)

# Budgets that bound API work per run. The reserve keeps room for the writes at the end.
MAX_REFERENCES = 20
MAX_CLAIM_READS = 5
MAX_CALLS = 600
BUDGET_RESERVE = 150

REASONS = (
    "no_accepted",
    "closed_accepted",
    "not_held",
    "editorial_off_lane",
    "paths_truncated",
    "held_cap",
    "sent_back",
    "awaiting_rereview",
    "retracted",
)
CLEAR_ROUTES = ("roster", "review", "hand", "record", "editorial", "assignment", "help_wanted")

DATA_KEYS = frozenset(
    {"reason", "route", "issues", "since", "cleared", "head", "cleared_head", "facts", "claimed", "seen"}
)
# Linear: one bounded group repeated at most 12 times, each repeat anchored by a literal
# `=` and an optional single space, with no quantified group inside another.
_DATA_LINE = re.compile(r"^<!-- acs-intake-data ((?:[a-z_]{1,16}=[A-Za-z0-9,._:-]{1,200} ?){1,12})-->$")
_PAIR = re.compile(r"([a-z_]{1,16})=([A-Za-z0-9,._:-]{1,200})")
_UNSAFE_PATH = re.compile(r"[^A-Za-z0-9._/-]")

FRESH_REVIEW_DAYS = 30


@dataclass(frozen=True)
class Reference:
    """An issue or pull request that this pull request names, with the facts the gate reads."""

    number: int
    kind: str
    is_pull: bool
    state: str | None
    labels: frozenset[str]
    assignees: frozenset[str]
    milestoned: bool
    author_commented_at: datetime | None
    unresolved: bool


@dataclass(frozen=True)
class Review:
    login: str
    state: str
    association: str
    submitted_at: datetime | None
    commit_id: str | None


@dataclass(frozen=True)
class BotComment:
    """The bot's existing comment on the pull request, parsed once at collection time."""

    id: int
    body: str
    data: dict[str, str] | None
    legacy: bool


@dataclass(frozen=True)
class Facts:
    """Everything the gate reads about one pull request, gathered before any decision."""

    number: int
    state: str
    draft: bool
    author: str  # casefolded
    author_is_bot: bool
    title: str
    body: str
    base: str
    head_sha: str
    created_at: datetime
    updated_at: datetime
    labels: frozenset[str]
    paths: tuple[str, ...]
    paths_truncated: bool
    references: tuple[Reference, ...]
    references_dropped: int
    reviews: tuple[Review, ...]
    last_unlabel: tuple[str, datetime] | None  # actor casefolded
    last_author_comment_at: datetime | None
    bot_comment: BotComment | None
    auto_merge: bool
    author_record: bool
    # The author's open pull requests, this one included, that reference each open accepted
    # issue, sorted ascending.
    held_use: dict[int, tuple[int, ...]]
    roster: frozenset[str]
    mode: str  # "legacy" or "enforced"
    sweep: bool
    event_action: str | None


@dataclass(frozen=True)
class Decision:
    outcome: str  # "pass", "queue", or "skip"
    route: str | None
    reasons: tuple[str, ...]
    label: str  # "set", "clear", or "keep"
    comment: str | None
    data: dict[str, str] | None
    disable_auto_merge: bool
    notices: tuple[str, ...]


def parse_data_line(body: str) -> dict[str, str] | None:
    """Read the bot's state from line 1 of a comment body, or None if it is not ours.

    Only line 1 counts. A well-formed line anywhere else is user text and carries no
    authority, so a forged `since=` further down cannot move a clock.
    """
    first = (body or "").split("\n", 1)[0].rstrip("\r")
    match = _DATA_LINE.match(first)
    if match is None:
        return None
    fields: dict[str, str] = {}
    for key, value in _PAIR.findall(match.group(1)):
        if key not in DATA_KEYS or key in fields:
            return None
        fields[key] = value
    return fields


def render_data_line(fields: dict[str, str]) -> str:
    """The data line for `fields`. Refuses anything `parse_data_line` could not read back."""
    line = DATA_PREFIX + " ".join(f"{key}={value}" for key, value in fields.items()) + "-->"
    if parse_data_line(line) != fields:
        raise ValueError("fields do not survive a round trip through the data line")
    return line


def editorial_ticked(body: str) -> bool:
    """Whether the editorial box is ticked, read exactly as the closing-choice check reads it."""
    return bool(closing_choice.EDITORIAL.search(closing_choice.normalize(body)))


def engaged_by_fresh_review(facts: Facts, today: date) -> bool:
    """Whether a CHANGES_REQUESTED review is recent enough to keep the pull request engaged."""
    cutoff = today - timedelta(days=FRESH_REVIEW_DAYS)
    return any(
        review.state == "CHANGES_REQUESTED"
        and review.submitted_at is not None
        and review.submitted_at.date() >= cutoff
        for review in facts.reviews
    )


def facts_hash(facts: Facts, today: date) -> str:
    """Twelve hex characters that change when anything the gate reads changes.

    `updated_at` is left out because any comment moves it, which would make the hash
    change on the bot's own writes. Review timestamps are left out for the same reason,
    and their one effect, freshness, enters through the derived boolean so a review that
    ages past thirty days still changes the hash. Title and body enter only through
    `editorial_ticked`, the one thing the gate reads from them.
    """
    parts = {
        "number": facts.number,
        "state": facts.state,
        "draft": facts.draft,
        "author": facts.author,
        "author_is_bot": facts.author_is_bot,
        "base": facts.base,
        "head_sha": facts.head_sha,
        "labels": sorted(facts.labels),
        "paths": list(facts.paths),
        "paths_truncated": facts.paths_truncated,
        "references": sorted(
            (
                ref.number, ref.kind, ref.is_pull, ref.state, sorted(ref.labels), sorted(ref.assignees),
                ref.milestoned, ref.author_commented_at, ref.unresolved,
            )
            for ref in facts.references
        ),
        "references_dropped": facts.references_dropped,
        "reviews": sorted((r.login, r.state, r.association, r.commit_id) for r in facts.reviews),
        "last_unlabel": facts.last_unlabel,
        "last_author_comment_at": facts.last_author_comment_at,
        "auto_merge": facts.auto_merge,
        "author_record": facts.author_record,
        "held_use": sorted(facts.held_use.items()),
        "roster": sorted(facts.roster),
        "mode": facts.mode,
        "engaged_by_fresh_review": engaged_by_fresh_review(facts, today),
        "editorial_ticked": editorial_ticked(facts.body),
    }
    return hashlib.sha256(repr(sorted(parts.items())).encode("utf-8")).hexdigest()[:12]


def safe_path(path: str) -> str:
    """A changed file's path made safe to print. Backticks, markup, and mentions become `?`."""
    return _UNSAFE_PATH.sub("?", path)[:200]
