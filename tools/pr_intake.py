#!/usr/bin/env python3
"""Decide whether a pull request has an accepted issue behind it, and say so once.

Version 1.0. Owner: ACS project leads. This module holds the data model, the parsing
helpers, the gate, and the collector. `decide` is a pure function of `Facts` and the date,
with no I/O. `collect_facts` does every read, through `gh_runner`'s allowlisted shapes,
inside a call budget. The writers join them in a later task of the same plan.

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
import json
import re
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta, timezone

import base_branch_guard
import closing_choice
import roadmap_model
from gh_runner import Runner, RunnerError, paginate, split_http

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
    {"reason", "route", "issues", "since", "cleared", "head", "cleared_head", "cleared_at", "facts", "claimed", "seen"}
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


def _by_bot(unlabel: tuple[str, datetime] | None) -> bool:
    return unlabel is not None and unlabel[0].casefold() == roadmap_model.BOT_LOGIN


def facts_hash(facts: Facts, today: date) -> str:
    """Twelve hex characters that change when anything the gate reads changes.

    Included: number, state, draft, author, author_is_bot, base, head_sha, labels, paths,
    paths_truncated, references_dropped, reviews (login, state, association, commit_id),
    last_unlabel, last_author_comment_at, auto_merge, author_record, held_use, roster,
    mode, and every reference in full. The closing set enters through `references[].kind`,
    which `closing_choice.parse_references` sets from the keyword, so `Closes #5` becoming
    `Refs #5` changes the hash. `cleared_head` from the bot comment's data line enters
    too, because the gate compares it with `head_sha`. Two derived booleans enter as well:
    `engaged_by_fresh_review`, which carries review freshness, and `editorial_ticked`.

    `created_at` enters because the help wanted route compares the claim with it, and a
    reason behind the first one may turn on it. It never changes on a real pull request.

    `labels` enters without the queue label, and `last_unlabel` enters only when a person
    removed the label. The bot owns that label and writes both facts itself, so hashing
    them would make every write re-render on the next run. The queue state is already on
    the data line as its reason.

    Excluded: `updated_at`, because any comment moves it and the bot's own writes would
    change the hash. `cleared_at` from the data line, which is bot state that changes only
    together with `last_unlabel`, already hashed. Raw review timestamps, whose one effect is
    freshness, already carried by the derived boolean. `sweep` and `event_action`, which
    describe why the run started, not the pull request. `title` and `body`, which enter
    only through `editorial_ticked`, so an edit that changes no fact keeps the comment.
    """
    parts = {
        "number": facts.number,
        "state": facts.state,
        "draft": facts.draft,
        "author": facts.author,
        "author_is_bot": facts.author_is_bot,
        "base": facts.base,
        "head_sha": facts.head_sha,
        "created_at": facts.created_at,
        "labels": sorted(facts.labels - {roadmap_model.NEEDS_TRIAGE}),
        "paths": list(facts.paths),
        "paths_truncated": facts.paths_truncated,
        # Sorted by repr so a None beside a datetime or a string never raises TypeError.
        "references": sorted(
            (
                (
                    ref.number, ref.kind, ref.is_pull, ref.state, sorted(ref.labels), sorted(ref.assignees),
                    ref.milestoned, ref.author_commented_at, ref.unresolved,
                )
                for ref in facts.references
            ),
            key=repr,
        ),
        "references_dropped": facts.references_dropped,
        "reviews": sorted(((r.login, r.state, r.association, r.commit_id) for r in facts.reviews), key=repr),
        "cleared_head": (facts.bot_comment.data or {}).get("cleared_head") if facts.bot_comment else None,
        "last_unlabel": None if _by_bot(facts.last_unlabel) else facts.last_unlabel,
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


# --- The gate ---------------------------------------------------------------------------

GATE_ORDER = ("bot", "roster", "engaged", "record", "editorial", "held", "help_wanted")
LEAD_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
HELP_WANTED = "help wanted"
HELD_CAP = 2
MAX_PATHS = 20
MAX_COMMENT = 8_000
REPO_URL = f"https://github.com/{roadmap_model.REPO}"

QUEUED_LINE = "This pull request is queued rather than ignored. Nothing here is rejected."
LEGACY_COMMENT = (
    LEGACY_PREFIX
    + "\n\nThis pull request does not reference an issue carrying `status:accepted`, so a maintainer has not"
    " looked at it yet and will not until the underlying issue is triaged. Nothing here is rejected. See"
    f" [Current Priority Scope]({REPO_URL}/blob/main/CONTRIBUTING.md#current-priority-scope) for what the"
    f" project is working on, and [`help wanted`]({REPO_URL}/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)"
    " for work that is already accepted."
    "\n\nIf this is an editorial correction, tick that box in the description and this comment stops applying."
)
CLEARED_LINES = {
    "roster": "Its author is a project lead, a workstream lead, a triage volunteer, or a code owner.",
    "review": "A lead has reviewed it.",
    "hand": "A lead removed the queue label. That holds until the next push.",
    "record": "A lead approved and merged an earlier pull request by its author.",
    "editorial": "It is an editorial correction, and every changed file is on the documentation lane.",
    "assignment": "It references an accepted issue assigned to its author.",
    "help_wanted": "It references a `help wanted` issue its author commented on before opening it.",
}
_GATE_TO_CLEAR = {"roster": "roster", "record": "record", "editorial": "editorial", "held": "assignment",
                  "help_wanted": "help_wanted"}


def _on_roster(login: str, facts: Facts) -> bool:
    return login.casefold() in facts.roster


def _lead_reviews(facts: Facts) -> list[Review]:
    """Reviews that speak for the project: a roster login that also holds a repository role."""
    return [r for r in facts.reviews if _on_roster(r.login, facts) and r.association in LEAD_ASSOCIATIONS]


def _fresh(review: Review, today: date) -> bool:
    return review.submitted_at is not None and review.submitted_at.date() >= today - timedelta(days=FRESH_REVIEW_DAYS)


def _stored(facts: Facts) -> dict[str, str]:
    """The bot's own state from its last comment. A legacy comment carries none."""
    if facts.bot_comment is None or facts.bot_comment.data is None:
        return {}
    return facts.bot_comment.data


def _unlabel_time(facts: Facts) -> str:
    """The last unlabel's time in the data line's form. A naive time is read as UTC."""
    when = facts.last_unlabel[1]
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hand_clear(facts: Facts) -> tuple[bool, bool]:
    """Whether a lead's removal of the label stands, and whether this run must record it.

    The clear is bound to the head it was made at, so a push after it does not ride on it.
    A removal newer than the recorded one is a fresh clear at the current head, so a lead
    who clears again after a push is not overruled. The run that first sees a removal
    records its head and time.
    """
    if facts.last_unlabel is None or not _on_roster(facts.last_unlabel[0], facts):
        return False, False
    stored = _stored(facts)
    recorded_at = stored.get("cleared_at")
    # Both sides are fixed-width UTC strings, so string order is time order.
    if recorded_at is None or _unlabel_time(facts) > recorded_at:
        return True, True
    return stored.get("cleared_head") == facts.head_sha, False


def _engaged(facts: Facts, today: date) -> str | None:
    for review in _lead_reviews(facts):
        if review.state == "APPROVED" or (review.state == "CHANGES_REQUESTED" and _fresh(review, today)):
            return "review"
    return "hand" if _hand_clear(facts)[0] else None


def _off_lane(facts: Facts) -> tuple[str, ...]:
    return tuple(path for path in facts.paths if not base_branch_guard.in_docs_lane(path))


def _editorial(facts: Facts) -> str | None:
    """None when the box is not ticked, else "pass" or "queue"."""
    if not editorial_ticked(facts.body):
        return None
    # A truncated listing may hide an off-lane path, so it never passes.
    return "queue" if facts.paths_truncated or _off_lane(facts) else "pass"


def _accepted_issues(facts: Facts) -> list[Reference]:
    """Referenced issues carrying status:accepted. A pull request number is never an issue."""
    return [
        ref for ref in facts.references
        if not ref.is_pull and not ref.unresolved and roadmap_model.ACCEPTED in ref.labels
    ]


def _is_open(ref: Reference) -> bool:
    return (ref.state or "").casefold() == "open"


def _uses(facts: Facts, number: int) -> tuple[int, ...]:
    # The collector fills held_use for every referenced open accepted issue. A missing entry
    # means this pull request is the only one, which is the reading that cannot exceed the cap.
    return facts.held_use.get(number, (facts.number,))


def _within_cap(facts: Facts, number: int) -> bool:
    return facts.number in _uses(facts, number)[:HELD_CAP]


def _assigned(facts: Facts, ref: Reference) -> bool:
    return facts.author.casefold() in {login.casefold() for login in ref.assignees}


def _claimed_help(facts: Facts, ref: Reference) -> bool:
    return (
        HELP_WANTED in ref.labels
        and ref.author_commented_at is not None
        and ref.author_commented_at < facts.created_at
    )


def _route_holds(name: str, facts: Facts, today: date) -> bool:
    open_accepted = [ref for ref in _accepted_issues(facts) if _is_open(ref)]
    if name == "roster":
        return _on_roster(facts.author, facts)
    if name == "engaged":
        return _engaged(facts, today) is not None
    if name == "record":
        return facts.author_record
    if name == "held":
        return any(_assigned(facts, ref) and _within_cap(facts, ref.number) for ref in open_accepted)
    if name == "help_wanted":
        return any(_claimed_help(facts, ref) and _within_cap(facts, ref.number) for ref in open_accepted)
    raise ValueError(f"unknown route {name}")


def _walk(facts: Facts, today: date) -> tuple[str | None, tuple[str, ...]]:
    """The gate route that passed, or None, and the routes that did not hold before it."""
    if facts.author in KNOWN_BOTS or facts.draft:
        return "bot", ()
    unmet: list[str] = []
    for name in GATE_ORDER[1:]:
        if name == "editorial":
            state = _editorial(facts)
            if state == "pass":
                return name, tuple(unmet)
            unmet.append(name)
            # A tick on an off-lane path is a claim the bot can check and refute, so it queues
            # before the issue routes are read. PR #354 is the case this exists for.
            if state == "queue":
                return None, tuple(unmet)
            continue
        if _route_holds(name, facts, today):
            return name, tuple(unmet)
        unmet.append(name)
    return None, tuple(unmet)


def unmet_routes(facts: Facts, today: date) -> tuple[str, ...]:
    """The routes in GATE_ORDER the gate read and found unmet, in order."""
    return _walk(facts, today)[1]


def _stale_review(facts: Facts, today: date) -> str | None:
    """sent_back or awaiting_rereview when a lead's newest review asked for changes too long ago."""
    dated = [review for review in _lead_reviews(facts) if review.submitted_at is not None]
    if not dated:
        return None
    newest = max(dated, key=lambda review: review.submitted_at)
    if newest.state != "CHANGES_REQUESTED" or _fresh(newest, today):
        return None
    pushed = newest.commit_id is not None and newest.commit_id != facts.head_sha
    replied = facts.last_author_comment_at is not None and facts.last_author_comment_at > newest.submitted_at
    return "awaiting_rereview" if pushed or replied else "sent_back"


def _issue_reasons(facts: Facts) -> set[str]:
    accepted = _accepted_issues(facts)
    found: set[str] = set()
    if not accepted:
        found.add("no_accepted")
    for ref in accepted:
        if not _is_open(ref):
            found.add("closed_accepted")
        elif _assigned(facts, ref) or _claimed_help(facts, ref):
            # Held or claimed, and the routes still failed, so the cap is what stopped it.
            found.add("held_cap")
        else:
            found.add("not_held")
    return found


def _reasons(facts: Facts, today: date) -> tuple[str, ...]:
    """Why the pull request is queued, in gate order: the review first, then the rest."""
    stale = _stale_review(facts, today)
    lead = (stale,) if stale else ()
    if _editorial(facts) == "queue":
        found = {"editorial_off_lane"} if _off_lane(facts) else set()
        if facts.paths_truncated:
            found.add("paths_truncated")
    else:
        found = _issue_reasons(facts)
    return lead + tuple(reason for reason in REASONS if reason in found)


def _roadmap_closes(facts: Facts) -> tuple[int, ...]:
    """Open milestoned issues this pull request closes by keyword, which merging would deliver."""
    return tuple(sorted({
        ref.number for ref in facts.references
        if ref.kind == "close" and not ref.is_pull and ref.milestoned and _is_open(ref)
    }))


def _auto_merge_off(facts: Facts, queued: bool) -> bool:
    # Keyed on state, not on the event, so enabling auto-merge after an edit is caught too.
    if not facts.auto_merge:
        return False
    return queued or (not _on_roster(facts.author, facts) and bool(_roadmap_closes(facts)))


# Data line values stop at 200 characters. A bounded count of the lowest numbers keeps a
# body naming many issues from making the line unwritable.
MAX_DATA_ISSUES = 10


def _claims(facts: Facts) -> list[tuple[int, date]]:
    """Comments by the author on accepted open issues they do not hold, which may be claims."""
    return sorted(
        (ref.number, ref.author_commented_at.date())
        for ref in _accepted_issues(facts)
        if _is_open(ref) and not _assigned(facts, ref) and ref.author_commented_at is not None
    )


def _hash_as_read_next(facts: Facts, cleared_head: str | None, today: date) -> str:
    """The facts hash the next run computes, once this run's cleared_head is on the comment."""
    if cleared_head == _stored(facts).get("cleared_head"):
        return facts_hash(facts, today)
    comment = BotComment(id=0, body="", data={"cleared_head": cleared_head} if cleared_head else None, legacy=False)
    return facts_hash(replace(facts, bot_comment=comment), today)


def _data(
    facts: Facts, today: date, route: str | None, reasons: tuple[str, ...], cleared_head: str | None,
    cleared_at: str | None,
) -> dict[str, str]:
    stored = _stored(facts)
    data: dict[str, str] = {}
    if route is not None:
        data["reason"] = "cleared"
        data["route"] = route
        same = stored.get("reason") == "cleared" and stored.get("route") == route
        data["cleared"] = stored["cleared"] if same and "cleared" in stored else today.isoformat()
    else:
        data["reason"] = reasons[0]
        issues = sorted({ref.number for ref in _accepted_issues(facts)})
        if issues:
            data["issues"] = ",".join(str(number) for number in issues[:MAX_DATA_ISSUES])
        # The queue clock runs from the first queue and survives re-renders, so the health
        # issue's day count is the time waited, not the time since the last edit.
        queued_before = stored.get("reason") not in (None, "cleared") and "since" in stored
        data["since"] = stored["since"] if queued_before else today.isoformat()
        claims = _claims(facts)
        if claims:
            data["claimed"] = ",".join(f"{number}:{when.isoformat()}" for number, when in claims[:MAX_CLAIM_READS])
    data["head"] = facts.head_sha
    if cleared_head:
        data["cleared_head"] = cleared_head
    if cleared_at:
        data["cleared_at"] = cleared_at
    data["facts"] = _hash_as_read_next(facts, cleared_head, today)
    return data


def _legacy(facts: Facts, today: date) -> Decision:
    """Today's behavior: queue a human's pull request once, and only on an event run."""
    would = _enforced(facts, today)
    notices = (
        f"Would {would.outcome} once enforced: route={would.route or 'none'}"
        f" reasons={','.join(would.reasons) or 'none'} auto_merge_off={would.disable_auto_merge}",
    )
    any_accepted = any(
        roadmap_model.ACCEPTED in ref.labels for ref in facts.references if not ref.is_pull
    )
    writes = (
        not facts.sweep
        and not any_accepted
        and not editorial_ticked(facts.body)
        and facts.bot_comment is None
        and facts.author not in KNOWN_BOTS
    )
    if writes:
        return Decision("queue", None, ("no_accepted",), "set", LEGACY_COMMENT, None, False, notices)
    return Decision("skip", None, (), "keep", None, None, False, notices)


def _enforced(facts: Facts, today: date) -> Decision:
    gate, _unmet = _walk(facts, today)
    stored = _stored(facts)
    passed = gate is not None
    if passed:
        route = _engaged(facts, today) if gate == "engaged" else _GATE_TO_CLEAR[gate]
        reasons: tuple[str, ...] = ()
    else:
        route, reasons = None, _reasons(facts, today)
    recorded, recorded_at, newly = stored.get("cleared_head"), stored.get("cleared_at"), False
    if route == "hand":
        newly = _hand_clear(facts)[1]
        if newly:
            recorded, recorded_at = facts.head_sha, _unlabel_time(facts)
    data = _data(facts, today, route, reasons, recorded, recorded_at)
    labeled = roadmap_model.NEEDS_TRIAGE in facts.labels
    decision = Decision(
        outcome="pass" if passed else "queue",
        route=route,
        reasons=reasons,
        label=("clear" if labeled else "keep") if passed else "set",
        comment=None,
        data=data,
        disable_auto_merge=_auto_merge_off(facts, not passed),
        notices=(),
    )
    if stored.get("facts") == data["facts"] and stored.get("reason") == data["reason"]:
        # The queue label is outside the hash, so a label that drifted from the recorded
        # state is repaired here without re-rendering the comment.
        drift = "set" if not passed and not labeled else "clear" if passed and labeled else "keep"
        return Decision(decision.outcome, route, reasons, drift, None, stored, decision.disable_auto_merge, ())
    # A pass on a pull request the bot never spoke on stays silent, unless the merger needs
    # the roadmap warning or a hand clear must be recorded.
    if passed and facts.bot_comment is None and not labeled and not _roadmap_closes(facts) and not newly:
        return decision
    return Decision(
        decision.outcome, route, reasons, decision.label, render_comment(facts, decision, today), data,
        decision.disable_auto_merge, (),
    )


def decide(facts: Facts, today: date) -> Decision:
    """The gate's decision for one pull request: what to label, say, and record. No I/O."""
    if facts.author in KNOWN_BOTS or facts.draft:
        return Decision("skip", None, (), "keep", None, None, False, ())
    if facts.mode == "legacy":
        return _legacy(facts, today)
    return _enforced(facts, today)


# --- The comment ------------------------------------------------------------------------

def _numbers(numbers: list[int] | tuple[int, ...], prefix: str = "#") -> str:
    """#a, or #a and #b, or #a, #b, and #c."""
    names = [f"{prefix}{number}" for number in numbers]
    if len(names) <= 2:
        return " and ".join(names)
    return ", ".join(names[:-1]) + ", and " + names[-1]


def _paths(paths: tuple[str, ...]) -> str:
    shown = ", ".join(f"`{safe_path(path)}`" for path in paths[:MAX_PATHS])
    extra = len(paths) - MAX_PATHS
    return shown + (f", and {extra} more" if extra > 0 else "")


def _review_paragraph(reason: str) -> str:
    if reason == "sent_back":
        return (
            "A lead requested changes more than 30 days ago, and nothing has changed since. Push the changes"
            " or reply on the review, and a lead looks again."
        )
    return (
        "A lead requested changes more than 30 days ago, and this pull request has changed since. It is"
        " waiting on the lead's re-review."
    )


def _not_held_paragraph(facts: Facts) -> str:
    refs = [
        ref for ref in _accepted_issues(facts)
        if _is_open(ref) and not _assigned(facts, ref) and not _claimed_help(facts, ref)
    ]
    numbers = sorted({ref.number for ref in refs})
    if len(numbers) == 1:
        lines = [f"This pull request references #{numbers[0]}, which is accepted and is not assigned to you."]
    else:
        nobody = "neither" if len(numbers) == 2 else "none"
        lines = [f"This pull request references {_numbers(numbers)}, which are accepted, and {nobody} is assigned to you."]
    claims = _claims(facts)
    for number, when in claims:
        lines.append(f"You commented on #{number} on {when.isoformat()}. If that was a claim, it is waiting on a lead.")
    if not claims:
        lines.append(
            "To claim one, comment on it, and a lead may assign it. A lead's approval of this pull request,"
            " or a changes-requested review, also clears the queue by the next nightly run."
        )
    return " ".join(lines)


def _held_cap_paragraph(facts: Facts) -> str:
    capped = sorted({
        ref.number for ref in _accepted_issues(facts)
        if _is_open(ref) and (_assigned(facts, ref) or _claimed_help(facts, ref))
    })
    return " ".join(
        f"#{number} already clears {_numbers(_uses(facts, number)[:HELD_CAP], 'PR #')}." for number in capped
    )


def _reason_paragraph(reason: str, facts: Facts) -> str:
    if reason in ("sent_back", "awaiting_rereview"):
        return _review_paragraph(reason)
    if reason == "editorial_off_lane":
        return (
            "The editorial box covers the documentation lane (`docs/topics/`, `design/`, and the root notice"
            f" files). These paths are outside it: {_paths(_off_lane(facts))}. Fold the wording change into the"
            " next pull request that changes the file, or leave it as a comment on the issue it concerns."
        )
    if reason == "paths_truncated":
        return (
            "The editorial box covers the documentation lane, but this pull request changes more files than"
            " the bot can list, so it cannot confirm that every path is on the lane. A lead reviews it instead."
        )
    if reason == "no_accepted":
        return (
            "This pull request references no open accepted issue. See"
            f" [Current Priority Scope]({REPO_URL}/blob/main/CONTRIBUTING.md#current-priority-scope) and"
            f" [`help wanted`]({REPO_URL}/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)"
            " for what the project has asked for."
        )
    if reason == "closed_accepted":
        closed = sorted({ref.number for ref in _accepted_issues(facts) if not _is_open(ref)})
        if len(closed) == 1:
            return f"This pull request references #{closed[0]}, which was accepted and is now closed. New work on it needs a new issue."
        return f"This pull request references {_numbers(closed)}, which were accepted and are now closed. New work on them needs a new issue."
    if reason == "not_held":
        return _not_held_paragraph(facts)
    if reason == "held_cap":
        return _held_cap_paragraph(facts)
    raise ValueError(f"no wording for reason {reason}")


def _auto_merge_line(facts: Facts) -> str:
    closes = _roadmap_closes(facts)
    if closes and not _on_roster(facts.author, facts):
        noun = "issue" if len(closes) == 1 else "issues"
        return (
            f"Auto-merge is off because this pull request closes roadmap {noun} {_numbers(closes)}."
            " A lead merges it by hand after confirming delivery."
        )
    return "Auto-merge is off while this pull request is queued."


def _keyword_warning(closes: tuple[int, ...]) -> str:
    verb = "is" if len(closes) == 1 else "are"
    issue_word = "that issue" if len(closes) == 1 else "those issues"
    return (
        f"This pull request's description says it closes {_numbers(closes)}, which {verb} on the project"
        f" roadmap. When it merges, GitHub closes {issue_word} and the roadmap counts it as delivered."
        " Please confirm the change delivers the whole issue before merging."
    )


def _reversed_unlabel(facts: Facts) -> bool:
    if facts.last_unlabel is None or roadmap_model.NEEDS_TRIAGE in facts.labels:
        return False
    actor = facts.last_unlabel[0].casefold()
    return not _on_roster(actor, facts) and actor != roadmap_model.BOT_LOGIN


def render_comment(facts: Facts, decision: Decision, today: date) -> str:
    """The bot's one comment: the data line, the marker, then a paragraph per point.

    Nothing from the pull request reaches this text except paths through `safe_path`,
    inside code spans, and issue and pull request numbers. No login appears, so the bot
    never mentions anyone.
    """
    data = decision.data or {}
    paragraphs: list[str] = []
    if decision.outcome == "queue":
        paragraphs.append(QUEUED_LINE)
        paragraphs.extend(_reason_paragraph(reason, facts) for reason in decision.reasons)
        if facts.references_dropped:
            paragraphs.append(
                f"The bot read the first {MAX_REFERENCES} issues this pull request names, and"
                f" {facts.references_dropped} more were not read."
            )
        if _reversed_unlabel(facts):
            paragraphs.append(
                "The queue label was removed by someone other than a lead, so the bot set it again."
                " A lead's removal clears the queue."
            )
        if facts.created_at.date() < RULE_LANDED:
            since = data.get("since", today.isoformat())
            paragraphs.append(
                "This pull request was opened before the intake rule took effect."
                f" The rule is new, and its 30-day clock starts on {since}."
            )
    else:
        paragraphs.append("This pull request is not queued. " + CLEARED_LINES[decision.route])
    if decision.disable_auto_merge:
        paragraphs.append(_auto_merge_line(facts))
    closes = _roadmap_closes(facts)
    if closes:
        paragraphs.append(_keyword_warning(closes))
    text = render_data_line(data) + "\n" + MARKER + "\n\n" + "\n\n".join(paragraphs)
    return text[:MAX_COMMENT]


# --- Collecting facts -------------------------------------------------------------------

_API = f"repos/{roadmap_model.REPO}"
# GitHub caps a pull request's files listing at 3,000 entries.
MAX_FILES = 3_000
_OWN_LINK = f"https://github.com/{roadmap_model.REPO}".casefold()
# Bounded and linear. An opening tag scan stops at the next `<` or `>`, and the closing
# tag allows a bounded run of spaces. Neither crosses a line any differently, since no
# pattern here needs DOTALL.
_ANCHOR_OPEN = re.compile(r"<a\s[^<>]{0,2048}>", re.IGNORECASE)
_ANCHOR_CLOSE = re.compile(r"</a\s{0,2048}>", re.IGNORECASE)
_HREF = re.compile(r"""(?<![A-Za-z0-9_-])href[ \t]{0,8}=[ \t]{0,8}["']?([^"'\s<>]{0,2048})""", re.IGNORECASE)
_KIND_RANK = {"none": 0, "contribute": 1, "close": 2}


class ListingError(RuntimeError):
    """A shared listing failed to arrive, so no pull request can be evaluated this run."""


class BudgetStop(RuntimeError):
    """The run spent its call budget. The caller stops and counts the rest as skipped."""


class CallCounter:
    """Counts runner calls across a run and stops the run past its limit.

    The check runs before the call, so the call that would exceed the limit never starts.
    """

    def __init__(self, limit: int = MAX_CALLS) -> None:
        self.limit = limit
        self.calls = 0

    def wrap(self, run: Runner) -> Runner:
        def counted(args: list[str], stdin: str | None = None) -> tuple[int, str, str]:
            if self.calls >= self.limit:
                raise BudgetStop(f"call budget of {self.limit} spent")
            self.calls += 1
            return run(args, stdin)

        return counted


def _login(user: object) -> str | None:
    """A casefolded login, or None for a deleted account or a malformed user."""
    if not isinstance(user, dict) or not isinstance(user.get("login"), str):
        return None
    return user["login"].casefold()


def _when(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _label_names(labels: object) -> frozenset[str]:
    return frozenset(label["name"] for label in labels or () if isinstance(label, dict) and isinstance(label.get("name"), str))


@dataclass
class Listings:
    """The shared listings one run reads once and every pull request's facts resolve against.

    `approved_merged` maps a casefolded author to the merged pull requests of theirs that a
    lead approved. It fills lazily, one author at a time, and is cached for the run.
    """

    accepted: dict[int, dict]
    milestoned: dict[int, dict]
    open_pulls: list[dict]
    merged_pulls: list[dict]
    approved_merged: dict[str, frozenset[int]] = field(default_factory=dict)

    def approved_for(self, run: Runner, author: str, roster: frozenset[str]) -> frozenset[int]:
        """The author's merged pull requests with an approval by a lead, read once per author."""
        if author not in self.approved_merged:
            approved: set[int] = set()
            for pull in self.merged_pulls:
                if _login(pull.get("user")) != author:
                    continue
                for review in paginate(run, f"{_API}/pulls/{int(pull['number'])}/reviews?per_page=100"):
                    user = review.get("user") if isinstance(review, dict) else None
                    if (
                        isinstance(user, dict) and user.get("type") != "Bot" and _login(user) in roster
                        and review.get("state") == "APPROVED" and review.get("author_association") in LEAD_ASSOCIATIONS
                    ):
                        approved.add(int(pull["number"]))
                        break
            # Cached only once every read succeeded, so a failed read is retried, never remembered.
            self.approved_merged[author] = frozenset(approved)
        return self.approved_merged[author]


def _issues_by_number(items: list) -> dict[int, dict]:
    # The issues endpoint lists pull requests too. They are never issues here.
    return {
        int(item["number"]): item for item in items
        if isinstance(item, dict) and "pull_request" not in item and isinstance(item.get("number"), int)
    }


def _pulls(items: list) -> list[dict]:
    return [item for item in items if isinstance(item, dict) and isinstance(item.get("number"), int)]


def load_listings(run: Runner) -> Listings:
    """Read the four shared listings. Any failure is a ListingError, never an empty listing."""
    try:
        accepted = paginate(run, f"{_API}/issues?labels=status%3Aaccepted&state=all&per_page=100")
        milestoned = paginate(run, f"{_API}/issues?milestone=%2A&state=all&per_page=100")
        open_pulls = paginate(run, f"{_API}/pulls?state=open&per_page=100")
        closed_pulls = paginate(run, f"{_API}/pulls?state=closed&sort=updated&direction=desc&per_page=100")
    except RunnerError as exc:
        raise ListingError(f"a shared listing failed: {exc}") from exc
    return Listings(
        accepted=_issues_by_number(accepted),
        milestoned=_issues_by_number(milestoned),
        open_pulls=_pulls(open_pulls),
        merged_pulls=[pull for pull in _pulls(closed_pulls) if pull.get("merged_at") is not None],
    )


def _ours(href: str) -> bool:
    folded = href.casefold()
    return folded == _OWN_LINK or folded.startswith(_OWN_LINK + "/")


def strip_foreign_anchors(text: str) -> str:
    """Drop every HTML anchor that links outside this repository, with its text.

    A Dependabot changelog links other projects' issues as `<a href="...">#92</a>`, and
    the `#92` would otherwise read as this repository's issue. An anchor with no closing
    tag drops the rest of the text, so nothing inside a foreign anchor is ever adopted.
    """
    out: list[str] = []
    pos = 0
    while True:
        opening = _ANCHOR_OPEN.search(text, pos)
        if opening is None:
            out.append(text[pos:])
            break
        href = _HREF.search(opening.group(0))
        if href is not None and _ours(href.group(1)):
            out.append(text[pos:opening.end()])
            pos = opening.end()
            continue
        out.append(text[pos:opening.start()])
        closing = _ANCHOR_CLOSE.search(text, opening.end())
        if closing is None:
            break
        out.append(" ")
        pos = closing.end()
    return "".join(out)


def referenced(title: str | None, body: str | None) -> tuple[list[tuple[int, str]], int]:
    """The distinct numbers a pull request names, title first, and how many were dropped.

    A number named twice keeps its first position and its strongest spelling, so a
    `Refs #5` before a `Closes #5` still reads as a close, which is what merging does.
    """
    kinds: dict[int, str] = {}
    for text in (title or "", body or ""):
        cleaned = strip_foreign_anchors(text[: closing_choice.MAX_CHARS])
        for ref in closing_choice.parse_references(closing_choice.normalize(cleaned)):
            previous = kinds.get(ref.number)
            if previous is None or _KIND_RANK[ref.kind] > _KIND_RANK[previous]:
                kinds[ref.number] = ref.kind
    numbers = list(kinds)
    return [(number, kinds[number]) for number in numbers[:MAX_REFERENCES]], max(0, len(numbers) - MAX_REFERENCES)


def _read_pull(run: Runner, number: int) -> dict:
    code, stdout, _stderr = run(["api", "-i", f"{_API}/pulls/{number}"], None)
    if not stdout:
        raise RunnerError(f"pull request read exited {code}")
    status, _headers, body = split_http(stdout)
    if status != 200:
        raise RunnerError(f"pull request read returned HTTP {status}")
    try:
        pull = json.loads(body)
    except ValueError:
        raise RunnerError("pull request read returned non-JSON output") from None
    if not isinstance(pull, dict):
        raise RunnerError("pull request read returned something other than an object")
    return pull


def _resolve(number: int, kind: str, listings: Listings, pulls: dict[int, dict]) -> Reference:
    """A reference resolved from the listings alone. Nothing here reads `issues/{m}`."""
    if number in pulls:
        pull = pulls[number]
        return Reference(number, kind, True, pull.get("state"), _label_names(pull.get("labels")), frozenset(), False,
                         None, False)
    issue = listings.accepted.get(number) or listings.milestoned.get(number)
    if issue is None:
        return Reference(number, kind, False, None, frozenset(), frozenset(), False, None, True)
    assignees = frozenset(login for login in map(_login, issue.get("assignees") or ()) if login)
    return Reference(
        number, kind, False, issue.get("state"), _label_names(issue.get("labels")), assignees,
        issue.get("milestone") is not None, None, False,
    )


def _open_accepted(ref: Reference) -> bool:
    return (
        not ref.is_pull and not ref.unresolved and (ref.state or "").casefold() == "open"
        and roadmap_model.ACCEPTED in ref.labels
    )


def _earliest_by(comments: list, author: str) -> datetime | None:
    times = [_when(c.get("created_at")) for c in comments if isinstance(c, dict) and _login(c.get("user")) == author]
    return min((t for t in times if t is not None), default=None)


def _latest_by(comments: list, author: str) -> datetime | None:
    times = [_when(c.get("created_at")) for c in comments if isinstance(c, dict) and _login(c.get("user")) == author]
    return max((t for t in times if t is not None), default=None)


def _bot_comment(comments: list) -> BotComment | None:
    """The bot's own comment. Only the bot's exact login counts, whatever another comment says."""
    mine = [
        c for c in comments
        if isinstance(c, dict) and isinstance(c.get("user"), dict) and c["user"].get("login") == roadmap_model.BOT_LOGIN
        and isinstance(c.get("body"), str)
    ]
    for comment in mine:
        if MARKER in comment["body"]:
            return BotComment(int(comment["id"]), comment["body"], parse_data_line(comment["body"]), False)
    for comment in mine:
        body = comment["body"]
        if body.startswith(LEGACY_PREFIX) or LEGACY_KEYWORD_MARKER in body:
            return BotComment(int(comment["id"]), body, None, True)
    return None


def _last_unlabel(timeline: list) -> tuple[str, datetime] | None:
    """The newest removal of the queue label and who made it.

    Only `unlabeled` events are read, and only their `actor` and `created_at`, which GitHub
    sets. A `committed` event's author and committer dates are set by whoever pushed, so
    they are never read.
    """
    found: list[tuple[datetime, str]] = []
    for event in timeline:
        if not isinstance(event, dict) or event.get("event") != "unlabeled":
            continue
        label = event.get("label")
        if not isinstance(label, dict) or label.get("name") != roadmap_model.NEEDS_TRIAGE:
            continue
        actor, when = _login(event.get("actor")), _when(event.get("created_at"))
        if actor is not None and when is not None:
            found.append((when, actor))
    if not found:
        return None
    when, actor = max(found)
    return actor, when


def _reviews(raw: list) -> tuple[Review, ...]:
    """Reviews by people. A deleted account, a bot, and a dismissed review count for nothing."""
    reviews = []
    for review in raw:
        if not isinstance(review, dict):
            continue
        user = review.get("user")
        login = _login(user)
        if login is None or user.get("type") == "Bot" or review.get("state") == "DISMISSED":
            continue
        commit = review.get("commit_id")
        reviews.append(Review(
            login=login, state=str(review.get("state") or ""), association=str(review.get("author_association") or ""),
            submitted_at=_when(review.get("submitted_at")), commit_id=commit if isinstance(commit, str) else None,
        ))
    return tuple(reviews)


def _held_use(number: int, author: str, refs: tuple[Reference, ...], listings: Listings) -> dict[int, tuple[int, ...]]:
    """For each open accepted issue this pull request names, the author's open pulls naming it.

    This pull request counts from its own fresh title and body, the others from the listing.
    A draft is out of the gate's scope, so another draft never takes a slot.
    """
    wanted = {ref.number for ref in refs if _open_accepted(ref)}
    uses: dict[int, set[int]] = {issue_number: {number} for issue_number in wanted}
    for pull in listings.open_pulls:
        other = int(pull["number"])
        if other == number or pull.get("draft") or _login(pull.get("user")) != author:
            continue
        named, _dropped = referenced(pull.get("title"), pull.get("body"))
        for issue_number, _kind in named:
            if issue_number in uses:
                uses[issue_number].add(other)
    return {issue_number: tuple(sorted(pulls)) for issue_number, pulls in uses.items()}


def collect_facts(
    run: Runner, number: int, *, listings: Listings, roster: frozenset[str], mode: str, sweep: bool,
    event_action: str | None, counter: CallCounter,
) -> Facts:
    """Read one pull request's facts: five reads, at most five claim reads, and the record.

    A failed read raises RunnerError. A response in a shape this cannot read raises
    RunnerError too, so the caller counts an evaluation error instead of a default fact.
    """
    run = counter.wrap(run)
    pull = _read_pull(run, number)
    files = paginate(run, f"{_API}/pulls/{number}/files?per_page=100")
    raw_reviews = paginate(run, f"{_API}/pulls/{number}/reviews?per_page=100")
    comments = paginate(run, f"{_API}/issues/{number}/comments?per_page=100")
    timeline = paginate(run, f"{_API}/issues/{number}/timeline?per_page=100")
    try:
        return _assemble(run, number, pull, files, raw_reviews, comments, timeline, listings=listings, roster=roster,
                         mode=mode, sweep=sweep, event_action=event_action)
    except (KeyError, TypeError, ValueError) as exc:
        raise RunnerError(f"pull request {number} had a response in an unexpected shape: {type(exc).__name__}") from None


def _assemble(
    run: Runner, number: int, pull: dict, files: list, raw_reviews: list, comments: list, timeline: list, *,
    listings: Listings, roster: frozenset[str], mode: str, sweep: bool, event_action: str | None,
) -> Facts:
    author = _login(pull.get("user"))
    if author is None:
        raise ValueError("pull request has no author")
    draft = bool(pull.get("draft"))
    title = pull.get("title") or ""
    body = (pull.get("body") or "")[: closing_choice.MAX_CHARS]
    paths = tuple(f["filename"] for f in files if isinstance(f, dict) and isinstance(f.get("filename"), str))
    changed = pull.get("changed_files")
    truncated = len(files) >= MAX_FILES or (isinstance(changed, int) and len(files) < changed)

    pulls = {int(p["number"]): p for p in listings.open_pulls + listings.merged_pulls}
    named, dropped = referenced(title, body)
    refs = [_resolve(n, kind, listings, pulls) for n, kind in named]
    claim_reads = 0
    for index, ref in enumerate(refs):
        if claim_reads >= MAX_CLAIM_READS:
            break
        if not _open_accepted(ref) or author in ref.assignees:
            continue
        claim_reads += 1
        issue_comments = paginate(run, f"{_API}/issues/{ref.number}/comments?per_page=100")
        refs[index] = replace(ref, author_commented_at=_earliest_by(issue_comments, author))
    references = tuple(refs)

    # The record route sits behind the roster in the gate, and bots and drafts never reach
    # it, so their merged history is not read.
    if author in roster or author in KNOWN_BOTS or draft:
        author_record = False
    else:
        author_record = bool(listings.approved_for(run, author, roster))

    created_at, updated_at = _when(pull.get("created_at")), _when(pull.get("updated_at"))
    if created_at is None or updated_at is None:
        raise ValueError("pull request has no timestamps")
    return Facts(
        number=number,
        state=str(pull["state"]),
        draft=draft,
        author=author,
        author_is_bot=pull["user"].get("type") == "Bot",
        title=title,
        body=body,
        base=str(pull["base"]["ref"]),
        head_sha=str(pull["head"]["sha"]),
        created_at=created_at,
        updated_at=updated_at,
        labels=_label_names(pull.get("labels")),
        paths=paths,
        paths_truncated=truncated,
        references=references,
        references_dropped=dropped,
        reviews=_reviews(raw_reviews),
        last_unlabel=_last_unlabel(timeline),
        last_author_comment_at=_latest_by(comments, author),
        bot_comment=_bot_comment(comments),
        auto_merge=pull.get("auto_merge") is not None,
        author_record=author_record,
        held_use=_held_use(number, author, references, listings),
        roster=roster,
        mode=mode,
        sweep=sweep,
        event_action=event_action,
    )
