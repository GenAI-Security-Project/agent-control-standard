#!/usr/bin/env python3
"""Decide whether a pull request has an accepted issue behind it, and say so once.

Version 1.0. Owner: ACS project leads. This module holds the data model, the parsing
helpers, and the gate: `decide` is a pure function of `Facts` and the date, with no I/O.
The collectors and the writers join it in later tasks of the same plan.

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
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta

import base_branch_guard
import closing_choice
import roadmap_model

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

    Excluded: `updated_at`, because any comment moves it and the bot's own writes would
    change the hash. Raw review timestamps, whose one effect is
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
        "labels": sorted(facts.labels),
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


def _hand_clear(facts: Facts) -> tuple[bool, bool]:
    """Whether a lead's removal of the label stands, and whether this run must record the head.

    The clear is bound to the head it was made at, so a push after it does not ride on it.
    The first run that sees the removal records the head. Until then nothing is recorded.
    """
    if facts.last_unlabel is None or not _on_roster(facts.last_unlabel[0], facts):
        return False, False
    recorded = _stored(facts).get("cleared_head")
    if recorded is None:
        return True, True
    return recorded == facts.head_sha, False


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


def _data(facts: Facts, today: date, route: str | None, reasons: tuple[str, ...], cleared_head: str | None) -> dict[str, str]:
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
            data["issues"] = ",".join(str(number) for number in issues)
        # The queue clock runs from the first queue and survives re-renders, so the health
        # issue's day count is the time waited, not the time since the last edit.
        queued_before = stored.get("reason") not in (None, "cleared") and "since" in stored
        data["since"] = stored["since"] if queued_before else today.isoformat()
        claims = _claims(facts)
        if claims:
            data["claimed"] = ",".join(f"{number}:{when.isoformat()}" for number, when in claims)
    data["head"] = facts.head_sha
    if cleared_head:
        data["cleared_head"] = cleared_head
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
    recorded, newly = stored.get("cleared_head"), False
    if route == "hand":
        newly = _hand_clear(facts)[1]
        recorded = facts.head_sha if newly else recorded
    data = _data(facts, today, route, reasons, recorded)
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
        return Decision(decision.outcome, route, reasons, "keep", None, stored, decision.disable_auto_merge, ())
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
