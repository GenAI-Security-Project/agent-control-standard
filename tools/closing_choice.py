#!/usr/bin/env python3
"""Make every pull request say, for each issue it names, whether it closes or contributes.

Version 1.0. Owner: ACS project leads. Spec: design/2026-10-04-roadmap-rollout-design.md,
package C, and the parser package D reuses.

This is early feedback for contributors, not the control that stops a false claim of
delivery. The roadmap build reruns `declared_closes` on the landed commit message, so a
pull request that slips past this check still cannot count as delivered.

The workflow runs this under `python3 -I -S` from a checkout of `main`, never the pull
request's head. Title and body arrive through the environment as untrusted text. Nothing
from them is echoed: every message prints fixed text and issue numbers only. Every pattern
here is linear, with bounded repeats and no nested quantifiers, so a hostile body cannot
stall the job.
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

REPO = "GenAI-Security-Project/agent-control-standard"
MAX_CHARS = 65_536
CLOSING = frozenset({"close", "closes", "closed", "fix", "fixes", "fixed", "resolve", "resolves", "resolved"})
CONTRIBUTING = frozenset({"part of", "refs", "contributes to"})
SECTION = "## Which issue does this implement"
SPELLINGS = (
    "Close an issue with Closes, Fixes, or Resolves. "
    "Contribute to it without closing it with Part of, Refs, or Contributes to."
)
EDITORIAL = re.compile(r"^[ \t]*-[ \t]*\[[xX]\][ \t]*This is an editorial correction", re.MULTILINE)
DEPENDABOT = "dependabot[bot]"

_LINK = re.compile(r"\[([^\[\]\n]{0,500})\]\([^()\s]{0,2048}\)")
_REF = re.compile(
    r"(?<![A-Za-z0-9_/#.-])"
    r"(?:https://github\.com/(?P<url_owner>[A-Za-z0-9-]{1,39})/(?P<url_repo>[A-Za-z0-9.-]{1,100})"
    r"/issues/(?P<url_number>[0-9]{1,9})"
    r"|(?:(?P<owner>[A-Za-z0-9-]{1,39})/(?P<repo>[A-Za-z0-9.-]{1,100}))?#(?P<number>[0-9]{1,9}))"
    r"(?![0-9A-Za-z])"
)
_KEYWORD = re.compile(
    r"(?<![A-Za-z0-9])(close[sd]?|fix(?:e[sd])?|resolve[sd]?|part[ \t]{1,8}of|refs|contributes[ \t]{1,8}to)"
    r"(?![A-Za-z0-9]):?",
    re.IGNORECASE,
)
_SPACES = re.compile(r"[ \t]{1,8}")
_LIST_GAP = re.compile(r"[ \t]{0,8},[ \t]{0,8}(?:and[ \t]{1,8})?")


@dataclass(frozen=True)
class Reference:
    """One reference to an issue in this repository, and the spelling that governs it.

    `kind` is "close", "contribute", or "none". `start` is the offset in the normalized
    text, which places the reference inside or outside the issue section.
    """

    number: int
    kind: str
    start: int


def normalize(text: str | None) -> str:
    """Truncate, unify line endings, unwrap links, and drop emphasis markers.

    A markdown link renders as its text, so `[Closes #5](url)` must read as `Closes #5`.
    Emphasis removal turns `**Closes** #5` into `Closes #5`, which is how it renders.
    """
    text = (text or "")[:MAX_CHARS]
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _LINK.sub(lambda match: match.group(1), text)
    return text.replace("*", "").replace("_", "")


def _ours(match: re.Match[str]) -> tuple[bool, int]:
    owner = match.group("url_owner") or match.group("owner")
    repo = match.group("url_repo") or match.group("repo")
    number = int(match.group("url_number") or match.group("number"))
    if owner is None:
        return True, number
    return f"{owner}/{repo}".casefold() == REPO.casefold(), number


def _keyword_kind(word: str) -> str:
    word = _SPACES.sub(" ", word.casefold())
    return "close" if word in CLOSING else "contribute"


def parse_references(text: str) -> list[Reference]:
    """Every reference to this repository's issues in normalized text, with its spelling.

    A closing keyword governs the one reference right after it. A contributing spelling
    governs the reference after it and any further references joined by commas. A
    reference with neither is kind "none". References to other repositories still use
    up a keyword, so `Closes other/repo#5, #6` leaves #6 without a spelling.
    """
    refs = list(_REF.finditer(text))
    spans = [(match.start(), match.end()) for match in refs]
    keywords = []
    index = 0
    for match in _KEYWORD.finditer(text):
        # A keyword inside a reference, as in fixes/repo#5, is part of the reference.
        while index < len(spans) and spans[index][1] <= match.start():
            index += 1
        if index < len(spans) and spans[index][0] <= match.start() < spans[index][1]:
            continue
        keywords.append(match)
    events = sorted(
        [(match.start(), 0, match) for match in keywords] + [(match.start(), 1, match) for match in refs],
        key=lambda event: (event[0], event[1]),
    )
    found: list[Reference] = []
    pending: str | None = None
    pending_end = 0
    listing = False
    list_end = 0
    for _start, is_ref, match in events:
        if not is_ref:
            pending, pending_end = _keyword_kind(match.group(1)), match.end()
            continue
        kind = "none"
        if pending is not None:
            # Same line, nothing but spaces between: GitHub's own reading of a keyword.
            if text[pending_end:match.start()].strip(" \t") == "":
                kind = pending
        elif listing and _LIST_GAP.fullmatch(text[list_end:match.start()]):
            kind = "contribute"
        listing = kind == "contribute"
        pending = None
        list_end = match.end()
        ours, number = _ours(match)
        if ours:
            found.append(Reference(number=number, kind=kind, start=match.start()))
    return found


def declared_closes(message: str | None, number: int) -> tuple[bool, bool]:
    """Whether a commit message closes issue `number`, and whether it contributes to it.

    Package D calls this on every landed message and keeps only the two booleans. The
    whole message is read, because a squash message from before package C carries the
    keyword in prose, as #174's "Closes #95." does.
    """
    refs = parse_references(normalize(message))
    closes = any(ref.number == number and ref.kind == "close" for ref in refs)
    contributes = any(ref.number == number and ref.kind == "contribute" for ref in refs)
    return closes, contributes



def _section_bounds(text: str) -> tuple[int, int] | None:
    offset = 0
    start = None
    for line in text.split("\n"):
        if start is None and line.rstrip() == SECTION:
            start = offset + len(line) + 1
        elif start is not None and line.startswith("## "):
            return start, offset
        offset += len(line) + 1
    return (start, len(text)) if start is not None else None


@dataclass(frozen=True)
class Verdict:
    passed: bool
    notices: tuple[str, ...]
    errors: tuple[str, ...]


def violations(title: str | None, body: str | None) -> list[str]:
    """The rule's failures, as fixed text plus issue numbers. Empty means the rule holds."""
    text = normalize(body)
    refs = parse_references(text)
    bounds = _section_bounds(text)
    found: list[str] = []
    if bounds is None:
        found.append(f"The description has no '{SECTION}' section.")
    inside = [ref for ref in refs if bounds and bounds[0] <= ref.start < bounds[1]]
    outside = [ref for ref in refs if not (bounds and bounds[0] <= ref.start < bounds[1])]
    for ref in inside:
        if ref.kind == "none":
            found.append(f"The issue section names #{ref.number} without a spelling.")
    closed = {ref.number for ref in refs if ref.kind == "close"}
    contributed = {ref.number for ref in refs if ref.kind == "contribute"}
    for number in sorted(closed & contributed):
        found.append(f"#{number} is both closed and contributed to.")
    for number in sorted({ref.number for ref in outside if ref.kind == "close"}):
        found.append(f"A closing keyword before #{number} sits outside the issue section.")
    for number in sorted({ref.number for ref in parse_references(normalize(title)) if ref.kind == "close"}):
        found.append(f"The title closes #{number}. Closing keywords belong in the issue section.")
    return found


def _closes_anything(title: str | None, body: str | None) -> bool:
    return any(
        ref.kind == "close"
        for text in (title, body)
        for ref in parse_references(normalize(text))
    )


def _since(raw: str | None) -> date | None:
    try:
        return date.fromisoformat((raw or "").strip())
    except ValueError:
        return None


def _created(raw: str | None) -> date | None:
    try:
        return datetime.fromisoformat((raw or "").strip().replace("Z", "+00:00")).date()
    except ValueError:
        return None


def evaluate(
    title: str | None,
    body: str | None,
    *,
    author: str,
    head_ref: str,
    head_repo: str,
    created_at: str | None,
    since: str | None,
    trusted: frozenset[str],
) -> Verdict:
    """Apply the exemptions, then the rule, then the CLOSING_CHOICE_SINCE date gate."""
    if head_repo.casefold() == REPO.casefold() and head_ref == "main" and author.casefold() in trusted:
        return Verdict(True, ("This is the sync pull request from main, so the check does not apply.",), ())
    closes = _closes_anything(title, body)
    if not closes and EDITORIAL.search(normalize(body)):
        return Verdict(True, ("Declared editorial and closes nothing, so the check does not apply.",), ())
    if not closes and author == DEPENDABOT:
        return Verdict(True, ("A Dependabot update that closes nothing, so the check does not apply.",), ())
    found = violations(title, body)
    if not found:
        return Verdict(True, (), ())
    gate = _since(since)
    created = _created(created_at)
    if gate is None or created is None or created < gate:
        # The kill switch. Unset, or a pull request opened before the date, passes and
        # says what it would have failed, so contributors see the rule before it binds.
        reason = "CLOSING_CHOICE_SINCE is unset" if gate is None else "this pull request predates CLOSING_CHOICE_SINCE"
        return Verdict(True, tuple(f"Would fail once enforced ({reason}): {line}" for line in found) + (SPELLINGS,), ())
    return Verdict(False, (), tuple(found) + (SPELLINGS,))


def _trusted(repo_root: Path) -> frozenset[str]:
    """The roster from main's checkout. A roster that does not parse trusts nobody."""
    sys.path.insert(0, str(repo_root / "tools"))
    try:
        import roadmap_model

        return roadmap_model.trusted_logins(repo_root)
    except Exception as exc:  # noqa: BLE001 - only the sync exemption depends on this
        print(f"::warning::The roster did not parse ({type(exc).__name__}), so no pull request is exempt as the sync.")
        return frozenset()


def main() -> int:
    env = os.environ
    verdict = evaluate(
        env.get("PR_TITLE"),
        env.get("PR_BODY"),
        author=env.get("PR_AUTHOR", ""),
        head_ref=env.get("PR_HEAD_REF", ""),
        head_repo=env.get("PR_HEAD_REPO", ""),
        created_at=env.get("PR_CREATED_AT"),
        since=env.get("CLOSING_CHOICE_SINCE"),
        trusted=_trusted(Path(__file__).resolve().parents[1]),
    )
    for line in verdict.notices:
        print(f"::notice::{line}")
    for line in verdict.errors:
        print(f"::error::{line}")
    if verdict.passed:
        print("closing choice: pass")
    return 0 if verdict.passed else 1


if __name__ == "__main__":
    sys.exit(main())
