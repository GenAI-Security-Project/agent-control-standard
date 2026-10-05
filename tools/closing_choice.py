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

import re
from dataclasses import dataclass

REPO = "GenAI-Security-Project/agent-control-standard"
MAX_CHARS = 65_536
CLOSING = frozenset({"close", "closes", "closed", "fix", "fixes", "fixed", "resolve", "resolves", "resolved"})
CONTRIBUTING = frozenset({"part of", "refs", "contributes to"})

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
