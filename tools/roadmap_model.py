#!/usr/bin/env python3
"""Shared rules for the ACS roadmap: who is trusted, and what an issue or a milestone means.

Version 1.0. Owner: ACS project lead. Spec: design/2026-10-04-roadmap-page-design.md.

Three callers run this module: the deploy build, the sync workflow under `python3 -I -S`,
and the test suite. It is therefore standard library only and never touches the network.
The current date is always a parameter, never read from the clock, so a quarter boundary
cannot change a test result or a pull request build.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

REPO = "GenAI-Security-Project/agent-control-standard"
# Changes whenever any rule in this module changes, so a health report or a roadmap.json
# names the rules that produced it.
RULES_VERSION = "2026-10-04.1"
SCHEMA_VERSION = 1

# Spec decision 4. The creators named under Origins hold read access today, so trusting
# them is a governance call for the project lead rather than a default of this module.
TRUST_ORIGINS = False

Person = tuple[str, str]


class RosterError(ValueError):
    """A roster file does not parse into plain, unambiguous logins."""


_OWNER_TOKEN = re.compile(r"^@[A-Za-z0-9-]+$")
_LINK = re.compile(r"\[@([^\]]+)\]\(https://github\.com/([^)/\s]+)\)")
_PERSON = re.compile(r"([^,()|]+?)\s*\(\[@([^\]]+)\]\(https://github\.com/([^)/\s]+)\)\)")
_SPLIT_CELLS = re.compile(r"(?<!\\)\|")


def parse_codeowners_logins(text: str) -> set[str]:
    """Return every owner login in CODEOWNERS rule lines, casefolded.

    Comments are stripped per line before any token is read. A whole-file match would pick
    up `@import` and `@font-face` from a comment, and `font-face` is a real outside account.
    Teams and email addresses raise, so the pull request that adds one fails its tests
    rather than silently distrusting everyone the team contains.
    """
    logins: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        for token in line.split()[1:]:
            if not _OWNER_TOKEN.match(token):
                raise RosterError(
                    f"CODEOWNERS owner {token!r} is not a plain @login. The roadmap trusts "
                    "individual logins only, so teams and email addresses are refused."
                )
            logins.add(token[1:].casefold())
    return logins


def _section(text: str, heading: str) -> list[str]:
    lines = text.splitlines()
    pattern = re.compile(rf"^##\s+{re.escape(heading)}\s*$", re.IGNORECASE)
    start = next((i for i, line in enumerate(lines) if pattern.match(line)), None)
    if start is None:
        raise RosterError(f"GOVERNANCE.md: no '## {heading}' section")
    body: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        body.append(line)
    return body


def _table_rows(lines: list[str], heading: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in _SPLIT_CELLS.split(stripped.strip("|"))]
        if set(cells[0]) <= set("-: "):
            continue
        rows.append(cells)
    if len(rows) < 2:
        raise RosterError(f"GOVERNANCE.md: the '{heading}' table is empty")
    return rows[1:]  # drop the header row


def _people(cell: str) -> tuple[Person, ...]:
    links = _LINK.findall(cell)
    people = _PERSON.findall(cell)
    for text_login, url_login in links:
        if text_login.casefold() != url_login.casefold():
            raise RosterError(
                f"GOVERNANCE.md: link text @{text_login} points at github.com/{url_login}. "
                "A reviewer reads the text, so the two must name the same account."
            )
    if len(people) != len(links):
        raise RosterError(f"GOVERNANCE.md: cannot read every person in {cell!r}")
    # A cell is either exactly "Open" or a list of linked people. Anything else, including
    # a trailing slash on a profile URL or a name with no link, would otherwise parse as an
    # empty seat and silently distrust a lead.
    if cell.strip() != "Open" and (not people or cell.count("github.com/") != len(people)):
        raise RosterError(f"GOVERNANCE.md: cannot read every person in {cell!r}")
    result: list[Person] = []
    for name, _text_login, url_login in people:
        cleaned = re.sub(r"^(and|&)\s+", "", name.strip(), flags=re.IGNORECASE)
        result.append((cleaned, url_login))
    return tuple(result)


@dataclass(frozen=True)
class Roster:
    project_leads: tuple[Person, ...]
    workstreams: dict[str, tuple[Person, ...]] = field(default_factory=dict)
    origins: tuple[Person, ...] = ()


def parse_governance(text: str) -> Roster:
    """Read the project lead table, the workstream leads table, and the Origins prose."""
    leads: list[Person] = []
    for cells in _table_rows(_section(text, "Project lead"), "Project lead"):
        if len(cells) != 2:
            raise RosterError(f"GOVERNANCE.md: project lead row has {len(cells)} cells")
        leads.extend(_people(cells[1]))
    workstreams: dict[str, tuple[Person, ...]] = {}
    for cells in _table_rows(_section(text, "Workstream leads"), "Workstream leads"):
        if len(cells) != 2:
            raise RosterError(f"GOVERNANCE.md: workstream row has {len(cells)} cells")
        workstreams[cells[0]] = _people(cells[1])
    origins = tuple(
        (re.sub(r"^(and|&)\s+", "", name.strip(), flags=re.IGNORECASE), url_login)
        for name, _text_login, url_login in _PERSON.findall(" ".join(_section(text, "Origins")))
    )
    if not leads:
        raise RosterError("GOVERNANCE.md: no project lead")
    return Roster(project_leads=tuple(leads), workstreams=workstreams, origins=origins)


def trusted_logins(repo_root: Path) -> frozenset[str]:
    """Logins whose closes count as delivered. Spec section "Trusted logins"."""
    codeowners = (repo_root / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    roster = parse_governance((repo_root / "GOVERNANCE.md").read_text(encoding="utf-8"))
    logins = set(parse_codeowners_logins(codeowners))
    people = list(roster.project_leads)
    for leads in roster.workstreams.values():
        people.extend(leads)
    if TRUST_ORIGINS:
        people.extend(roster.origins)
    logins.update(login.casefold() for _name, login in people)
    return frozenset(logins)
