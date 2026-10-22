#!/usr/bin/env python3
"""Shared rules for the ACS roadmap: who is trusted, and what an issue or a milestone means.

Version 1.1. Owner: ACS project leads. Spec: design/2026-10-04-roadmap-page-design.md and
design/2026-10-04-roadmap-rollout-design.md.

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
RULES_VERSION = "2026-10-04.2"
SCHEMA_VERSION = 1

# Spec decision 4. The creators named under Origins hold read access today, so trusting
# them is a governance call for the project lead rather than a default of this module.
TRUST_ORIGINS = False

Person = tuple[str, str]


class RosterError(ValueError):
    """A roster file does not parse into plain, unambiguous logins."""


_OWNER_TOKEN = re.compile(r"^@[A-Za-z0-9-]+$")
_LINK = re.compile(r"\[@([^\]]+)\]\(https://github\.com/([^)/\s]+)\)")
# A name may carry one parenthesized part, such as a nickname in "Kyriakos Lambros (Rock)".
# The group refuses a parenthesis that opens the handle link, so the name ends there.
_PERSON = re.compile(r"((?:[^,()|]|\((?!\[@)[^()|]*\))+?)\s*\(\[@([^\]]+)\]\(https://github\.com/([^)/\s]+)\)\)")
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


def _first_section(text: str, *headings: str) -> list[str]:
    """The first heading that exists wins, so a rename can land before every reader moves."""
    for heading in headings:
        try:
            return _section(text, heading)
        except RosterError:
            continue
    raise RosterError(f"GOVERNANCE.md: no '## {headings[0]}' section")


def _table_rows(lines: list[str], heading: str, allow_empty: bool = False) -> list[list[str]]:
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
        if allow_empty:
            return []
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
    triage_volunteers: tuple[Person, ...] = ()


# GitHub hides an HTML comment when it renders the file, so a reviewer never sees a row
# inside one. An unterminated comment hides everything after it, so it is stripped to the
# end of the text rather than left in place.
_HTML_COMMENT = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)
TRIAGE_VOLUNTEERS = "Triage volunteers"


def _volunteers(text: str) -> tuple[Person, ...]:
    """The Triage volunteers table. Absent or empty means nobody, never a parse failure.

    Each Volunteer cell holds exactly one linked handle under the lead tables' checks, so
    an "Open" placeholder or a cell naming two people raises rather than trusting either.
    """
    try:
        lines = _section(text, TRIAGE_VOLUNTEERS)
    except RosterError:
        return ()
    people: list[Person] = []
    for cells in _table_rows(lines, TRIAGE_VOLUNTEERS, allow_empty=True):
        if len(cells) != 2:
            raise RosterError(f"GOVERNANCE.md: triage volunteer row has {len(cells)} cells")
        found = _people(cells[0])
        if len(found) != 1:
            raise RosterError(f"GOVERNANCE.md: a triage volunteer cell must name one person: {cells[0]!r}")
        people.extend(found)
    return tuple(people)


def parse_governance(text: str) -> Roster:
    """Read the project leads, workstream leads, and triage volunteer tables, and Origins.

    "Project leads" is the heading since the October 2026 leadership change. "Project lead"
    is still read, so an older checkout of GOVERNANCE.md keeps parsing.
    """
    text = _HTML_COMMENT.sub("", text)
    leads: list[Person] = []
    for cells in _table_rows(_first_section(text, "Project leads", "Project lead"), "Project leads"):
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
    return Roster(
        project_leads=tuple(leads), workstreams=workstreams, origins=origins,
        triage_volunteers=_volunteers(text),
    )


def project_lead_logins(roster: Roster) -> frozenset[str]:
    """Casefolded project lead logins. Spec decision 12: only these attest a hand close."""
    return frozenset(login.casefold() for _name, login in roster.project_leads)


def trusted_logins(repo_root: Path) -> frozenset[str]:
    """Logins whose closes count as delivered. Spec decision 4, narrowed by decision 12."""
    codeowners = (repo_root / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    roster = parse_governance((repo_root / "GOVERNANCE.md").read_text(encoding="utf-8"))
    logins = set(parse_codeowners_logins(codeowners))
    people = list(roster.project_leads) + list(roster.triage_volunteers)
    for leads in roster.workstreams.values():
        people.extend(leads)
    if TRUST_ORIGINS:
        people.extend(roster.origins)
    logins.update(login.casefold() for _name, login in people)
    return frozenset(logins)

# --- Labels and decision constants --------------------------------------------------
# Spec decision defaults that code reads sit here: decision 3 (MILESTONE_ACCEPTS, ADD_IN_FOCUS_ON_ACCEPT), decision 4 (TRUST_ORIGINS, above), and decision 5 (CO_OWNERS_SOURCE). Decisions 6 to 8 are rollout data, not code.

from datetime import date, timedelta  # noqa: E402

ACCEPTED = "status:accepted"
NEEDS_TRIAGE = "status:needs-triage"
DEFERRED = "scope:deferred"
IN_FOCUS = "scope:in-focus"
SCOPE_PREFIX = "scope:"
# Spec decision 3. Setting a milestone accepts the issue, and adds scope:in-focus when the
# issue carries no scope label. Turning MILESTONE_ACCEPTS off makes the event job a no-op.
MILESTONE_ACCEPTS = True
ADD_IN_FOCUS_ON_ACCEPT = True
# Spec decision 5. "project_lead" names the GOVERNANCE.md project lead table. "origins"
# adds the creators named under Origins.
CO_OWNERS_SOURCE = "project_lead"
# A milestone set on an issue carrying one of these is a standing triage decision the
# event job must not overrule.
DECLINE_LABELS = frozenset(
    {DEFERRED, "scope:out", "status:blocked", "status:needs-info", "wontfix", "invalid", "duplicate"}
)
# The value a milestone's Workstream line uses for project-level work, which maps to the
# project lead table rather than to a workstream row.
PROJECT_WORKSTREAM = "Project"
# The OWASP sheet's Deliverable Type dropdown, spelled as the sheet spells it. The roadmap
# design points here rather than repeating the list.
DELIVERABLE_TYPES = ("Application/Tool", "Cheat Sheet", "Code Sample", "Document", "OSS Project", "Other")
# The health issue is found by this marker plus its bot author, never by title.
HEALTH_MARKER = "<!-- acs-roadmap-health -->"
BOT_LOGIN = "github-actions[bot]"

CLASSES = ("done", "unverified", "planned", "deferred", "dropped", "untriaged")
KNOWN_REASONS = frozenset({"COMPLETED", "NOT_PLANNED", "DUPLICATE"})


# Rollout design, package D. Each unverified close carries exactly one of these.
REASON_CODES = (
    "not_on_main", "reverted", "no_close_declared", "contributing", "other_repository",
    "not_a_lead", "untrusted_closer", "unparsed", "unknown_closer",
)
# Where a commit stands against main, as the fetch's git check reports it.
LANDINGS = ("on_main", "not_on_main", "reverted")


@dataclass(frozen=True)
class IssueRecord:
    """One issue plus the close facts the fetch wrote. Every fact defaults to the reading
    that verifies nothing, so a record built without them can never count as done."""

    number: int
    state: str
    state_reason: str | None
    labels: frozenset[str]
    author: str | None
    closed_by: str | None
    closer_kind: str = "unknown"
    closer_in_repo: bool = False
    declares_close: bool = False
    declares_contribution: bool = False
    unparsed: bool = False
    closer_landing: str | None = None
    references_landing: str = "not_on_main"


def closer_facts(raw: dict) -> dict:
    """IssueRecord keyword arguments from the fetch's camelCase close facts."""
    return {
        "closer_kind": raw.get("closerKind") or "unknown",
        "closer_in_repo": raw.get("closerInRepo") is True,
        "declares_close": raw.get("declaresClose") is True,
        "declares_contribution": raw.get("declaresContribution") is True,
        "unparsed": raw.get("unparsed") is True,
        "closer_landing": raw.get("closerLanding"),
        "references_landing": raw.get("referencesLanding") or "not_on_main",
    }


def _landing_reason(landing: str | None) -> str | None:
    if landing == "on_main":
        return None
    return "reverted" if landing == "reverted" else "not_on_main"


def assess(issue: IssueRecord, trusted: frozenset[str], leads: frozenset[str]) -> tuple[str, str | None]:
    """Spec "The rule". The class, plus the reason code when the class is unverified.

    A close counts as done only when the data says so: a pull request in this repository
    or a commit whose message closes the issue and contributes to it nowhere, whose commit
    is on main and not reverted, or a project lead's hand close. In both cases every merged
    pull request that references the issue must also be on main.
    """
    if issue.state == "CLOSED":
        if issue.closed_by is None or issue.closed_by.casefold() not in trusted:
            return "unverified", "untrusted_closer"
        if issue.state_reason != "COMPLETED":
            return "dropped", None
        if issue.unparsed:
            return "unverified", "unparsed"
        if issue.closer_kind == "none":
            if issue.closed_by.casefold() not in leads:
                return "unverified", "not_a_lead"
        elif issue.closer_kind in ("pull_request", "commit"):
            if not issue.closer_in_repo:
                return "unverified", "other_repository"
            if issue.declares_contribution:
                return "unverified", "contributing"
            if not issue.declares_close:
                return "unverified", "no_close_declared"
            reason = _landing_reason(issue.closer_landing)
            if reason:
                return "unverified", reason
        else:
            return "unverified", "unknown_closer"
        reason = _landing_reason(issue.references_landing)
        if reason:
            return "unverified", reason
        return "done", None
    if ACCEPTED in issue.labels:
        return "planned", None
    if DEFERRED in issue.labels:
        return "deferred", None
    return "untriaged", None


def classify(issue: IssueRecord, trusted: frozenset[str], leads: frozenset[str]) -> str:
    """The class alone. See assess for the rule and its reason codes."""
    return assess(issue, trusted, leads)[0]


def unknown_reason(issue: IssueRecord) -> bool:
    return issue.state == "CLOSED" and issue.state_reason not in KNOWN_REASONS


def remaining(counts: dict[str, int]) -> int:
    """Work a milestone still owes: unverified closes and every open issue in it.

    An open issue counts whatever its labels, so one whose status:accepted was replaced by
    status:blocked, or one nobody triaged, still holds the milestone open.
    """
    return sum(counts.get(name, 0) for name in ("unverified", "planned", "deferred", "untriaged"))


def milestone_state(closed: bool, has_due: bool, counts: dict[str, int]) -> str:
    """Spec section "Milestone states", with every open issue counted as remaining.

    A milestone with remaining work never reads published or ready. One holding only
    deferred issues and nothing done still reads deferred, which OWASP reports as Planning.
    """
    done = counts.get("done", 0)
    left = remaining(counts)
    if closed:
        if done == 0:
            return "withdrawn"
        return "published" if left == 0 else "closed_with_open_work"
    if done == 0 and left == counts.get("deferred", 0):
        return "deferred" if left else "skipped"
    if not has_due:
        return "ongoing"
    if left == 0:
        return "ready"
    if done:
        return "in_progress"
    return "planning"


OWASP_STATUS: dict[str, str | None] = {
    "withdrawn": None,
    "published": "Published",
    "closed_with_open_work": "In Review",
    "skipped": None,
    "deferred": "Planning",
    "ongoing": "Ongoing",
    "ready": "In Review",
    "in_progress": "In Progress",
    "planning": "Planning",
}


# --- Dates ---------------------------------------------------------------------------

def due_date(due_on: str | None) -> date | None:
    """The calendar date a maintainer chose. GitHub stores it at 00:00Z on that date."""
    return date.fromisoformat(due_on[:10]) if due_on else None


def _quarter(day: date) -> tuple[int, int]:
    return day.year, (day.month - 1) // 3 + 1


def quarter_label(day: date) -> str:
    year, q = _quarter(day)
    return f"Q{q} {year}"


def is_quarter_end(day: date) -> bool:
    return day.month in (3, 6, 9, 12) and (day + timedelta(days=1)).month != day.month


def target_passed(due: date | None, committed: date | None, today: date) -> bool:
    if committed is not None:
        return today > committed
    if due is not None:
        return _quarter(today) > _quarter(due)
    return False


# --- Milestone descriptions ----------------------------------------------------------

_DESCRIPTION_LINE = re.compile(r"^(Committed|Workstream|Type):[ \t]*(.*?)[ \t]*$")


@dataclass(frozen=True)
class Description:
    text: str
    committed: date | None
    workstream: str | None
    deliverable_type: str | None
    errors: tuple[str, ...]


def parse_description(raw: str | None, workstream_names: set[str]) -> Description:
    """Split the three machine-read lines from the prose. Spec "Milestone description lines"."""
    values: dict[str, str] = {}
    prose: list[str] = []
    for line in (raw or "").splitlines():
        match = _DESCRIPTION_LINE.match(line.strip())
        if match:
            values[match.group(1)] = match.group(2)
        else:
            prose.append(line.rstrip())
    errors: list[str] = []
    committed = None
    if "Committed" in values:
        try:
            committed = date.fromisoformat(values["Committed"])
        except ValueError:
            errors.append("committed")
    workstream = values.get("Workstream")
    if workstream not in workstream_names | {PROJECT_WORKSTREAM}:
        errors.append("workstream")
        workstream = None
    deliverable_type = values.get("Type")
    if deliverable_type not in DELIVERABLE_TYPES:
        errors.append("type")
        deliverable_type = None
    return Description(
        text="\n".join(prose).strip(),
        committed=committed,
        workstream=workstream,
        deliverable_type=deliverable_type,
        errors=tuple(errors),
    )


# --- roadmap.json --------------------------------------------------------------------

def _record(raw: dict) -> IssueRecord:
    return IssueRecord(
        number=int(raw["number"]),
        state=raw["state"],
        state_reason=raw.get("stateReason"),
        labels=frozenset(raw.get("labels") or ()),
        author=raw.get("author"),
        closed_by=raw.get("closedBy"),
        **closer_facts(raw),
    )


def _names(people: tuple[Person, ...]) -> list[str]:
    return [name for name, _login in people]


def empty_roadmap(status: str, generated: str, commit: str, run: str, reason: str | None = None) -> dict:
    """The document written when publishing is off or the data could not be built."""
    doc = {
        "schema_version": SCHEMA_VERSION,
        "rules_version": RULES_VERSION,
        "status": status,
        "generated": generated,
        "commit": commit,
        "run": run,
        "project_leads": [],
        "co_owners": [],
        "workstreams": {},
        "milestones": [],
    }
    if reason is not None:
        doc["reason"] = reason
    return doc


def build_roadmap(
    milestones: list[dict],
    roster: Roster,
    trusted: frozenset[str],
    today: date,
    generated: str,
    commit: str,
    run: str,
) -> dict:
    """Classify every milestone. Carries numbers and maintainer-written milestone text only.

    Issue titles never enter the document, so phase 0 publishes no text an outsider wrote.
    """
    doc = empty_roadmap("ok", generated, commit, run)
    doc["project_leads"] = _names(roster.project_leads)
    co_owners = list(roster.project_leads)
    if CO_OWNERS_SOURCE == "origins":
        co_owners += list(roster.origins)
    doc["co_owners"] = _names(tuple(co_owners))
    doc["workstreams"] = {name: _names(people) for name, people in roster.workstreams.items()}
    doc["workstreams"][PROJECT_WORKSTREAM] = _names(roster.project_leads)
    names = set(roster.workstreams)
    leads = project_lead_logins(roster)
    entries: list[dict] = []
    for milestone in milestones:
        records = [_record(raw) for raw in milestone.get("issues") or ()]
        by_class: dict[str, list[int]] = {name: [] for name in CLASSES}
        reasons: dict[str, str] = {}
        for record in records:
            cls, reason = assess(record, trusted, leads)
            by_class[cls].append(record.number)
            if reason is not None:
                reasons[str(record.number)] = reason
        counts = {name: len(numbers) for name, numbers in by_class.items()}
        due = due_date(milestone.get("dueOn"))
        description = parse_description(milestone.get("description"), names)
        state = milestone_state(milestone["state"] == "CLOSED", due is not None, counts)
        entries.append(
            {
                "number": int(milestone["number"]),
                "url": milestone["url"],
                "title": milestone["title"],
                "description": description.text,
                "committed": description.committed.isoformat() if description.committed else None,
                "workstream": description.workstream,
                "type": description.deliverable_type,
                "description_errors": list(description.errors),
                "state": state,
                "owasp_status": OWASP_STATUS[state],
                "quarter": quarter_label(due) if due else None,
                "due_on": due.isoformat() if due else None,
                "target_passed": milestone["state"] == "OPEN" and state != "skipped" and target_passed(due, description.committed, today),
                "counts": counts,
                "issues": {name: sorted(numbers) for name, numbers in by_class.items()},
                "unknown_reasons": sorted(r.number for r in records if unknown_reason(r)),
                # Issue number to reason code. Codes only, so no fetched text reaches it.
                "unverified_reasons": dict(sorted(reasons.items(), key=lambda item: int(item[0]))),
            }
        )
    entries.sort(key=lambda e: (e["due_on"] is None, e["due_on"] or "", e["title"].casefold()))
    doc["milestones"] = entries
    return doc
