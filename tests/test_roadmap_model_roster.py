"""Tests for the roadmap trust roster.

CODEOWNERS is prose plus patterns, so these cases are the point: a comment that names
@import must not trust the real account called `import`, and a link whose text and URL
disagree must fail rather than trust whichever one a reviewer did not read.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from roadmap_model import (  # noqa: E402
    Roster,
    RosterError,
    parse_codeowners_logins,
    parse_governance,
    trusted_logins,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

GOVERNANCE = """# Governance

## Project lead

| Role | Name |
| --- | --- |
| Project Lead | Rock Lambros ([@rocklambros](https://github.com/rocklambros)) |

## Workstream leads

Intro prose.

| Workstream | Leads |
| --- | --- |
| Coding Agents | Almog Langleben ([@almogbhl](https://github.com/almogbhl)), Stefano Amorelli ([@stefanoamorelli](https://github.com/stefanoamorelli)) |
| Documentation | Open |
| Reference Implementation | Evgeniy Kokuykin ([@artmaro](https://github.com/artmaro)) |

## Origins

Michael Bargury ([@mbrg](https://github.com/mbrg)) and Ory Segal ([@oorryy](https://github.com/oorryy)) created ACS.

## Related
"""


def test_codeowners_comments_never_grant_trust():
    text = "# mentions @import and @font-face\n* @rocklambros @Fewdisc # trailing @nobody\n"
    assert parse_codeowners_logins(text) == {"rocklambros", "fewdisc"}


def test_codeowners_team_entry_fails_loudly():
    with pytest.raises(RosterError, match="@org/team"):
        parse_codeowners_logins("/docs/ @rocklambros @org/team\n")


def test_codeowners_email_entry_fails_loudly():
    with pytest.raises(RosterError):
        parse_codeowners_logins("/docs/ someone@example.com\n")


def test_governance_parses_leads_and_open_seats():
    roster = parse_governance(GOVERNANCE)
    assert roster.project_leads == (("Rock Lambros", "rocklambros"),)
    assert roster.workstreams["Coding Agents"] == (
        ("Almog Langleben", "almogbhl"),
        ("Stefano Amorelli", "stefanoamorelli"),
    )
    assert roster.workstreams["Documentation"] == ()
    assert roster.workstreams["Reference Implementation"] == (("Evgeniy Kokuykin", "artmaro"),)
    assert roster.origins == (("Michael Bargury", "mbrg"), ("Ory Segal", "oorryy"))


def test_governance_link_text_must_match_url():
    bad = GOVERNANCE.replace(
        "[@artmaro](https://github.com/artmaro)", "[@artmaro](https://github.com/someone-else)"
    )
    with pytest.raises(RosterError, match="artmaro"):
        parse_governance(bad)


import pytest as _pytest  # noqa: E402


@_pytest.mark.parametrize(
    "cell",
    [
        "Jane Doe",
        "TBD (seeking a lead)",
        "Jane ([@jane](https://github.com/jane/))",
        "Jane ([@jane](https://github.com/jane)), Bob ([bob](https://github.com/bob))",
    ],
)
def test_governance_malformed_cell_raises(cell):
    bad = GOVERNANCE.replace("| Documentation | Open |", f"| Documentation | {cell} |")
    with _pytest.raises(RosterError):
        parse_governance(bad)


def test_governance_missing_section_fails():
    with pytest.raises(RosterError, match="Workstream leads"):
        parse_governance(GOVERNANCE.replace("## Workstream leads", "## Something else"))


def test_trusted_logins_from_the_real_repository():
    trusted = trusted_logins(REPO_ROOT)
    assert "rocklambros" in trusted
    assert "artmaro" in trusted
    # Origins are excluded by default (spec decision 4).
    assert "mbrg" not in trusted
    assert "import" not in trusted and "font-face" not in trusted
    assert all(login == login.casefold() for login in trusted)


def test_real_governance_parses():
    roster = parse_governance((REPO_ROOT / "GOVERNANCE.md").read_text(encoding="utf-8"))
    assert isinstance(roster, Roster)
    assert roster.project_leads
    assert "Spec" in roster.workstreams
