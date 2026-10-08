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


# --- Rollout package A: plural heading, comments, triage volunteers -------------------

from roadmap_model import project_lead_logins  # noqa: E402

PLURAL = GOVERNANCE.replace(
    "## Project lead\n\n| Role | Name |\n| --- | --- |\n"
    "| Project Lead | Rock Lambros ([@rocklambros](https://github.com/rocklambros)) |",
    "## Project leads\n\n| Role | Name |\n| --- | --- |\n"
    "| Project Lead | Rock Lambros ([@rocklambros](https://github.com/rocklambros)) |\n"
    "| Project Lead | Ariel Fogel ([@afogel](https://github.com/afogel)) |",
)
VOLUNTEERS = """
## Triage volunteers

| Volunteer | Assigned by |
| --- | --- |
| Victor Hernandez ([@victorm-hernandez](https://github.com/victorm-hernandez)) | Rock Lambros |
"""


def with_volunteers(table: str, base: str = PLURAL) -> str:
    return base.replace("## Origins", table.strip() + "\n\n## Origins")


def test_both_lead_headings_parse():
    assert parse_governance(GOVERNANCE).project_leads == (("Rock Lambros", "rocklambros"),)
    plural = parse_governance(PLURAL)
    assert plural.project_leads == (("Rock Lambros", "rocklambros"), ("Ariel Fogel", "afogel"))
    assert project_lead_logins(plural) == frozenset({"rocklambros", "afogel"})


def test_populated_volunteer_table():
    roster = parse_governance(with_volunteers(VOLUNTEERS))
    assert roster.triage_volunteers == (("Victor Hernandez", "victorm-hernandez"),)
    assert project_lead_logins(roster) == frozenset({"rocklambros", "afogel"})


def test_empty_and_absent_volunteer_tables_trust_nobody():
    empty = "## Triage volunteers\n\n| Volunteer | Assigned by |\n| --- | --- |\n"
    assert parse_governance(with_volunteers(empty)).triage_volunteers == ()
    assert parse_governance(PLURAL).triage_volunteers == ()


def test_commented_out_rows_grant_nothing():
    hidden = VOLUNTEERS.replace(
        "| Victor Hernandez",
        "<!-- | Mallory ([@mallory](https://github.com/mallory)) | Rock Lambros | -->\n| Victor Hernandez",
    )
    roster = parse_governance(with_volunteers(hidden))
    assert [login for _name, login in roster.triage_volunteers] == ["victorm-hernandez"]
    lead_hidden = PLURAL.replace(
        "| Project Lead | Ariel Fogel",
        "<!--\n| Project Lead | Mallory ([@mallory](https://github.com/mallory)) |\n-->\n| Project Lead | Ariel Fogel",
    )
    assert "mallory" not in project_lead_logins(parse_governance(lead_hidden))


def test_unterminated_comment_hides_the_rest_of_the_file():
    # GitHub renders nothing after an unterminated comment, so neither does the parser.
    tail = with_volunteers(VOLUNTEERS).replace(
        "## Triage volunteers", "<!--\n## Triage volunteers"
    )
    with pytest.raises(RosterError):
        parse_governance(tail)


@pytest.mark.parametrize(
    "cell",
    [
        "Open",
        "Victor Hernandez",
        "Jane ([@jane](https://github.com/jane)), Bob ([@bob](https://github.com/bob))",
        "Jane ([@jane](https://github.com/someone-else))",
        "Jane ([@jane](https://github.com/jane/))",
    ],
)
def test_malformed_volunteer_cell_raises(cell):
    bad = VOLUNTEERS.replace(
        "Victor Hernandez ([@victorm-hernandez](https://github.com/victorm-hernandez))", cell
    )
    with pytest.raises(RosterError):
        parse_governance(with_volunteers(bad))


def test_volunteer_row_with_wrong_cell_count_raises():
    bad = VOLUNTEERS.replace("| Rock Lambros |", "| Rock Lambros | extra |")
    with pytest.raises(RosterError, match="cells"):
        parse_governance(with_volunteers(bad))


def test_volunteers_join_the_trusted_set(tmp_path):
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").write_text("* @rocklambros\n", encoding="utf-8")
    (tmp_path / "GOVERNANCE.md").write_text(with_volunteers(VOLUNTEERS), encoding="utf-8")
    trusted = trusted_logins(tmp_path)
    assert {"victorm-hernandez", "afogel", "rocklambros"} <= trusted


def test_real_governance_names_the_three_project_leads_and_the_volunteers():
    roster = parse_governance((REPO_ROOT / "GOVERNANCE.md").read_text(encoding="utf-8"))
    assert project_lead_logins(roster) == frozenset({"rocklambros", "afogel", "bar-capsule"})
    assert ("Victor Hernandez", "victorm-hernandez") in roster.triage_volunteers
    assert "victorm-hernandez" in trusted_logins(REPO_ROOT)
