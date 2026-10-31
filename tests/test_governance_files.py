"""Pins the rollout's package A text: who owns the roster files and the trust code, who
project.owasp.yaml names, and the front-door sentences that defer to GOVERNANCE.md."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ROSTER_OWNERS = ["@rocklambros", "@afogel", "@bar-capsule", "@GangGreenTemperTatum", "@mamicidal", "@sclintonowasp"]
LEAD_PATHS = (
    "/GOVERNANCE.md", "/project.owasp.yaml", "/.github/",
    "/tools/roadmap_model.py", "/tools/fetch_roadmap.py", "/tools/closing_choice.py",
)


def codeowner_rules() -> list[tuple[str, list[str]]]:
    rules = []
    for raw in (REPO_ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            pattern, *owners = line.split()
            rules.append((pattern, owners))
    return rules


def test_roster_files_and_trust_code_need_a_project_lead():
    rules = dict(codeowner_rules())
    for path in LEAD_PATHS:
        assert rules[path] == ROSTER_OWNERS, path


def test_trust_code_lines_come_after_tools_so_they_win():
    order = [pattern for pattern, _owners in codeowner_rules()]
    for path in ("/tools/roadmap_model.py", "/tools/fetch_roadmap.py", "/tools/closing_choice.py"):
        assert order.index("/tools/") < order.index(path)


def test_codeowners_header_names_the_leads_and_the_lapsed_invitations():
    text = (REPO_ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    assert "The project leads are @rocklambros,\n# @afogel, and @bar-capsule." in text
    assert "@artmaro holds write access." in text
    assert "lapsed and are not being re-sent" in text


def test_project_owasp_yaml_names_the_leads_and_the_creators():
    data = yaml.safe_load((REPO_ROOT / "project.owasp.yaml").read_text(encoding="utf-8"))
    assert [leader["github"] for leader in data["leaders"]] == ["rocklambros", "afogel", "bar-capsule", "mbrg", "oorryy"]


def test_front_door_defers_to_triage_authority():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "[Triage authority](./GOVERNANCE.md#triage-authority)" in readme
    assert "Only a\nmaintainer can move" not in readme
    landing = (REPO_ROOT / "landing" / "index.html").read_text(encoding="utf-8")
    assert "Only an accepted issue enters the backlog." in landing
    assert "a maintainer marks" not in landing


def test_governance_speaks_of_the_project_leads():
    text = (REPO_ROOT / "GOVERNANCE.md").read_text(encoding="utf-8")
    assert "## Project leads\n" in text and "## Project lead\n" not in text
    assert not re.search(r"\b[Tt]he project lead\b(?!s)", text)
    assert "only when a project lead made it" in text
    assert "health issue reports every bypassed merge and every direct push" in text
    assert text.index("## Triage authority") < text.index("## Triage volunteers") < text.index("## Origins")
