"""Pins the rollout's package A text: who owns the roster files and the trust code, who
project.owasp.yaml names, and the front-door sentences that defer to GOVERNANCE.md."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
# D-053: the project leads own everything, four workstream leads join them on every
# path except the specification, and the OWASP organization owners sit on every line.
PROJECT_LEADS = ["@rocklambros", "@afogel", "@bar-capsule"]
ORG_OWNERS = ["@GangGreenTemperTatum", "@mamicidal", "@sclintonowasp"]
SPEC_OWNERS = PROJECT_LEADS + ORG_OWNERS
LEAD_OWNERS = PROJECT_LEADS + ["@fewdisc", "@artmaro", "@Lrd0036", "@e2hln"] + ORG_OWNERS
LEAD_PATHS = (
    "/GOVERNANCE.md", "/project.owasp.yaml", "/.github/",
    "/tools/roadmap_model.py", "/tools/fetch_roadmap.py", "/tools/closing_choice.py",
)
SPEC_PATHS = ("/specification/", "/docs/spec/")


def codeowner_rules() -> list[tuple[str, list[str]]]:
    rules = []
    for raw in (REPO_ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            pattern, *owners = line.split()
            rules.append((pattern, owners))
    return rules


def test_roster_files_and_trust_code_take_the_lead_owner_set():
    rules = dict(codeowner_rules())
    for path in LEAD_PATHS:
        assert rules[path] == LEAD_OWNERS, path


def test_only_the_project_leads_own_the_specification():
    rules = codeowner_rules()
    for path in SPEC_PATHS:
        assert dict(rules)[path] == SPEC_OWNERS, path
    # No later line may hand a specification path to anyone else, except the AgBOM lead's
    # D-044 paths and the AgBOM Viewer, which is tooling rather than specification text.
    agbom = SPEC_OWNERS + ["@e2hln"]
    later = {p: o for p, o in rules if p.startswith(SPEC_PATHS) and p not in SPEC_PATHS}
    assert later == {
        "/specification/v0.1.0/agbom/": agbom,
        "/specification/v0.1.0/inspect/": agbom,
        "/docs/spec/inspect/": agbom,
        "/docs/spec/inspect/agbom-viewer/": LEAD_OWNERS,
    }


def test_every_project_lead_owns_every_line():
    for pattern, owners in codeowner_rules():
        for lead in PROJECT_LEADS:
            assert lead in owners, (pattern, lead)


def test_trust_code_lines_come_after_tools_so_they_win():
    order = [pattern for pattern, _owners in codeowner_rules()]
    for path in ("/tools/roadmap_model.py", "/tools/fetch_roadmap.py", "/tools/closing_choice.py"):
        assert order.index("/tools/") < order.index(path)


def test_codeowners_header_names_the_leads_and_excludes_owners_without_write():
    text = (REPO_ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    assert "The project leads are @rocklambros,\n# @afogel, and @bar-capsule." in text
    assert "@artmaro holds write access." in text
    assert "an entry without write access does nothing" in text


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
