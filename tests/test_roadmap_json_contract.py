"""Pins every roadmap.json key the owasp-acs-roadmap skill reads, so a rename fails here
rather than at the OWASP deadline."""
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import json  # noqa: E402

from roadmap_model import build_roadmap, parse_governance, trusted_logins  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
TOP = {"schema_version", "status", "generated", "project_leads", "co_owners", "workstreams", "milestones"}
MILESTONE = {"number", "url", "title", "description", "committed", "workstream", "type",
             "description_errors", "state", "owasp_status", "quarter"}


def test_contract():
    fixture = json.loads((REPO_ROOT / "tests" / "fixtures" / "roadmap-data.json").read_text())
    roster = parse_governance((REPO_ROOT / "GOVERNANCE.md").read_text())
    doc = build_roadmap(fixture["milestones"], roster, trusted_logins(REPO_ROOT), date(2026, 11, 15), "t", "c", "r")
    assert TOP <= set(doc)
    assert doc["schema_version"] == 1
    for milestone in doc["milestones"]:
        assert MILESTONE <= set(milestone)
