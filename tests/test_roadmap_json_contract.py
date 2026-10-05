"""Pins every roadmap.json key the owasp-acs-roadmap skill reads, so a rename fails here
rather than at the OWASP deadline. Pins unverified_reasons too, which carries reason codes
and issue numbers only."""
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import json  # noqa: E402

from roadmap_model import REASON_CODES, build_roadmap, parse_governance, trusted_logins  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
TOP = {"schema_version", "status", "generated", "project_leads", "co_owners", "workstreams", "milestones"}
MILESTONE = {"number", "url", "title", "description", "committed", "workstream", "type",
             "description_errors", "state", "owasp_status", "quarter", "unverified_reasons"}


def build() -> dict:
    fixture = json.loads((REPO_ROOT / "tests" / "fixtures" / "roadmap-data.json").read_text())
    roster = parse_governance((REPO_ROOT / "GOVERNANCE.md").read_text())
    doc = build_roadmap(fixture["milestones"], roster, trusted_logins(REPO_ROOT), date(2026, 11, 15), "t", "c", "r")
    # Round-trip, so the check reads what a consumer reads.
    return json.loads(json.dumps(doc))


def test_contract():
    doc = build()
    assert TOP <= set(doc)
    assert doc["schema_version"] == 1
    for milestone in doc["milestones"]:
        assert MILESTONE <= set(milestone)


def test_unverified_reasons_map_every_unverified_issue_to_one_code():
    for milestone in build()["milestones"]:
        reasons = milestone["unverified_reasons"]
        assert all(key.isdigit() for key in reasons)
        assert set(reasons.values()) <= set(REASON_CODES)
        assert sorted(int(key) for key in reasons) == milestone["issues"]["unverified"]
