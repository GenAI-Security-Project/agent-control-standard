"""Keep audience scope and Inspect method discovery explicit in the docs."""
from pathlib import Path

from render_landing import read_nav_config

REPO = Path(__file__).resolve().parents[1]


def test_introductions_name_agent_classes_and_bound_coverage():
    for path in ["README.md", "about.md"]:
        text = (REPO / "docs" / path).read_text(encoding="utf-8").lower()
        for audience in ["enterprise production agents", "coding agents", "personal agents"]:
            assert audience in text
        assert "outside" in text
        assert "connected approver" in text
        assert "ask support" in text


def test_introduction_names_inspect_reconnaissance_risk_and_access_restriction():
    text = (REPO / "docs" / "README.md").read_text(encoding="utf-8")
    assert "attacker planning reconnaissance" in text
    assert "Restrict access to Inspect outputs" in text


def test_navigation_places_inspect_methods_with_their_pillar():
    nav = read_nav_config(REPO / "mkdocs.yml").nav
    specification = next(item["Specification"] for item in nav if "Specification" in item)
    instrument = next(item["Instrument"] for item in specification if "Instrument" in item)
    assert {"Protocol and hooks contract": "spec/instrument/specification.md"} in instrument
    inspect = next(item["Inspect"] for item in specification if "Inspect" in item)
    for method, anchor in [("agbom/snapshot", "agbomsnapshot"), ("agbom/changed", "agbomchanged")]:
        page = method.split("/", 1)[1]
        assert {method: f"spec/inspect/{page}.md"} in inspect
        reference = (REPO / "docs" / "spec" / "inspect" / f"{page}.md").read_text(encoding="utf-8")
        assert f"(../instrument/hooks.md#{anchor})" in reference
        overview = (REPO / "docs" / "spec" / "inspect" / "README.md").read_text(encoding="utf-8")
        assert f"[`{method}`](../instrument/hooks.md#{anchor})" in overview


def test_shared_catalog_points_inspect_readers_back_to_their_pillar():
    catalog = (REPO / "docs" / "spec" / "instrument" / "hooks.md").read_text(encoding="utf-8")
    introduction = catalog.split("## ", 1)[0]
    assert "../inspect/README.md#wire-methods" in introduction
    assert "not Instrument control hooks" in introduction
