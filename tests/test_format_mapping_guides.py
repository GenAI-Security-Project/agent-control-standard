"""The CycloneDX and SPDX guides must say what format-mapping.json says.

`specification/v0.1.0/inspect/format-mapping.json` and the two guides under
`docs/spec/inspect/` each called themselves normative, and they disagreed. An
ACS-Inspect implementer got different output depending on which one they read:

  - CycloneDX `model` was `machine-learning-model` in the schema and `ai-model`
    in the guide, and `ai-model` is not a CycloneDX 1.6 component type;
  - `memory_store` was `data` in the schema and `service` in the guide;
  - `agent_capability` was a composition in the schema and `application` in the
    guide;
  - SPDX `memory_store` was a dataset package and `agent_capability` a bundle in
    the schema, and `Service` and `software_Package` in the guide;
  - `skill` was mapped in the schema and absent from both guides.

`service` is not a CycloneDX 1.6 component type either: services live in the
separate top-level `services` array, which the schema's description now says.

The schema is the source. It carries each type mapping as data in
`x-acs-type-map`, and its prose description restates the same mapping. These
tests hold the prose and both guides to that data, so a change to one of them
that is not made in the others fails here.
"""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "specification" / "v0.1.0"
FORMAT_MAPPING = SCHEMAS / "inspect" / "format-mapping.json"
COMPONENT_SCHEMA = SCHEMAS / "agbom" / "component.json"
CYCLONEDX_GUIDE = ROOT / "docs" / "spec" / "inspect" / "extend_cyclonedx.md"
SPDX_GUIDE = ROOT / "docs" / "spec" / "inspect" / "extend_spdx.md"

# The component types CycloneDX 1.6 defines in bom-1.6.schema.json. `service` and
# `composition` are not among them: they are the `services` and `compositions`
# arrays.
CYCLONEDX_COMPONENT_TYPES = {
    "application", "framework", "library", "container", "platform", "operating-system",
    "device", "device-driver", "firmware", "file", "machine-learning-model", "data",
    "cryptographic-asset",
}
CYCLONEDX_NON_COMPONENT_ELEMENTS = {"service", "composition"}


def mapping() -> dict:
    return json.loads(FORMAT_MAPPING.read_text(encoding="utf-8"))["properties"]


def canonical_types() -> list:
    schema = json.loads(COMPONENT_SCHEMA.read_text(encoding="utf-8"))
    return schema["properties"]["type"]["enum"]


def type_map(target: str) -> dict:
    return mapping()[target]["x-acs-type-map"]


def table_rows(markdown: str, first_header: str) -> dict:
    """Rows of the table whose header starts with `first_header`, as {first cell: second cell}.

    Cells are read without their backticks, so `model` | `ai-model` becomes {"model": "ai-model"}.
    """
    lines = markdown.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(f"| {first_header} |"))
    rows = {}
    for line in lines[start + 2:]:
        if not line.startswith("|"):
            break
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        rows[cells[0]] = cells[1]
    return rows


def clause_for(description: str, canonical: str) -> str:
    """The part of the description's type-mapping sentence that follows `canonical →`."""
    match = re.search(rf"(?:^|[:;] )(?:\w+, )*{re.escape(canonical)}(?:, \w+)* → ([^;.]*)", description)
    assert match, f"the description never maps {canonical!r}"
    return match.group(1)


@pytest.mark.parametrize("target", ["cyclonedx_1_6", "spdx_3_0"])
def test_the_type_map_covers_every_canonical_component_type_and_no_other(target):
    assert sorted(type_map(target)) == sorted(canonical_types())


def test_cyclonedx_type_map_names_only_real_cyclonedx_elements():
    for canonical, element in type_map("cyclonedx_1_6").items():
        assert element in CYCLONEDX_COMPONENT_TYPES | CYCLONEDX_NON_COMPONENT_ELEMENTS, (
            f"{canonical} maps to {element!r}, which is neither a CycloneDX 1.6 component type "
            "nor the services or compositions array"
        )


def test_the_issue_rows_hold_in_the_type_map():
    cdx, spdx = type_map("cyclonedx_1_6"), type_map("spdx_3_0")
    assert cdx["model"] == "machine-learning-model"
    assert cdx["memory_store"] == "data"
    assert cdx["agent_capability"] == "composition"
    assert spdx["memory_store"] == "dataset_DatasetPackage"
    assert spdx["agent_capability"] == "Bundle"
    assert "skill" in cdx and "skill" in spdx


# The description is prose, and prose is what an implementer reads first.

CYCLONEDX_PHRASE = {"service": "'services' array", "composition": "'compositions' array"}


def test_the_cyclonedx_description_agrees_with_the_type_map():
    description = mapping()["cyclonedx_1_6"]["description"]
    for canonical, element in type_map("cyclonedx_1_6").items():
        phrase = CYCLONEDX_PHRASE.get(element, f"'{element}'")
        assert phrase in clause_for(description, canonical), f"{canonical} should read {phrase}"


def test_the_cyclonedx_description_says_service_is_not_a_component_type():
    description = mapping()["cyclonedx_1_6"]["description"]
    assert "'service' is not a component type" in description
    assert "ai-model" not in description


def test_the_spdx_description_agrees_with_the_type_map():
    description = mapping()["spdx_3_0"]["description"]
    for canonical, spdx_class in type_map("spdx_3_0").items():
        assert re.search(rf"\b{re.escape(spdx_class)}\b", clause_for(description, canonical)), (
            f"{canonical} should read {spdx_class}"
        )


# The guides.

def test_the_cyclonedx_guide_table_matches_the_type_map():
    rows = table_rows(CYCLONEDX_GUIDE.read_text(encoding="utf-8"), "Canonical type")
    assert rows == type_map("cyclonedx_1_6")


def test_the_spdx_guide_table_matches_the_type_map():
    rows = table_rows(SPDX_GUIDE.read_text(encoding="utf-8"), "Canonical type")
    assert rows == type_map("spdx_3_0")


@pytest.mark.parametrize("guide", [CYCLONEDX_GUIDE, SPDX_GUIDE], ids=lambda p: p.name)
def test_each_guide_links_the_schema_it_restates(guide):
    text = guide.read_text(encoding="utf-8")
    assert "schema/v0.1.0/inspect/format-mapping.json" in text
    assert "test_format_mapping_guides.py" in text


def test_the_cyclonedx_guide_never_says_ai_model():
    assert "ai-model" not in CYCLONEDX_GUIDE.read_text(encoding="utf-8")


def test_the_cyclonedx_guide_example_uses_only_real_component_types_and_a_services_array():
    text = CYCLONEDX_GUIDE.read_text(encoding="utf-8")
    block = re.search(r"```json\n(.*?)\n```", text, re.S)
    assert block, "the guide has no JSON example"
    bom = json.loads(block.group(1))
    for component in bom["components"]:
        assert component["type"] in CYCLONEDX_COMPONENT_TYPES, f"{component['bom-ref']} has type {component['type']!r}"
    assert bom["services"], "the example never shows a service in the services array"
    assert all("type" not in service for service in bom["services"])


def test_the_spdx_guide_relationships_are_the_ones_the_schema_names():
    schema_verbs = set(re.findall(r"--([A-Z_]+)-->", mapping()["spdx_3_0"]["description"]))
    text = SPDX_GUIDE.read_text(encoding="utf-8")
    section = text.split("## Relationships", 1)[1].split("\n## ", 1)[0]
    guide_verbs = set(re.findall(r"`[^`]*\b([A-Z_]{4,})\b[^`]*`\s*\|\s*$", section, re.M))
    assert guide_verbs == schema_verbs
