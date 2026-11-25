# Extending CycloneDX

The canonical ACS Agent Bill of Materials (AgBOM) records which components an agent uses, how they relate, and their registration provenance when available. Mapping that inventory to CycloneDX lets existing BOM tools consume it and helps identify where the formats differ.

CycloneDX 2.0 is the target for this work. The AgBOM Viewer follows a pinned revision of `2.0-dev` and offers samples, use cases, field-level mapping details, and local BOM inspection and comparison.

## Canonical ACS component types

- Model
- MCP server
- A2A peer
- Tool
- Knowledge source
- Memory store
- Agent capability
- Skill

## What comes next

ACS is mapping AgBOM fields and terms to CycloneDX 2.0 and recording gaps. See [D-044](../../decisions/index.md#d-044-manage-agbom-as-an-acs-sub-stream-and-map-it-to-cyclonedx-first). Once CycloneDX publishes the final 2.0 release, ACS will check the mapping and viewer against it and align both with the release.

- Explore samples and use cases, review field-level mappings, and compare bundled captures in the [AgBOM Viewer](agbom-viewer/index.html).
- Learn how to inspect and compare your BOMs from an ACS checkout in the [Local BOMs guide](agbom_viewer_local.md).
