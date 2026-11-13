# Extending SWID

SWID (ISO/IEC 19770-2) is one of the three normative AgBOM serializations in v0.1.0. The canonical AgBOM document is the source of truth; SWID tags are derived deterministically from it. The mapping rules live in [`inspect/format-mapping.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/inspect/format-mapping.json).

## Component-type mapping

Each canonical component becomes one SoftwareIdentity tag with `tagId` = component `id` and `name` = component `name`, plus a `Link` element pointing back to the canonical AgBOM document so consumers can reach the full structured graph.

| Canonical type | SWID role | Notes |
|---|---|---|
| `model` | `softwareCreator` | The model identifies itself as a software artifact whose creator is the provider. |
| `mcp_server` | `softwareCreator` | The MCP server's vendor. |
| `a2a_peer` | `softwareCreator` | When known, the peer's identity. |
| `tool` | `softwareCreator` | The tool's vendor. |
| `knowledge_source` | `softwareCreator` | The knowledge-source vendor. |
| `memory_store` | `softwareCreator` | The memory-store vendor. |
| `agent_capability` | `aggregator` | Composed capabilities aggregate their tool/MCP/A2A children. |

## Status

Working draft. SWID's strength here is its compactness for environments that already consume SWID via management tooling (NIST SCAP, asset inventories); CycloneDX and SPDX cover most agent-deployment use cases.
