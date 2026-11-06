# Extending SPDX

SPDX 3.0 is one of the three normative AgBOM serializations in v0.1.0. The canonical AgBOM document is the source of truth; SPDX output is derived deterministically from it. The mapping rules live in [`inspect/format-mapping.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/inspect/format-mapping.json).

## Component-type mapping

[`format-mapping.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/inspect/format-mapping.json) states this mapping, and the tables below restate it. A test (`tests/test_format_mapping_guides.py`) fails when the two disagree, so when they do, the schema wins.

Each canonical component becomes one SPDX Element node. The graph between them is wired with relationships.

| Canonical type | SPDX class | Notes |
|---|---|---|
| `model` | `ai_AIPackage` | SPDX 3.0 AI profile node for model artifacts. |
| `mcp_server` | `Service` | Endpoint reachable via MCP. |
| `a2a_peer` | `Service` | Cross-agent endpoint; `agent_card_ref` flows into `externalRef`. |
| `tool` | `software_Package` | Agent-callable code unit. |
| `knowledge_source` | `Service` | Datastore or search endpoint. |
| `memory_store` | `dataset_DatasetPackage` | SPDX 3.0 Dataset profile node for the long-lived state store. |
| `agent_capability` | `Bundle` | Composed capability; the components it references are its `CONTAINS` targets. |
| `skill` | `software_Package` | Carries a verified checksum derived from its definition digest; the components and skills it references are its `CONTAINS` targets. |

## Relationships

| ACS edge | SPDX relationship |
|---|---|
| `agent_capability.tools[]` | `agent_capability CONTAINS tool` |
| `agent_capability.mcp_servers[]` | `agent_capability CONTAINS mcp_server` |
| `agent_capability.a2a_peers[]` | `agent_capability CONTAINS a2a_peer` |
| `skill.tools[]`, `skill.mcp_servers[]`, `skill.a2a_peers[]`, `skill.composed_skills[]` | `skill CONTAINS <component or skill>` |
| `mcp_server.tools[]` | `mcp_server EXPOSES tool` |

## Status

Working draft. The full SPDX 3.0 JSON-LD profile bindings are evolving alongside SPDX's AI profile work.
