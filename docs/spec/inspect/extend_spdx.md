# Extending SPDX

SPDX 3.0 is one of the three normative AgBOM serializations in v0.1.0. The canonical AgBOM document is the source of truth; SPDX output is derived deterministically from it. The mapping rules live in [`inspect/format-mapping.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/inspect/format-mapping.json).

## Component-type mapping

Each canonical component becomes one SPDX `software_Package` or `Service` node. Relationships (`DEPENDS_ON`, `DESCRIBES`, `USES`) reflect the agent_capability/tool/mcp_server graph.

| Canonical type | SPDX class | Notes |
|---|---|---|
| `model` | `ai_AIPackage` | SPDX 3.0 AI profile node for model artifacts. |
| `mcp_server` | `Service` | Endpoint reachable via MCP. |
| `a2a_peer` | `Service` | Cross-agent endpoint; `agent_card_ref` flows into `externalRef`. |
| `tool` | `software_Package` | Agent-callable code unit. |
| `knowledge_source` | `Service` | Datastore or search endpoint. |
| `memory_store` | `Service` | Long-lived state store. |
| `agent_capability` | `software_Package` | Composed capability; its tool/MCP/A2A dependencies become `DEPENDS_ON` relationships. |

## Relationships

| ACS edge | SPDX relationship |
|---|---|
| `agent_capability.tools[]` | `agent_capability USES tool` |
| `agent_capability.mcp_servers[]` | `agent_capability USES mcp_server` |
| `agent_capability.a2a_peers[]` | `agent_capability USES a2a_peer` |
| `mcp_server.tools[]` | `mcp_server CONTAINS tool` |
| Root agent → all components | `agent DEPENDS_ON <component>` |

## Status

Working draft. The full SPDX 3.0 JSON-LD profile bindings are evolving alongside SPDX's AI profile work.
