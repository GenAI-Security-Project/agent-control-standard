# Extending SPDX

SPDX 3.0 is one of the three normative AgBOM serializations in v0.1.0. The canonical AgBOM document is the source of truth, and the Guardian derives SPDX 3.0 JSON-LD from it on request. The mapping rules live in [`inspect/format-mapping.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/inspect/format-mapping.json), and this page restates them. Where the two differ, the mapping file wins.

## Component-type mapping

Each canonical component becomes one SPDX Element node.

| Canonical type | SPDX class | Notes |
|---|---|---|
| `model` | `spdx:AIPackage` | The SPDX 3.0 AI profile's class for models. |
| `tool` | `spdx:SoftwarePackage` | Agent-callable code. |
| `mcp_server` | `spdx:Service` | An endpoint reachable through MCP. |
| `a2a_peer` | `spdx:Service` | A peer agent's endpoint. |
| `knowledge_source` | `spdx:Service` | A datastore or search endpoint. |
| `memory_store` | `spdx:DatasetPackage` | A long-lived state store. |
| `agent_capability` | `spdx:Bundle` | Aggregates the components it references through `CONTAINS` relationships. |
| `skill` | `spdx:SoftwarePackage` | Carries a verified checksum derived from its definition digest, and aggregates the components it references through `CONTAINS` relationships. |

## Relationships

| ACS edge | SPDX relationship |
|---|---|
| `agent_capability.tools[]`, `.mcp_servers[]`, `.a2a_peers[]` | `agent_capability CONTAINS <component>` |
| `skill.tools[]`, `.mcp_servers[]`, `.a2a_peers[]`, `.composed_skills[]` | `skill CONTAINS <component>` |
| `mcp_server.tools[]` | `mcp_server EXPOSES tool` |

AgBOM-level metadata (`agent.agent_id`, `generated_at`, `agbom_hash`) maps to `spdx:CreationInfo` and SPDX Element identifiers.

## Status

Working draft. The mapping file fixes the classes and relationships above. The full SPDX 3.0 JSON-LD bindings are evolving alongside SPDX's AI profile work.
