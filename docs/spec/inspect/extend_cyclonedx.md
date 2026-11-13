# Extending CycloneDX

CycloneDX 1.6 is one of the three normative AgBOM serializations in v0.1.0. The canonical AgBOM document is the source of truth; CycloneDX output is derived deterministically from it. The mapping rules live in [`inspect/format-mapping.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/inspect/format-mapping.json).

## Component-type mapping

Each canonical component becomes one entry in the CycloneDX `components[]` array. CycloneDX `bom-ref` equals the canonical component `id`, which makes round-tripping straightforward.

| Canonical type | CycloneDX `type` | Notes |
|---|---|---|
| `model` | `ai-model` | Uses CycloneDX's bom-types extension for AI models. |
| `mcp_server` | `service` | An endpoint reachable via MCP. |
| `a2a_peer` | `service` | Cross-agent endpoint; `agent_card_ref` flows into `externalReferences`. |
| `tool` | `application` | Agent-callable code unit. Capability flows into `properties`. |
| `knowledge_source` | `service` | A datastore or search endpoint. |
| `memory_store` | `service` | Long-lived state store. |
| `agent_capability` | `application` | A composed capability — its tool/MCP/A2A dependencies become CycloneDX `dependencies`. |

## Example

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-04-30T10:30:00Z",
    "tools": [{ "name": "acs-guardian", "version": "0.1.0" }],
    "component": { "type": "application", "bom-ref": "urn:agent:finance-summary-agent" }
  },
  "components": [
    {
      "type": "ai-model",
      "bom-ref": "gpt-4o-2024-08-06",
      "name": "GPT-4o",
      "version": "2024-08-06",
      "supplier": { "name": "OpenAI" },
      "properties": [
        { "name": "acs:context_window", "value": "128000" },
        { "name": "acs:endpoint", "value": "https://api.openai.com/v1" }
      ]
    },
    {
      "type": "service",
      "bom-ref": "urn:mcp:db-mcp",
      "name": "db-mcp",
      "version": "1.4.0",
      "endpoints": ["https://mcp.internal/db"]
    },
    {
      "type": "application",
      "bom-ref": "urn:tool:database_query",
      "name": "database_query",
      "version": "1.4.0",
      "properties": [
        { "name": "acs:capability", "value": "datastore.read" },
        { "name": "acs:registration_provenance.origin", "value": "system" }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "urn:agent:finance-summary-agent",
      "dependsOn": ["gpt-4o-2024-08-06", "urn:mcp:db-mcp", "urn:tool:database_query"]
    }
  ]
}
```

## Notes

- Canonical fields without a direct CycloneDX home land in `properties` under the `acs:` prefix. This keeps the serialization round-trip-safe — anything a Guardian needs for policy is reachable from CycloneDX without consulting the canonical document separately.
- `registration_provenance` becomes a property pair (`acs:registration_provenance.origin`, `acs:registration_provenance.source_id`) so audits can detect components added by runtime discovery vs. configuration.
- For `agbom/changed`, deployments MAY emit a CycloneDX VEX-style diff or simply emit a fresh full serialization — the canonical wire form already carries the diff structure (`added[]`, `removed[]`, `changed[]`).
