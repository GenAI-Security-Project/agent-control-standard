# Extending SWID

SWID (ISO/IEC 19770-2) is one of the three normative AgBOM serializations in v0.1.0. The canonical AgBOM document is the source of truth, and the Guardian derives SWID XML tags from it on request. The mapping rules live in [`inspect/format-mapping.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/inspect/format-mapping.json), and this page restates them. Where the two differ, the mapping file wins.

## Component mapping

Each canonical component becomes one `SoftwareIdentity` tag with `@tagId` set to the component `id`, `@name` to its `name`, and `@version` to its `version`. A root `SoftwareIdentity` whose `@tagId` is the agent's `agent_id` wraps the per-component tags and carries the AgBOM-level agent and timestamps.

| Canonical field or type | SWID element | Notes |
|---|---|---|
| `provider` | `<Entity role='softwareCreator' name='...'/>` | For every component type that carries a provider. |
| `endpoint` | `<Meta @location='...'/>` | For every component type that carries an endpoint. |
| `agent_capability` | `SoftwareIdentity` with `@corpus='true'` | Uses `<Link rel='requires' href='...'/>` to reference each constituent component. |
| `skill` | `SoftwareIdentity` with the definition digest in `<Payload><File @SHA256:hash='...'/></Payload>` | Uses `<Link rel='requires' href='...'/>` to reference its constituent components and composed skills. |
| `model`, `mcp_server`, `a2a_peer`, `tool`, `knowledge_source`, `memory_store` | Plain `SoftwareIdentity` | The fields above apply. |

## Status

Working draft. SWID's strength here is its compactness for environments that already consume SWID through management tooling (NIST SCAP, asset inventories). CycloneDX and SPDX cover most agent-deployment use cases.
