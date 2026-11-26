# Extending CycloneDX

## Map AgBOM v0.1.0 to CycloneDX 1.6 { #v010-mapping-cyclonedx-16 }

CycloneDX 1.6 is one of the three normative AgBOM serializations in v0.1.0. The canonical AgBOM document is the source of truth, and the Guardian derives CycloneDX output from it on request. The mapping rules live in [`inspect/format-mapping.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/inspect/format-mapping.json), and this page restates them with an example. Where the two differ, the mapping file wins.

### Component-type mapping

Each canonical component becomes one entry in the CycloneDX `components[]` array, except an `agent_capability`, which becomes a composition. The CycloneDX `bom-ref` equals the canonical component `id`, so a consumer can trace each entry back to the canonical document.

| Canonical type | CycloneDX representation | Notes |
|---|---|---|
| `model` | component, `type: machine-learning-model` | CycloneDX's component type for models. |
| `mcp_server` | component, `type: service` | An endpoint reachable through MCP. |
| `a2a_peer` | component, `type: service` | A peer agent's endpoint. |
| `tool` | component, `type: application` | Agent-callable code. |
| `knowledge_source` | component, `type: service` | A datastore or search endpoint. |
| `memory_store` | component, `type: data` | A `database` subtype where it applies. |
| `agent_capability` | `compositions[]` entry | Aggregates the components the capability references. |
| `skill` | component, `type: application`, plus a `compositions[]` entry | The definition digest goes in the component's `hashes`. The composition aggregates the components the skill references. |

Provenance attached to a component goes into CycloneDX `evidence` or `properties`, which [`format-mapping.json`](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/specification/v0.1.0/inspect/format-mapping.json) requires, as `acs:provenance:origin` and, when present, `acs:provenance:source_id`. Specification v0.1.0 carries factual provenance only. The Guardian computes trust classification against local policy, and CycloneDX output does not export it ([§7.1](../instrument/specification.md#71-optional-trust-enum)).

`metadata.tools` names the Observed Agent's framework as the BOM generator, as [`format-mapping.json`](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/specification/v0.1.0/inspect/format-mapping.json) recommends.

### Example

This canonical AgBOM declares a model, a tool, a skill that uses the tool, and a capability that uses the tool:

```json
{
  "agbom_version": "0.1.0",
  "agent": {
    "agent_id": "finance-summary-agent",
    "name": "Finance summary agent",
    "version": "2.0.0"
  },
  "generated_at": "2026-10-13T09:14:59Z",
  "components": [
    {
      "id": "model-primary",
      "type": "model",
      "name": "example-model",
      "version": "2026-08-01",
      "provider": "Example Model Co",
      "endpoint": "https://models.example.com/v1",
      "model_fields": {
        "context_window": 128000
      },
      "registration_provenance": {
        "provenance_id": "prov-1",
        "origin": "system",
        "source_id": "agent-config.yaml"
      }
    },
    {
      "id": "tool-database-query",
      "type": "tool",
      "name": "database_query",
      "version": "1.4.0",
      "provider": "Example Corp",
      "tool_fields": {
        "capability": "datastore.read"
      },
      "registration_provenance": {
        "provenance_id": "prov-2",
        "origin": "system",
        "source_id": "agent-config.yaml"
      }
    },
    {
      "id": "skill-quarterly-report",
      "type": "skill",
      "name": "quarterly-report",
      "version": "1.1.0",
      "skill_fields": {
        "description": "Builds the quarterly finance summary.",
        "definition": {
          "ref": "https://skills.example.com/quarterly-report/1.1.0.zip",
          "digest": {
            "algorithm": "sha-256",
            "value": "b0fb17f81f93281ccb95efafd2ffbe7ba3d856e7872da86c0af52e934ede16e2"
          }
        },
        "declared_capabilities": [
          "datastore.read"
        ],
        "tools": [
          "tool-database-query"
        ]
      },
      "registration_provenance": {
        "provenance_id": "prov-3",
        "origin": "user_input",
        "source_id": "skill-install"
      }
    },
    {
      "id": "cap-reporting",
      "type": "agent_capability",
      "name": "finance-reporting",
      "agent_capability_fields": {
        "description": "Answers finance questions from the ledger.",
        "tools": [
          "tool-database-query"
        ]
      }
    }
  ]
}
```

Derived as CycloneDX 1.6:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-10-13T09:14:59Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "example-agent-framework",
          "version": "2.3.0"
        }
      ]
    },
    "component": {
      "type": "application",
      "bom-ref": "finance-summary-agent",
      "name": "Finance summary agent",
      "version": "2.0.0"
    }
  },
  "components": [
    {
      "type": "machine-learning-model",
      "bom-ref": "model-primary",
      "name": "example-model",
      "version": "2026-08-01",
      "supplier": {
        "name": "Example Model Co"
      },
      "properties": [
        {
          "name": "acs:provenance:origin",
          "value": "system"
        },
        {
          "name": "acs:provenance:source_id",
          "value": "agent-config.yaml"
        }
      ]
    },
    {
      "type": "application",
      "bom-ref": "tool-database-query",
      "name": "database_query",
      "version": "1.4.0",
      "supplier": {
        "name": "Example Corp"
      },
      "properties": [
        {
          "name": "acs:provenance:origin",
          "value": "system"
        },
        {
          "name": "acs:provenance:source_id",
          "value": "agent-config.yaml"
        }
      ]
    },
    {
      "type": "application",
      "bom-ref": "skill-quarterly-report",
      "name": "quarterly-report",
      "version": "1.1.0",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "b0fb17f81f93281ccb95efafd2ffbe7ba3d856e7872da86c0af52e934ede16e2"
        }
      ],
      "properties": [
        {
          "name": "acs:provenance:origin",
          "value": "user_input"
        },
        {
          "name": "acs:provenance:source_id",
          "value": "skill-install"
        }
      ]
    }
  ],
  "compositions": [
    {
      "bom-ref": "cap-reporting",
      "aggregate": "complete",
      "assemblies": [
        "tool-database-query"
      ]
    },
    {
      "bom-ref": "skill-quarterly-report-composition",
      "aggregate": "complete",
      "assemblies": [
        "tool-database-query"
      ]
    }
  ]
}
```

Each component keeps its canonical `id` as its `bom-ref`, and both provenance properties ride in `properties`. The skill's `sha-256` definition digest becomes a `SHA-256` hash. The capability has no component entry. Its composition carries the capability's `id` as its `bom-ref` and lists the tool it references.

### Notes

- `format-mapping.json` fixes the component types, `bom-ref`, the provenance properties, the compositions and the skill hash. It does not say where the other canonical fields go, such as `provider`, `endpoint`, `context_window` or a tool's `capability`. This example puts `provider` in `supplier` and leaves the rest out. The canonical document keeps every field.
- The mapping file doesn't name the composition that a skill adds beside its component, which cannot reuse the component's `bom-ref`. This example appends `-composition` to the skill's `id`.
- For `agbom/changed`, deployments MAY emit a CycloneDX VEX-style diff or simply emit a fresh full serialization — the canonical wire form already carries the diff structure (`added[]`, `removed[]`, `changed[]`).

!!! note "Non-normative: CycloneDX services"
    CycloneDX 1.6 lists services in a top-level `services[]` array, and `service` is not one of its component types. A strict CycloneDX 1.6 validator therefore rejects a `components[]` entry with `type: service`, which the mapping file gives `mcp_server`, `a2a_peer` and `knowledge_source`. The example above holds none of those types for that reason. The mapping stays as published until the specification changes it.

## Explore the CycloneDX 2.0-dev mapping (non-normative draft) { #cyclonedx-20-dev-non-normative-draft }

The AgBOM Viewer follows a pinned revision of CycloneDX 2.0-dev. The draft maps canonical ACS AgBOM fields and terms to CycloneDX 2.0 and records gaps.

## What comes next

The ACS leads chose CycloneDX 2.0 as the first target for the AgBOM mapping workstream ([D-044](../../decisions/index.md#d-044-manage-agbom-as-an-acs-sub-stream-and-map-it-to-cyclonedx-first)). Once CycloneDX publishes the final 2.0 release, ACS will check the mapping and viewer against it and align both with the release.

- Explore the 2.0-dev mapping, samples, use cases, and bundled capture comparisons in the [AgBOM Viewer](agbom-viewer/index.html).
- Follow the [Local BOMs guide](agbom_viewer_local.md) to open the viewer from an ACS checkout and inspect and compare your own BOMs.
