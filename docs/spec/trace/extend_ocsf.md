# Extending OCSF

The Open Cybersecurity Schema Framework (OCSF) integration enables standardized security-event logging for AI agent activity. ACS-shaped events drop directly into existing SIEM pipelines without bespoke parsers.

ACS events map to OCSF 1.9.0 event classes. The normative class assignments and the disposition → `severity_id` mapping live on the [Trace Events](./events.md) page; the machine-readable mapping is at [`trace/ocsf-mapping.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/trace/ocsf-mapping.json). This page describes how to assemble the events themselves and provides representative wire examples.

## Class assignments at a glance

| ACS step | OCSF class | Class UID |
|---|---|---|
| `steps/sessionStart`, `steps/sessionEnd`, `steps/subagentStart`, `steps/subagentStop` | Authentication | 3002 |
| `steps/agentTrigger`, `steps/userMessage`, `steps/agentResponse`, `steps/turnStart`, `steps/turnEnd` | Application Lifecycle | 6002 |
| `steps/toolCallRequest`, `steps/toolCallResult` | Process Activity | 1007 |
| `steps/skillLoad`, `steps/skillUnload` | Module Activity | 1005 (`activity_id` 1 load, 2 unload) |
| `steps/knowledgeRetrieval`, `steps/memoryStore`, `steps/memoryContextRetrieval`, `steps/preCompact`, `steps/postCompact` | Datastore Activity | 6005 |
| Decision (deny/modify/ask/defer) | Detection Finding | 2004 |
| `agbom/snapshot`, `agbom/changed` | Device Inventory Info | 5001 (`activity_id` 2, Collect) |
| `steps/skillRegister` | Device Inventory Info | 5001 (`activity_id` 2, Collect) |

## Severity mapping

| Disposition | `severity_id` |
|---|---|
| `allow` | 1 (Informational) |
| `modify` | 2 (Low) |
| `ask` | 3 (Medium) |
| `defer` | 3 (Medium) |
| `deny` | 4 (High) |

## Example: tool call as Process Activity (1007)

```json
{
  "category_uid": 1,
  "category_name": "System Activity",
  "class_uid": 1007,
  "class_name": "Process Activity",
  "activity_id": 1,
  "activity_name": "Launch",
  "time": 1706550000000,
  "type_uid": 100701,
  "severity_id": 1,
  "metadata": {
    "version": "1.9.0",
    "correlation_uid": "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36:3f6c1e2a-8b4d-4c1e-9a7f-2d5b6e8c9a01",
    "product": { "name": "ACS Guardian", "vendor_name": "ACS" }
  },
  "actor": {
    "user": {
      "uid": "agent-123",
      "name": "CustomerServiceAgent",
      "type_id": 99,
      "type": "AI Agent"
    },
    "session": { "uid": "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36" }
  },
  "process": {
    "name": "database_query",
    "uid": "exec-123",
    "cmd_line": "tools/call:database_query"
  },
  "unmapped": {
    "acs": {
      "request_id": "3f6c1e2a-8b4d-4c1e-9a7f-2d5b6e8c9a01",
      "session_id": "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36",
      "step": { "id": "step-abc", "type": "toolCallRequest", "turn_id": "turn-456" },
      "tool": { "id": "database_query", "execution_id": "exec-123", "capability": "datastore.read" },
      "provenance": [
        { "provenance_id": "p1", "origin": "user_input", "source_id": "user-12345" }
      ]
    }
  }
}
```

## Example: deny decision as Detection Finding (2004)

```json
{
  "category_uid": 2,
  "category_name": "Findings",
  "class_uid": 2004,
  "class_name": "Detection Finding",
  "activity_id": 1,
  "activity_name": "Create",
  "time": 1706550000050,
  "type_uid": 200401,
  "severity_id": 4,
  "action_id": 2,
  "action": "Denied",
  "disposition_id": 2,
  "disposition": "Blocked",
  "is_alert": true,
  "metadata": {
    "version": "1.9.0",
    "profiles": ["security_control"],
    "correlation_uid": "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36:7c4e9a1d-2f6b-4d8e-a3c5-1b9f0e7d6a52",
    "product": { "name": "ACS Guardian", "vendor_name": "ACS" }
  },
  "finding_info": {
    "uid": "decision-001",
    "title": "Tool call denied: outside committed Intent",
    "desc": "email.send to recipient outside Intent.parsed; IBAC P-I check failed."
  },
  "evidences": [
    {
      "ai_agent": { "uid": "agent-123" },
      "actor": { "session": { "uid": "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36" } },
      "api": { "operation": "email.send" }
    }
  ],
  "authorizations": [
    { "policy": { "uid": "acme-ibac", "version": "v1" } }
  ],
  "unmapped": {
    "acs": {
      "decision": "deny",
      "reasoning": "email.send to recipient outside Intent.parsed; IBAC P-I check failed.",
      "metadata": { "evaluator": "deterministic" },
      "policy_references": [
        { "policy_id": "acme-ibac", "policy_version": "v1", "rule_id": "email-send-recipient-not-in-intent" }
      ],
      "reason_codes": ["ibac_capability_mismatch"],
      "cited_provenance_ids": ["p1"],
      "chain_hash": "9f2c4e7a1b3d5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8",
      "request_id": "7c4e9a1d-2f6b-4d8e-a3c5-1b9f0e7d6a52",
      "session_id": "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36"
    }
  }
}
```

## Example: AgBOM snapshot as Device Inventory Info (5001)

```json
{
  "category_uid": 5,
  "category_name": "Discovery",
  "class_uid": 5001,
  "class_name": "Device Inventory Info",
  "activity_id": 2,
  "activity_name": "Collect",
  "time": 1706549900000,
  "type_uid": 500102,
  "severity_id": 1,
  "metadata": {
    "version": "1.9.0",
    "correlation_uid": "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36:8d2b7f40-1c3e-4a59-b6d8-0e9f1a2b3c4d",
    "product": { "name": "ACS Guardian", "vendor_name": "ACS" }
  },
  "device": {
    "uid": "agent-123",
    "name": "CustomerServiceAgent",
    "type_id": 99,
    "type": "AI Agent"
  },
  "unmapped": {
    "acs": {
      "request_id": "8d2b7f40-1c3e-4a59-b6d8-0e9f1a2b3c4d",
      "session_id": "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36",
      "agbom": {
        "format": "canonical",
        "component_count": 7,
        "components": [
          { "type": "model", "id": "gpt-4o", "provider": "OpenAI" },
          { "type": "mcp_server", "id": "db-mcp", "endpoint": "https://mcp.internal/db" },
          { "type": "tool", "id": "database_query", "capability": "datastore.read" }
        ]
      }
    }
  }
}
```

## Implementation notes

- **`actor.user.type_id: 99`** is the OCSF "Other" sentinel; pair with `actor.user.type: "AI Agent"` so SIEM filters can distinguish agent identities from human ones.
- **Native fields first.** SIEM content reads native fields, not `unmapped`. A decision event puts the join pair in `metadata.correlation_uid`, the agent and the gated action in `evidences`, and the policies in `authorizations`. The example above shows each, and the [Trace Events](./events.md#ocsf-event-classes) page has the rules, including what a late decision carries.
- **`unmapped.acs`** carries ACS-specific facts that don't have direct OCSF equivalents in OCSF 1.9.0. On a step event it carries `request_id`, `session_id`, and facts from the request that have no OCSF attribute of their own. On a decision event it carries the fields that `join_fields` and `acs_fields` in `ocsf-mapping.json` list. Backends that index `unmapped` keep this fully searchable.
- **Provenance** flows onto OCSF events under `unmapped.acs.provenance` as `{provenance_id, origin, source_id when present}` in code-point argument-key / output-index order, deduplicated by `provenance_id`, so `unmapped.acs.cited_provenance_ids` on a decision event resolves to its provenance facts on the step event. Trust classification is omitted on the wire for v0.1; backends that compute trust apply it as an enrichment step.

For more worked examples — including A2A and MCP wrapped events — see [Implementation examples](./OCSF/implementation_examples.md).
