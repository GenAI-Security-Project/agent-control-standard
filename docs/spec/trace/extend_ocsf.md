# Extending OCSF

The Open Cybersecurity Schema Framework (OCSF) integration enables standardized security-event logging for AI agent activity. ACS-shaped events drop directly into existing SIEM pipelines without bespoke parsers.

ACS events map to OCSF 1.5+ event classes. The normative class assignments and the disposition → `severity_id` mapping live on the [Trace Events](./events.md) page; the machine-readable mapping is at [`trace/ocsf-mapping.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/trace/ocsf-mapping.json). This page describes how to assemble the events themselves and provides representative wire examples.

## Class assignments at a glance

| ACS step | OCSF class | Class UID |
|---|---|---|
| `steps/sessionStart`, `steps/sessionEnd`, `steps/subagentStart`, `steps/subagentStop` | Authentication | 3002 |
| `steps/agentTrigger`, `steps/userMessage`, `steps/agentResponse`, `steps/turnStart`, `steps/turnEnd` | Application Activity | 6002 |
| `steps/toolCallRequest`, `steps/toolCallResult` | Process Activity | 1007 |
| `steps/skillLoad` | Process Activity | 1007 |
| `steps/knowledgeRetrieval`, `steps/memoryStore`, `steps/memoryContextRetrieval`, `steps/preCompact`, `steps/postCompact` | Datastore Activity | 6005 |
| Decision (deny/modify/ask/defer) | Detection Finding | 2004 |
| `agbom/snapshot`, `agbom/changed` | Inventory Info | 5001 |
| `steps/skillRegister`, `steps/skillUnload` | Inventory Info | 5001 |

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
    "version": "1.5.0",
    "product": { "name": "ACS Guardian", "vendor_name": "ACS" }
  },
  "actor": {
    "user": {
      "uid": "agent-123",
      "name": "CustomerServiceAgent",
      "type_id": 99,
      "type": "AI Agent"
    },
    "session": { "uid": "session-789" }
  },
  "process": {
    "name": "database_query",
    "uid": "exec-123",
    "cmd_line": "tools/call:database_query"
  },
  "unmapped": {
    "acs": {
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
  "severity_id": 4,
  "status_id": 1,
  "metadata": { "version": "1.5.0", "product": { "name": "ACS Guardian", "vendor_name": "ACS" } },
  "finding_info": {
    "uid": "decision-001",
    "title": "Tool call denied: outside committed Intent",
    "desc": "email.send to recipient outside Intent.parsed; IBAC P-I check failed."
  },
  "unmapped": {
    "acs": {
      "decision": "deny",
      "evaluator": "deterministic",
      "policy_references": [
        { "policy_id": "acme-ibac", "policy_version": "v1", "rule_id": "email-send-recipient-not-in-intent" }
      ],
      "reason_codes": ["ibac_capability_mismatch"],
      "cited_provenance_ids": ["p1"],
      "session_id": "session-789",
      "step_id": "step-abc"
    }
  }
}
```

## Example: AgBOM snapshot as Inventory Info (5001)

```json
{
  "category_uid": 5,
  "category_name": "Discovery",
  "class_uid": 5001,
  "class_name": "Inventory Info",
  "activity_id": 1,
  "activity_name": "Log",
  "time": 1706549900000,
  "severity_id": 1,
  "metadata": { "version": "1.5.0" },
  "device": {
    "uid": "agent-123",
    "name": "CustomerServiceAgent",
    "type": "AI Agent"
  },
  "unmapped": {
    "acs": {
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
- **`unmapped.acs`** carries ACS-specific facts that don't have direct OCSF equivalents in v1.5. The structure mirrors the request envelope's `payload` plus the decision envelope's `policy_data` / `reason_codes`. Backends that index `unmapped` keep this fully searchable.
- **Provenance** flows onto OCSF events under `unmapped.acs.provenance`. Trust classification is omitted on the wire for v0.1; backends that compute trust apply it as an enrichment step.

For more worked examples — including A2A and MCP wrapped events — see [Implementation examples](./OCSF/implementation_examples.md).
