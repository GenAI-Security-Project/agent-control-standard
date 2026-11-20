# OCSF Implementation Examples

This page shows one way to turn ACS traffic into OCSF 1.9.0 events by following [`trace/ocsf-mapping.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/trace/ocsf-mapping.json), and how to query the result in a SIEM. [Trace Events](../events.md#ocsf-event-classes) states the rules. Where this page and the mapping file differ, the mapping file wins.

The code is an illustration, not a package the project ships. No release 0.1.5 component emits OCSF yet.

## Build events from an ACS exchange

The function below uses the Python standard library only. It takes a signed request and the Guardian's response and builds two events: the step itself as Process Activity (1007), and the decision as Detection Finding (2004), or as Application Lifecycle (6002) for an allow.

```python
"""Build OCSF 1.9.0 events from an ACS request and response, per trace/ocsf-mapping.json."""
import json
from datetime import datetime

OCSF_VERSION = "1.9.0"
PRODUCT = {"name": "Example ACS Guardian", "vendor_name": "Example Corp"}

# From ocsf-mapping.json: step_to_class for the two tool hooks, and the decision tables.
TOOL_CLASS = {"class_uid": 1007, "class_name": "Process Activity", "category_uid": 1, "category_name": "System Activity"}
SEVERITY = {"allow": 1, "modify": 2, "ask": 3, "defer": 3, "deny": 4}
ACTION = {"allow": (1, "Allowed"), "deny": (2, "Denied"), "modify": (4, "Modified"), "ask": (99, "ask"), "defer": (99, "defer")}
DISPOSITION = {"allow": (1, "Allowed"), "deny": (2, "Blocked"), "modify": (99, "modify"), "ask": (99, "ask"), "defer": (99, "defer")}
ALERT = {"allow": False, "deny": True, "modify": False, "ask": True, "defer": True}
ACS_FIELDS = ["request_id", "decision", "reasoning", "reason_codes", "policy_references",
              "cited_provenance_ids", "chain_hash", "metadata"]


def epoch_ms(timestamp):
    return int(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp() * 1000)


def pair(request):
    return request["params"]["metadata"]["session_id"], request["params"]["request_id"]


def provenance_enrichments(payload):
    """Provenance facts go in enrichments named acs_provenance_* (provenance_metadata)."""
    found = []
    for argument in payload.get("arguments", {}).values():
        found.extend(argument.get("provenance", []))
    enrichments = []
    for item in found:
        enrichments.append({"name": "acs_provenance_origin", "value": item["origin"], "data": item})
        if "source_id" in item:
            enrichments.append({"name": "acs_provenance_source_id", "value": item["source_id"], "data": item})
    return enrichments


def step_event(request, activity_id, activity_name, host_context):
    """A steps/toolCallRequest or steps/toolCallResult event as Process Activity (1007).

    host_context carries the OCSF context only the host runtime knows, such as
    actor, device and process. ACS payloads do not hold it.
    """
    params = request["params"]
    session_id, request_id = pair(request)
    event = {
        **TOOL_CLASS,
        "activity_id": activity_id,
        "activity_name": activity_name,
        "type_uid": TOOL_CLASS["class_uid"] * 100 + activity_id,
        "severity_id": 1,
        "time": epoch_ms(params["timestamp"]),
        "metadata": {"version": OCSF_VERSION, "product": PRODUCT,
                     "correlation_uid": f"{session_id}:{request_id}"},
        **host_context,
        "unmapped": {"acs": {
            "method": request["method"],
            "request_id": request_id,
            "session_id": session_id,
            "agent_id": params["metadata"]["agent_id"],
            **params["payload"],
        }},
    }
    enrichments = provenance_enrichments(params["payload"])
    if enrichments:
        event["enrichments"] = enrichments
    return event


def decision_event(request, response, decided_at):
    """The Guardian's answer: Detection Finding (2004), or Application Lifecycle (6002) for allow."""
    result = response["result"]
    decision = result["decision"]
    session_id, request_id = pair(request)
    unmapped = {"session_id": session_id}
    unmapped.update({name: result[name] for name in ACS_FIELDS if result.get(name) not in (None, [], {})})
    common = {
        "time": epoch_ms(decided_at),
        "severity_id": SEVERITY[decision],
        "metadata": {"version": OCSF_VERSION, "product": PRODUCT,
                     "correlation_uid": f"{session_id}:{request_id}"},
        "unmapped": {"acs": unmapped},
    }
    if decision == "allow":
        # allow_class leaves activity_id open, so this example records 0 (Unknown).
        return {"class_uid": 6002, "class_name": "Application Lifecycle", "category_uid": 6,
                "category_name": "Application Activity", "activity_id": 0, "activity_name": "Unknown",
                "type_uid": 600200, **common}
    action_id, action = ACTION[decision]
    disposition_id, disposition = DISPOSITION[decision]
    event = {
        "class_uid": 2004, "class_name": "Detection Finding", "category_uid": 2, "category_name": "Findings",
        "activity_id": 1, "activity_name": "Create", "type_uid": 200401,
        **common,
        "action_id": action_id, "action": action,
        "disposition_id": disposition_id, "disposition": disposition,
        "is_alert": ALERT[decision],
        "finding_info": {"uid": f"{session_id}:{request_id}",
                         "title": f"ACS {decision} on {request['method']}"},
        "evidences": [{
            "ai_agent": {"uid": request["params"]["metadata"]["agent_id"]},
            "actor": {"session": {"uid": session_id}},
        }],
    }
    if request["method"] in ("steps/toolCallRequest", "steps/toolCallResult"):
        event["evidences"][0]["api"] = {"operation": request["params"]["payload"]["tool"]["name"]}
    event["metadata"]["profiles"] = ["security_control"]
    if "reasoning" in result:
        event["finding_info"]["desc"] = result["reasoning"]
    references = result.get("policy_references", [])
    if references:
        event["authorizations"] = [
            {"policy": {key: ref[src] for key, src in (("uid", "policy_id"), ("version", "policy_version"), ("name", "policy_name")) if src in ref}}
            if ("policy_id" in ref or "policy_name" in ref) else {}
            for ref in references
        ]
    return event
```

Two choices in it come from the example, not from the mapping. The mapping fixes the class for a tool step but not its `activity_id`, so the caller passes one. The mapping leaves the `activity_id` of an allow event open too, and the code records 0 (Unknown).

The step event holds only the fields ACS defines. Process Activity also requires `actor`, `device` and `process`, which only the host runtime knows, so the caller passes them in `host_context`. The [OCSF example in the ACS overview](../../../acs.md#traceable) shows a step event with that context filled in.

`unmapped.acs` copies the request payload as it is, tool arguments included. Apply the deployment's redaction policy before an event leaves the host, as [Trace with OpenTelemetry](../extend_opentelemetry.md#sensitive-data) advises for spans.

## Example output

Run on the `steps/toolCallRequest` exchange from the [ACS overview](../../../acs.md#instrumentable), with an empty `host_context`, the step event is:

```json
{
  "class_uid": 1007,
  "class_name": "Process Activity",
  "category_uid": 1,
  "category_name": "System Activity",
  "activity_id": 1,
  "activity_name": "Launch",
  "type_uid": 100701,
  "severity_id": 1,
  "time": 1791882900000,
  "metadata": {
    "version": "1.9.0",
    "product": {
      "name": "Example ACS Guardian",
      "vendor_name": "Example Corp"
    },
    "correlation_uid": "17a301f1-6d17-4941-8bea-92320f0773aa:c329d5a4-97ae-44c8-986d-77d1da194ab7"
  },
  "unmapped": {
    "acs": {
      "method": "steps/toolCallRequest",
      "request_id": "c329d5a4-97ae-44c8-986d-77d1da194ab7",
      "session_id": "17a301f1-6d17-4941-8bea-92320f0773aa",
      "agent_id": "research-assistant",
      "tool": {
        "name": "database_query"
      },
      "capability": "datastore.read",
      "arguments": {
        "query": {
          "value": "SELECT * FROM customers"
        }
      }
    }
  }
}
```

The Guardian answered `modify`, so the decision event is a Detection Finding with `action_id` 4 (Modified) and `disposition_id` 99, whose `disposition` carries the ACS name:

```json
{
  "class_uid": 2004,
  "class_name": "Detection Finding",
  "category_uid": 2,
  "category_name": "Findings",
  "activity_id": 1,
  "activity_name": "Create",
  "type_uid": 200401,
  "time": 1791882900042,
  "severity_id": 2,
  "metadata": {
    "version": "1.9.0",
    "product": {
      "name": "Example ACS Guardian",
      "vendor_name": "Example Corp"
    },
    "correlation_uid": "17a301f1-6d17-4941-8bea-92320f0773aa:c329d5a4-97ae-44c8-986d-77d1da194ab7",
    "profiles": [
      "security_control"
    ]
  },
  "unmapped": {
    "acs": {
      "session_id": "17a301f1-6d17-4941-8bea-92320f0773aa",
      "request_id": "c329d5a4-97ae-44c8-986d-77d1da194ab7",
      "decision": "modify",
      "reasoning": "Narrowed the query to two columns and 100 rows. A full customer export violates the data-protection policy.",
      "reason_codes": [
        "pii_detected"
      ],
      "policy_references": [
        {
          "policy_id": "data-protection",
          "rule_id": "limit-customer-export"
        }
      ],
      "chain_hash": "25d878e6726ecf3bd9ee823d7642bdd78f148c0db5c06a585d16bc23494e2175",
      "metadata": {
        "evaluator": "deterministic"
      }
    }
  },
  "action_id": 4,
  "action": "Modified",
  "disposition_id": 99,
  "disposition": "modify",
  "is_alert": false,
  "finding_info": {
    "uid": "17a301f1-6d17-4941-8bea-92320f0773aa:c329d5a4-97ae-44c8-986d-77d1da194ab7",
    "title": "ACS modify on steps/toolCallRequest",
    "desc": "Narrowed the query to two columns and 100 rows. A full customer export violates the data-protection policy."
  },
  "evidences": [
    {
      "ai_agent": {
        "uid": "research-assistant"
      },
      "actor": {
        "session": {
          "uid": "17a301f1-6d17-4941-8bea-92320f0773aa"
        }
      },
      "api": {
        "operation": "database_query"
      }
    }
  ],
  "authorizations": [
    {
      "policy": {
        "uid": "data-protection"
      }
    }
  ]
}
```

The policy reference carries no `policy_version`, so its `authorizations` entry has no `version`. Both events carry the same `metadata.correlation_uid`, which is how a SIEM joins a decision to the step it gated. If the step carried Provenance, the step event would also carry `enrichments` named `acs_provenance_origin` and `acs_provenance_source_id`.

## Query the events in a SIEM

SIEM content reads native fields. Join on `metadata.correlation_uid`, filter on `class_uid`, and read `unmapped.acs` for the exact ACS values. An `action_id` of 2 (Denied) records the Guardian's verdict. It does not prove the action was blocked, and a decision event whose `finding_info.types` includes `late_decision_fail_open` or `late_decision_fail_closed` never counts as enforced ([Trace Events](../events.md#ocsf-event-classes)).

### Splunk

```spl
# Guardian verdicts on tool calls, by tool and disposition
index=security sourcetype=ocsf class_uid=2004
| stats count by evidences{}.api.operation, unmapped.acs.decision
| sort - count

# Each tool step beside the decision that gated it
index=security sourcetype=ocsf (class_uid=1007 OR class_uid=2004 OR class_uid=6002)
| stats values(class_uid) as classes, values(unmapped.acs.decision) as decision by metadata.correlation_uid

# Decisions that arrived after the agent stopped waiting
index=security sourcetype=ocsf class_uid=2004
    (finding_info.types{}="late_decision_fail_open" OR finding_info.types{}="late_decision_fail_closed")
| stats count by unmapped.acs.decision
```

### Elasticsearch

Field names below assume the default dynamic mapping, which adds a `.keyword` subfield to each string.

```json
{
  "query": {
    "term": { "class_uid": 2004 }
  },
  "aggs": {
    "by_tool": {
      "terms": { "field": "evidences.api.operation.keyword", "size": 10 },
      "aggs": {
        "by_decision": {
          "terms": { "field": "unmapped.acs.decision.keyword" }
        }
      }
    }
  }
}
```

## Implementation guidelines

- **Pin the OCSF version.** Set `metadata.version` to `1.9.0`, the version the mapping's class UIDs come from.
- **Fill native fields first.** Put the join pair in `metadata.correlation_uid`, the agent and tool in `evidences`, and the policies in `authorizations`. Keep `unmapped.acs` as the exact copy for replay.
- **Treat every value as untrusted.** Agent and tool text can carry content an attacker shaped. Render it as data, never as markup or instructions.
- **Never let the sink block enforcement.** A failed OCSF write must not change the decision the Observed Agent receives.
- **Validate against OCSF.** Run each event through an OCSF 1.9.0 validator before you point SIEM content at it.

## Resources

- [OCSF Schema Documentation](https://schema.ocsf.io/)
- [OCSF Examples](https://github.com/ocsf/examples)
