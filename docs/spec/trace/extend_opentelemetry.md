# Extending OpenTelemetry

ACS reuses OpenTelemetry as the primary observability transport. Each ACS step becomes a span; each Guardian decision becomes a span event on the parent step span. The result is an end-to-end view of agent behavior — reasoning, retrieval, tool calls, decisions — already shaped to fit existing OTel-based tooling.

The normative span-name and required-attribute table is on the [Trace Events](./events.md) page. The machine-readable mapping lives at [`trace/otel-mapping.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/trace/otel-mapping.json). This page describes how to *use* the mapping in practice.

## Span hierarchy

A typical agent session produces a tree of spans:

- A root **session** span (`acs.session`) opened by `steps/sessionStart` and closed by `steps/sessionEnd`. Carries `acs.session.id` and (when set) `acs.tenant_id`.
- One **turn** span (`acs.turn`) per agent turn, opened by `steps/turnStart` and closed by `steps/turnEnd`. Carries `acs.turn.id`. Nested turns (e.g. subagent turns inside a parent turn awaiting `subagentStop`) record `acs.turn.parent_id`.
- One **step** span per `steps/*` hook, parented to the enclosing turn (or session when the step is session-level: `agentTrigger`, `agbom/*` outside a turn). Every step span carries `acs.request_id` and `acs.session.id`, the pair a reader joins on.
- Each **decision** is a span event on the step span carrying `acs.decision`, plus `acs.evaluator` (`deterministic` / `agent` / `composite`), `acs.reasoning`, and `acs.confidence` when the response carries them. The replay attributes on [Trace Events](./events.md) ride the same event. Decisions are not separate spans because the verdict and the action it gates share a parent.
- A **decision failure** is a separate span event, `acs.decision.failure`, on the same step span. It records that no usable decision arrived and the deployment's failure posture.

This hierarchy is deterministic — implementations that follow the mapping produce comparable traces across vendors and Guardians.

## Example: a denied tool call

This is one span the reference Guardian exported, a `steps/toolCallRequest` the stock policy denied, copied from the committed [sample trace](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/reference-implementations/agt/samples/trace/acs-trace-sample.jsonl). Every value in it is synthetic. It's the OTLP/JSON shape the exporter writes, so attribute values are typed (`stringValue`, `arrayValue`).

The span carries the join pair (`acs.session.id` and `acs.request_id`), the tool name, and the two Provenance columns. `acs.provenance.source_id` has `""` where the second object has no `source_id`. The decision rides on the span as the `acs.decision` event, with the verdict, the reasoning, the reason codes and the three policy arrays. `acs.policy.versions` is `[""]`, because this Guardian doesn't send a policy version.

```json
{
  "traceId": "85c4878c9bda9e5b4f2fc6aae242d31f",
  "spanId": "dea6530ad1681c0e",
  "name": "gen_ai.tool.call",
  "kind": 1,
  "startTimeUnixNano": "1791928279698000000",
  "endTimeUnixNano": "1791928279749301083",
  "attributes": [
    {
      "key": "acs.session.id",
      "value": {
        "stringValue": "5a3c1e7e-0b1d-4c6a-9e2f-7d4b8c0a1f01"
      }
    },
    {
      "key": "acs.request_id",
      "value": {
        "stringValue": "1b6f0c2a-3d4e-4f5a-8b6c-7d8e9f0a1b03"
      }
    },
    {
      "key": "gen_ai.tool.name",
      "value": {
        "stringValue": "Bash"
      }
    },
    {
      "key": "acs.provenance.origin",
      "value": {
        "arrayValue": {
          "values": [
            {
              "stringValue": "user_input"
            },
            {
              "stringValue": "agent_generated"
            }
          ]
        }
      }
    },
    {
      "key": "acs.provenance.source_id",
      "value": {
        "arrayValue": {
          "values": [
            {
              "stringValue": "sample-user-1"
            },
            {
              "stringValue": ""
            }
          ]
        }
      }
    }
  ],
  "droppedAttributesCount": 0,
  "events": [
    {
      "attributes": [
        {
          "key": "acs.decision",
          "value": {
            "stringValue": "deny"
          }
        },
        {
          "key": "acs.reasoning",
          "value": {
            "stringValue": "This command was blocked because it matches a destructive-shell-command pattern. Policy: destructive_shell_command_blocked, from AGT's stock bundle (agt_stock). Matched at offset 0."
          }
        },
        {
          "key": "acs.reason_codes",
          "value": {
            "arrayValue": {
              "values": [
                {
                  "stringValue": "destructive_shell_command_blocked"
                }
              ]
            }
          }
        },
        {
          "key": "acs.policy.ids",
          "value": {
            "arrayValue": {
              "values": [
                {
                  "stringValue": "agt_stock"
                }
              ]
            }
          }
        },
        {
          "key": "acs.policy.versions",
          "value": {
            "arrayValue": {
              "values": [
                {
                  "stringValue": ""
                }
              ]
            }
          }
        },
        {
          "key": "acs.policy.rule_ids",
          "value": {
            "arrayValue": {
              "values": [
                {
                  "stringValue": "destructive_shell_command_blocked"
                }
              ]
            }
          }
        }
      ],
      "name": "acs.decision",
      "timeUnixNano": "1791928279749295500",
      "droppedAttributesCount": 0
    }
  ],
  "droppedEventsCount": 0,
  "status": {
    "code": 0
  },
  "links": [],
  "droppedLinksCount": 0,
  "flags": 257
}
```

To produce a trace like this yourself, follow [Produce a trace](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/reference-implementations/agt/README.md#produce-a-trace) in the reference implementation's README.

## Provenance attributes

When a hook payload carries Provenance, the resulting span MUST carry `acs.provenance.origin` and SHOULD carry `acs.provenance.source_id` when populated. The set of provenance ids cited by a Guardian decision (the response envelope's `cited_provenance_ids`) MAY be expressed as OTel span links keyed by `provenance_id`, letting tools that index span links reconstruct the lineage graph without parsing payloads.

v0.1 emits factual provenance attributes only. Trust classification is computed by the Guardian against local policy and is not a v0.1 span attribute.

## Sensitive data

Attributes can carry user prompts, tool arguments, and retrieved knowledge. Any of it can carry text an attacker influenced. [Trace Events](./events.md) says how consumers treat it. Implementations SHOULD apply the deployment's redaction or hashing policy at attribute-emit time rather than relying on backend-side scrubbing. The Guardian's `modifications.redactions` payload is the natural input to the policy: the same list that drives content rewriting drives attribute redaction.

## Transport

ACS does not redefine a trace transport. Implementations emit OTLP/gRPC or OTLP/HTTP to existing backends. The Guardian's handshake `trace_emission` field MAY advertise an OTLP collector endpoint; when set, the Observed Agent SHOULD route ACS-shaped trace traffic there in addition to (or instead of) its default collector.

## Failure isolation

Trace events MUST NOT block enforcement. If the Trace sink is unreachable or returns an error, the Guardian's disposition MUST still be returned to the Observed Agent. The agent's hot path is enforcement; observability is best-effort.
