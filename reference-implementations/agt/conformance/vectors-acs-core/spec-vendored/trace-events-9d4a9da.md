# Trace Events

Every agent step that produces an ACS hook is recordable as a Trace event. The Trace pillar is decoupled from enforcement and runs out of the request/response path: deployments emit OpenTelemetry spans (over OTLP/gRPC or OTLP/HTTP) and/or OCSF events to existing observability backends. ACS does not redefine a trace transport. Its normative contribution is the **vocabulary** — span names, attribute keys, event classes, severity/disposition mapping — that ensures cross-vendor agents and Guardians produce comparable traces.

Trace emission is the subject of the **ACS-Trace** [conformance profile](../conformance.md#acs-trace). Deployments that implement only ACS-Core (Instrument) without Trace are v0.1.0-conformant but do not claim ACS-Trace.

## OpenTelemetry semantic conventions

Each ACS step produces a span whose `name` and required attributes are fixed by the table below. Decisions are recorded as span events on the parent step span, not as separate spans, so the enforcement verdict and the action it gates share a parent.

The full mapping lives in [`trace/otel-mapping.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/trace/otel-mapping.json). See [Extending OpenTelemetry](./extend_opentelemetry.md) for a deeper integration guide.

| ACS step | OTel span name | Required attributes |
|---|---|---|
| `steps/sessionStart` | `acs.session` | `acs.session.id`; `acs.tenant_id` if set |
| `steps/agentTrigger` | `acs.agent.trigger` | `acs.agent.id`, `acs.trigger.type` |
| `steps/userMessage` | `acs.message.user` | `acs.session.id`, `acs.content.types[]` |
| `steps/agentResponse` | `acs.message.agent` | `acs.session.id`, `acs.agent.id` |
| `steps/toolCallRequest` | `gen_ai.tool.call` | `gen_ai.tool.name`, `acs.capability`; `acs.tool.provider` (optional) |
| `steps/toolCallResult` | `gen_ai.tool.result` | `gen_ai.tool.name`, `acs.exit_status`; `acs.duration_ms` (optional) |
| `steps/knowledgeRetrieval` | `acs.knowledge.retrieval` | `acs.source.type`, `acs.results.count` |
| `steps/memoryStore` | `acs.memory.store` | `acs.memory_store.name`, `acs.operation` |
| `steps/memoryContextRetrieval` | `acs.memory.retrieval` | `acs.memory_store.name`, `acs.results.count` |
| `steps/sessionEnd` | `acs.session.end` | `acs.session.reason` |
| `steps/turnStart`, `steps/turnEnd` | `acs.turn`, `acs.turn.end` | `acs.turn.id`, `acs.turn.triggered_by` / `acs.turn.outcome` |
| `steps/preCompact` | `acs.compact` | `acs.compact.entry_count`, `acs.compact.triggered_by` |
| `steps/postCompact` | `acs.compact.complete` | `acs.compact.entry_count`; `acs.compact.lineage_depth_after` (optional) |
| `steps/subagentStart`, `steps/subagentStop` | `acs.subagent`, `acs.subagent.end` | `acs.subagent.session_id`, `acs.subagent.parent_session_id`, `acs.subagent.intent_derivation` / `acs.subagent.outcome`, `acs.subagent.final_chain_hash` |
| Decision (allow/deny/modify/ask/defer) | `acs.decision` (span event) | `acs.decision`, `acs.evaluator`, `acs.reasoning` (when present), `acs.confidence` (when present) |
| `agbom/snapshot` | `acs.agbom` | `acs.agbom.format` (`canonical`/`cyclonedx`/`spdx`/`swid`), `acs.agbom.component_count` |
| `agbom/changed` | `acs.agbom` | `acs.agbom.format` (`canonical`/`cyclonedx`/`spdx`/`swid`), `acs.agbom.change_reason` |

When Provenance is attached to a hook payload, the resulting span MUST carry `acs.provenance.origin` as an attribute, and SHOULD carry `acs.provenance.source_id` and `acs.provenance.lineage_depth` when populated. v0.1 emits factual provenance attributes; trust classification is computed by the Guardian against local policy and is not a v0.1 span attribute (see [Specification §7](../instrument/specification.md#7-provenance)). Provenance lineage edges MAY be linked via OTel span links keyed by `provenance_id`.

## OCSF event classes

Each ACS step is representable as an OCSF event in the class shown below (OCSF 1.5+). Required class-specific attributes are populated from the ACS payload.

The full mapping lives in [`trace/ocsf-mapping.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/trace/ocsf-mapping.json). See [Extending OCSF](./extend_ocsf.md) for the deeper integration guide.

| ACS step | OCSF class | Class UID |
|---|---|---|
| `steps/sessionStart` | Authentication | 3002 |
| `steps/agentTrigger`, `steps/userMessage`, `steps/agentResponse` | Application Activity | 6002 |
| `steps/toolCallRequest`, `steps/toolCallResult` | Process Activity | 1007 |
| `steps/knowledgeRetrieval`, `steps/memoryStore`, `steps/memoryContextRetrieval` | Datastore Activity | 6005 |
| `steps/preCompact`, `steps/postCompact` | Datastore Activity | 6005 (compaction subtype) |
| `steps/subagentStart`, `steps/subagentStop` | Authentication | 3002 (logon/logoff for the subagent's session) |
| `steps/turnStart`, `steps/turnEnd` | Application Activity | 6002 |
| Decision (deny/modify/ask/defer) | Detection Finding | 2004 |
| `agbom/snapshot`, `agbom/changed` | Inventory Info | 5001 |
| `steps/sessionEnd` | Authentication | 3002 (logoff) |

OCSF `severity_id` for decision events is set from the disposition:

| Disposition | `severity_id` |
|---|---|
| `allow` | 1 (Informational) |
| `modify` | 2 (Low) |
| `ask` | 3 (Medium) |
| `defer` | 3 (Medium) |
| `deny` | 4 (High) |

## ACS-Trace conformance bar

A deployment claiming **ACS-Trace** MUST:

1. Emit at least one of {OTel, OCSF} for every ACS step the deployment supports, with the required attributes populated.
2. Record every decision as a Trace event carrying the disposition, evaluator identity, and reasoning when present.
3. Carry provenance facts forward from the hook payload onto the Trace event so audit replay reconstructs the policy decision without consulting Guardian state separately.

Trace events MUST NOT block enforcement — failure of the Trace sink MUST NOT change the disposition returned to the Observed Agent. Deployments that do not claim ACS-Trace SHOULD still emit Trace events where feasible; the vocabulary is normative regardless of profile claim.
