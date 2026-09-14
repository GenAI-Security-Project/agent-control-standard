# Extending OpenTelemetry

ACS reuses OpenTelemetry as the primary observability transport. Each ACS step becomes a span; each Guardian decision becomes a span event on the parent step span. The result is an end-to-end view of agent behavior — reasoning, retrieval, tool calls, decisions — already shaped to fit existing OTel-based tooling.

The normative span-name and required-attribute table is on the [Trace Events](./events.md) page. The machine-readable mapping lives at [`trace/otel-mapping.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/trace/otel-mapping.json). This page describes how to *use* the mapping in practice.

## Span hierarchy

A typical agent session produces a tree of spans:

- A root **session** span (`acs.session`) opened by `steps/sessionStart` and closed by `steps/sessionEnd`. Carries `acs.session.id` and (when set) `acs.tenant_id`.
- One **turn** span (`acs.turn`) per agent turn, opened by `steps/turnStart` and closed by `steps/turnEnd`. Carries `acs.turn.id`. Nested turns (e.g. subagent turns inside a parent turn awaiting `subagentStop`) record `acs.turn.parent_id`.
- One **step** span per `steps/*` hook, parented to the enclosing turn (or session when the step is session-level: `agentTrigger`, `agbom/*` outside a turn).
- Each **decision** is a span event on the step span carrying `acs.decision`, `acs.evaluator` (`deterministic` / `agent` / `composite`), `acs.reasoning` (when present), and `acs.confidence` (when present). Decisions are not separate spans because the verdict and the action it gates share a parent.

This hierarchy is deterministic — implementations that follow the mapping produce comparable traces across vendors and Guardians.

## Provenance attributes

When a hook payload carries Provenance, the resulting span MUST carry `acs.provenance.origin` and SHOULD carry `acs.provenance.source_id` and `acs.provenance.lineage_depth`. The set of provenance ids cited by a Guardian decision (the response envelope's `cited_provenance_ids`) MAY be expressed as OTel span links keyed by `provenance_id`, letting tools that index span links reconstruct the lineage graph without parsing payloads.

v0.1 emits factual provenance attributes only. Trust classification is computed by the Guardian against local policy and is not a v0.1 span attribute.

## Sensitive data

Attributes can carry user prompts, tool arguments, and retrieved knowledge. Implementations SHOULD apply the deployment's redaction or hashing policy at attribute-emit time rather than relying on backend-side scrubbing. The Guardian's `modifications.redactions` payload is the natural input to the policy: the same list that drives content rewriting drives attribute redaction.

## Transport

ACS does not redefine a trace transport. Implementations emit OTLP/gRPC or OTLP/HTTP to existing backends. The Guardian's handshake `trace_emission` field MAY advertise an OTLP collector endpoint; when set, the Observed Agent SHOULD route ACS-shaped trace traffic there in addition to (or instead of) its default collector.

## Failure isolation

Trace events MUST NOT block enforcement. If the Trace sink is unreachable or returns an error, the Guardian's disposition MUST still be returned to the Observed Agent. The agent's hot path is enforcement; observability is best-effort.
