# Hooks

ACS v0.1.0 defines 19 native `steps/*` hooks plus the wrapped `protocols/MCP/*` namespace, the Inspect-pillar `agbom/*` methods, and the `system/ping` liveness method. This page catalogs each hook: when it fires, the canonical schema, the disposition contract, and the audit-chain implications.

The full per-hook payload schemas live under [`specification/v0.1.0/hooks/`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/). Common envelope rules — `request_id`, `timestamp`, `acs_version`, `metadata`, signature handling, replay protection — are documented in [Specification §3](./specification.md#3-wire-format) and [§10.3](./specification.md#103-replay-protection).

## Overview

| Hook | When it fires | Decision-eligible | Audit-chain |
|---|---|---|---|
| [`sessionStart`](#sessionstart) | Session initiation | Yes | Root entry |
| [`agentTrigger`](#agenttrigger) | Agent activation by event/schedule | Yes | Yes |
| [`turnStart`](#turnstart) | Beginning of an agent turn | Yes (most return ALLOW) | Yes |
| [`userMessage`](#usermessage) | User input received | Yes | Yes |
| [`agentResponse`](#agentresponse) | Agent output before user delivery | Yes | Yes |
| [`knowledgeRetrieval`](#knowledgeretrieval) | RAG / knowledge lookup | Yes | Yes |
| [`memoryContextRetrieval`](#memorycontextretrieval) | Memory read | Yes | Yes |
| [`memoryStore`](#memorystore) | Memory write | Yes | Yes |
| [`toolCallRequest`](#toolcallrequest) | Before tool execution | Yes | Yes |
| [`toolCallResult`](#toolcallresult) | After tool execution, before agent ingestion | Yes | Yes |
| [`preCompact`](#precompact) | Before context-window compaction | Yes | Yes |
| [`postCompact`](#postcompact) | After compaction; carries new summary | No (audit + lineage binding) | Yes |
| [`subagentStart`](#subagentstart) | In-process subagent spawned | Yes | Yes |
| [`subagentStop`](#subagentstop) | Subagent terminated | No | Yes |
| [`skillRegister`](#skillregister) | Skill enters the available set, before it can load | Yes | Yes |
| [`skillLoad`](#skillload) | Registered skill activates into a session, before its actions run | Yes | Yes |
| [`skillUnload`](#skillunload) | Skill leaves the active set | No (audit) | Yes |
| [`turnEnd`](#turnend) | End of an agent turn | No (audit) | Yes |
| [`sessionEnd`](#sessionend) | Session termination | No (audit finalization) | Yes |
| [`agbom/snapshot`](#agbomsnapshot) | Full AgBOM, once per session | Yes (banned components) | Yes |
| [`agbom/changed`](#agbomchanged) | Mid-session AgBOM mutation | Yes | Yes |
| [`system/ping`](#systemping) | Liveness probe | Always ALLOW | No |
| `protocols/MCP/*` | Wrapped MCP messages | Yes | Yes |

`protocols/A2A/*` is reserved for v0.2. The namespace is recognized in the handshake's `wrapped_protocols` for forward compatibility, but no normative wrapping semantics are defined in v0.1.

## Common envelope

Every native hook uses the standard request envelope from [`request-envelope.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/request-envelope.json):

```json
{
  "jsonrpc": "2.0",
  "method": "steps/<hook>",
  "id": "<jsonrpc-id>",
  "params": {
    "acs_version": "0.1.0",
    "request_id": "<uuid>",
    "timestamp": "<iso-8601>",
    "tenant_id": "<optional>",
    "metadata": {
      "agent_id": "<id>",
      "session_id": "<uuid>",
      "turn_id": "<id-when-inside-a-turn>"
    },
    "payload": { /* hook-specific */ },
    "signature": { "algorithm": "...", "value": "...", "key_id": "..." }
  }
}
```

The decision envelope shape is documented in [Specification §6](./specification.md#6-disposition-vocabulary) and [`response-envelope.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/response-envelope.json).

---

## sessionStart

Schema: [`hooks/session-start.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/session-start.json).

Fires once per session, after the `handshake/hello` exchange completes and before any other `steps/*` hook for the same `session_id`. Establishes the audit chain root (`previous_hash: null`), session-level identity and policy bindings, and the initial `Intent` (when IBAC is the enforcement paradigm).

**Payload:** session-level identity descriptors, declared policy mode, `intent` (optional, with `parser_provenance`), platform context.

**Decision:** ALLOW / DENY. A Guardian MAY refuse a session whose identity, policy mode, or platform fails policy checks; this is the cleanest place to refuse before content enters.

A deployment that does not emit `sessionStart` MAY allow the Guardian to implicitly initialize the chain at the first content-bearing hook, but this is discouraged because it leaves no place to attach session-level Intent before content enters.

---

## agentTrigger

Schema: [`hooks/agent-trigger.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/agent-trigger.json).

Fires when the agent is activated by an external triggering condition (event arrival, scheduled tick, A2A inbound message, user-initiated session, or system-issued activation). For A2A-mediated delegation, `trigger_type: "a2a_inbound"` carries the originating peer identity; for in-process subagent spawns, see [`subagentStart`](#subagentstart).

**Payload:** `trigger_type` (`user_message`, `scheduled`, `external_event`, `a2a_inbound`, `system`), `trigger_source` (shape depends on `trigger_type`), optional `intent` (IBAC adopters populate; the Intent registered at sessionStart, carried here for activation-time policy checks).

**Decision:** ALLOW / DENY / MODIFY. Guardian MAY rewrite the trigger payload (e.g. redact PII) before activation.

---

## turnStart

Schema: [`hooks/turn-start.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/turn-start.json).

Lightweight hook marking the start of an agent turn. Many policies key on per-turn state — "deny consequential actions in any turn after a turn that retrieved untrusted data," "limit tool-call count per turn," "reset cumulative-taint at turn boundary." Without an explicit turn boundary, every Guardian rolls its own heuristic for inferring turn breaks (usually pairing `userMessage` with the next `agentResponse`), and the heuristics don't agree under auto-continuation, planning loops, and multi-step ReAct cycles.

`turn_id` is added to the request envelope's `metadata` block and propagated onto every per-step ContextEntry between `turnStart` and `turnEnd`. AARM-style "no consequential action in N turns after taint" becomes computable from the audit chain in O(1) per check.

**Payload:** `turn_id`, `triggered_by` (`user_message`, `auto_continuation`, `agent_loop`, `subagent_return`), optional `parent_turn_id` for nested turns.

**Decision:** Decision-eligible — a Guardian MAY deny to block the turn from starting — but most deployments will return ALLOW and use the hook for state transitions in policy.

---

## userMessage

Schema: [`hooks/user-message.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/user-message.json).

Fires when external user input arrives, before it is presented to the agent's reasoning context. Provenance: `origin: user_input`.

**Payload:** message content, optional citation/sources, user context.

**Decision:** ALLOW / DENY / MODIFY. Guardian MAY redact content before delivery to the agent.

---

## agentResponse

Schema: [`hooks/agent-response.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/agent-response.json).

Fires after the agent has produced a response, before it is delivered to the recipient (user, A2A peer, parent agent, or external system). Provenance: `origin: agent_generated` with `derived_from` set to whatever inputs the response is derived from.

**Payload:** response content, optional sources/citations, agent reasoning.

**Decision:** ALLOW / DENY / MODIFY.

---

## knowledgeRetrieval

Schema: [`hooks/knowledge-retrieval.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/knowledge-retrieval.json).

Fires when the agent retrieves external knowledge (RAG, vector search, knowledge base lookup). Provenance: `origin: retrieved`, with `source_id` identifying the index or knowledge source.

**Payload:** `query`, `keywords`, retrieved results (each with content, mime type, source id).

**Decision:** ALLOW / DENY / MODIFY. Guardian MAY redact retrieved content before injection into the agent context.

---

## memoryContextRetrieval

Schema: [`hooks/memory-context-retrieval.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/memory-context-retrieval.json).

Memory read — long-term, session-scoped, or user-scoped — into the agent's working context. Provenance: `origin: retrieved`, `source_id` identifies the memory store.

**Payload:** memory entries pulled into context.

**Decision:** ALLOW / DENY / MODIFY.

---

## memoryStore

Schema: [`hooks/memory-store.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/memory-store.json).

Memory write. The standard sink for cross-session influence; mediating it prevents memory poisoning.

**Payload:** entries to be written, target store, scope (`session`/`user`/`tenant`/`global`), TTL.

**Decision:** ALLOW / DENY / MODIFY.

---

## toolCallRequest

Schema: [`hooks/tool-call-request.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/tool-call-request.json).

Fires after the framework has parsed a tool call from the LLM's output, but before the tool is dispatched to its handler. The central enforcement point for IBAC, FIDES, CaMeL, and AARM. Argument-level provenance attached to each `ToolArgumentValue` lets Guardians reason about the lineage of individual arguments, so policy can target specific data flows rather than the call as a whole.

Frameworks MUST fire `toolCallRequest` for every action that escapes the agent's reasoning context, regardless of whether the framework's tool registry models it as a tool. This includes built-in operations such as filesystem reads/writes, network fetches, process execution, and shell commands. The Guardian relies on a complete view of all outward actions; primitives that bypass `toolCallRequest` are invisible to policy.

**Payload:** `tool` (id, capability), `arguments` (each value carrying optional Provenance), agent reasoning.

**Decision:** ALLOW / DENY / MODIFY / ASK / DEFER. The full disposition vocabulary applies — this is the hook where most paradigm composition happens.

---

## toolCallResult

Schema: [`hooks/tool-call-result.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/tool-call-result.json).

Fires after tool execution, before the result is ingested into the agent's reasoning context. Provenance: `origin: tool_output`, with `derived_from` set to the originating `toolCallRequest`'s provenance ids when the tool's output is data-derived.

**Payload:** `execution_id` (correlated to the request), outputs, exit status, duration.

**Decision:** ALLOW / DENY / MODIFY.

---

## preCompact

Schema: [`hooks/pre-compact.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/pre-compact.json).

Fires before context-window compaction. Compaction is the chokepoint where provenance can be laundered: when the runtime LLM compresses a long context window into a summary, the post-compaction text is new `agent_generated` content whose `derived_from` lineage spans every untrusted item that was in the pre-compaction context. Without an explicit hook, the framework has no clean place to attach the rule that *the compacted summary's lineage is the union of all summarized entries' lineage*. AARM cumulative-context tracking breaks across compaction without it, FIDES's monotonicity claim is unverifiable, and Guardians cannot enforce "don't compact across a trust boundary" policies.

**Payload:** `entries_to_compact` (array of `step_id`s that will be summarized), pre-compaction `provenance_summary` (so the Guardian can see what it's about to lose), `triggered_by` (`size_threshold`, `manual`, `agent_initiated`).

**Decision:** Decision-eligible. Guardian MAY return DENY to block compaction (e.g. because deployment policy disallows compacting after `untrusted` data has entered until a trusted re-grounding occurs).

---

## postCompact

Schema: [`hooks/post-compact.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/post-compact.json).

Fires after compaction. Audit + provenance-binding hook.

**Payload:** resulting `summary` content with `provenance` whose `origin` MUST be `agent_generated` and whose `derived_from` MUST equal the union of `provenance_id`s of every entry in `entries_compacted`. The framework — not the LLM — populates `derived_from`.

**Decision:** Not decision-eligible — compaction has already occurred. A Guardian MAY return MODIFY (rewrite the summary, e.g. to redact a region the policy can't compact), but MAY NOT return DENY. The audit chain MUST record the post-compact state regardless.

---

## subagentStart

Schema: [`hooks/subagent-start.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/subagent-start.json).

In-process delegation — a parent agent spawning a subagent within the same runtime, with no A2A boundary crossed — needs an explicit lifecycle event. A2A-mediated delegation already flows through [`agentTrigger`](#agenttrigger) with `trigger_type: a2a_inbound` on the subagent's side; `subagentStart` is for the same-runtime case.

This matters for IBAC: when a subagent spawns, the audit chain must record whether it inherits the parent's `Intent.parsed`, gets a derived intent, or starts fresh — and whether subsequent operations are checked against the parent's, the subagent's, or both Intents. The composition case (IBAC outer + CaMeL inner) is precisely the case this hook handles.

**Payload:** `subagent_session_id` (a fresh `session_id` distinct from the envelope's parent `session_id`), `parent_session_id`, `parent_step_id` (the originating step that triggered the spawn), `intent_derivation` (`inherit_full` / `inherit_subset` / `derived_from_parent` / `fresh`), `subagent_intent` (the new Intent for the subagent, with `parser_provenance`).

**Decision:** Decision-eligible. Guardian MAY DENY — refuse the subagent spawn, e.g. because the `intent_derivation` would grant capabilities the parent's `Intent.parsed` does not authorize.

Each subagent has its own SessionContext and audit chain; the parent–child relation is captured in the `subagentStart` payload.

---

## subagentStop

Schema: [`hooks/subagent-stop.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/subagent-stop.json).

**Payload:** `subagent_session_id`, `outcome` (`completed`, `failed`, `cancelled`), the subagent's `final_chain_hash`, optional `summary` of what was returned to the parent. The summary's `provenance` follows the standard monotonicity rule.

**Decision:** Audit only.

---

## skillRegister

Schema: [`hooks/skill-register.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/skill-register.json).

Fires when a skill enters the agent's available set, before it is eligible to load or run. This is the static vetting gate: the one point where a Guardian sees the whole skill definition before any of its actions execute. A payload split across a skill's actions is benign at each action and malicious only in composition, so it escapes per-action hooks like [`toolCallRequest`](#toolcallrequest); `skillRegister` is where the whole definition is inspected.

A skill is the loadable, composed counterpart to the passive `agent_capability` grouping. It is cataloged as a `skill` AgBOM component carrying its composition references, a least-privilege capability manifest, and the definition's reference and integrity digest. The `ref` and `digest` commit to the complete loadable artifact, including any bundled model weights or adapters, not only text. This matters for a model-bearing skill whose backdoor lives in opaque weights rather than any readable instruction: source inspection cannot see it, so the control is the digest plus `registration_provenance`, not body reading. The full definition body travels in this payload for inspection but is NOT persisted to the AgBOM; only the `ref` and `digest` persist. The approval recorded here is keyed on the `(skill_id, digest)` pair, which `skillLoad` is later checked against. Marketplace pre-publication scanning and publisher reputation are out of scope; ACS surfaces the definition, provenance, and manifest so the Guardian's policy can act.

**Payload:** `skill_id`, `definition` (`ref`, `digest`, optional `body` for inspection), `declared_capabilities`, optional `composition` (`tools`/`mcp_servers`/`a2a_peers`/`models`/`composed_skills`), `registration_provenance`. A model-bearing skill lists its bundled model under `composition.models` so the AgBOM inventories it as a `model` component with its own provenance, rather than leaving the weights opaque inside the definition.

**Decision:** ALLOW / DENY. A Guardian MAY deny registration; a denied skill MUST NOT become eligible to load. A Guardian SHOULD compare `declared_capabilities` against the union of capabilities the composed tools expose and MAY deny over-broad declarations.

---

## skillLoad

Schema: [`hooks/skill-load.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/skill-load.json).

Fires when a registered skill activates into a session, before its actions run. Where `skillRegister` vets the artifact once and statically, `skillLoad` governs each activation in live context. It carries the load path, the ordered list of skills that led to the current load, so a Guardian can see and contain inter-skill cascades (skill A loads B loads C, each clean alone).

`skillLoad` carries the `digest` of the artifact being loaded so the Guardian binds the activation to an approved registration. A load MUST be correlatable to a prior approved `skillRegister` for the same `(skill_id, digest)`; one the Guardian cannot tie to an approved registration, or whose digest differs from the approved one, is unverifiable and SHOULD be denied. Without this binding the gate is bypassable: a framework could emit `skillLoad` for an artifact that was never registered, or whose registration was denied. The framework MAY send a `digest_verified` hint, but a Guardian verifies the binding itself by comparing `digest` against its record of the approved registration rather than trusting the flag, since a compromised framework could assert it falsely.

When a load is triggered by another skill, `load_trigger` is `skill_composition` and `load_path` carries more than one element.

**Payload:** `skill_id`, `digest` (`algorithm`, `value`), `load_trigger` (`user`/`agent_decision`/`skill_composition`/`system`), `load_path` (ordered `{skill_id, step_id?}`, root first), optional `registration_ref`, optional `parent_step_id`, optional `digest_verified`, optional `declared_capabilities`.

**Decision:** ALLOW / DENY. A Guardian SHOULD deny a load it cannot correlate to an approved `skillRegister` for the same `(skill_id, digest)`, SHOULD deny when `load_path` shows a skill loading another outside its declared `composed_skills`, and SHOULD deny when the loaded artifact's digest does not match the one vetted at `skillRegister`.

---

## skillUnload

Schema: [`hooks/skill-unload.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/skill-unload.json).

Fires when a skill leaves the active set. Its enforcement value is low: by unload time the skill's actions have already run, so a Guardian typically observes rather than denies. It keeps the AgBOM's active inventory accurate, and repeated load/unload churn of the same skill is itself a signal worth tracing.

**Payload:** `skill_id`, `reason` (`session_end`/`explicit_unload`/`replaced`/`error`), optional `replaced_by`.

**Decision:** Audit only.

---

## turnEnd

Schema: [`hooks/turn-end.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/turn-end.json).

**Payload:** `turn_id`, `outcome` (`completed`, `deferred`, `error`), `step_count`, optional `summary`.

**Decision:** Not decision-eligible — the turn has already happened.

---

## sessionEnd

Schema: [`hooks/session-end.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/session-end.json).

Session termination, audit finalization. The Guardian seals the chain at this point.

**Payload:** `session_reason` (`completed`, `cancelled`, `error`, `timeout`), final aggregates.

**Decision:** Audit only.

---

## agbom/snapshot

Schema: [`hooks/agbom-snapshot.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/agbom-snapshot.json).

Inspect-pillar method. Fires once per session, after `sessionStart` and before `agentTrigger` (the first content-bearing hook), and again after handshake-renegotiation. Carries the full AgBOM (the Observed Agent's component graph: models, MCP servers, A2A peers, tools, knowledge sources, memory stores, agent capabilities, skills).

**Decision:** Normally ALLOW. Guardian MAY DENY to refuse a session whose component graph contains a banned model, tool, or peer.

See the [Inspect pillar](../inspect/README.md) for the full AgBOM schema and serialization mapping.

---

## agbom/changed

Schema: [`hooks/agbom-changed.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/agbom-changed.json).

Inspect-pillar method. Fires whenever a component is added, removed, or version-changed mid-session. Carries either a full snapshot or a diff (`added[]`, `removed[]`, `changed[]`).

**Decision:** ALLOW / DENY. Guardian MAY DENY to block a hot-swap; otherwise audited.

`agbom/changed` is part of the **ACS-Inspect-Dynamic** profile extension. Deployments claiming the base **ACS-Inspect** profile (snapshot only) are not required to emit it.

---

## system/ping

Schema: [`hooks/system-ping.json`](https://github.com/afogel/ACS_official/blob/dev/specification/v0.1.0/hooks/system-ping.json). See [Specification §13](./specification.md#13-liveness-system-methods).

> **Note:** `system/ping` is in the `system/*` namespace, not `steps/*`. It is not a hook in the enforcement sense: it carries no audit and bypasses signature requirements.

Liveness probe. Always returns `decision: "allow"` regardless of policy, signature, or session state. NOT written into SessionContext. NOT subject to signature requirements even when the session otherwise requires signatures.

---

## protocols/MCP/\*

See [Extending MCP](./extend_mcp.md). Wrapped MCP messages flow through `protocols/MCP/*` (e.g. `protocols/MCP/initialize`, `protocols/MCP/tools/call`, `protocols/MCP/prompts/get`, `protocols/MCP/resources/read`). The wrapped methods carry the underlying MCP message intact and apply the standard ACS envelope, decision contract, and audit-chain rules on top. Deployments that only need transport-agnostic tool governance MAY collapse MCP tool calls into `steps/toolCallRequest`; deployments that need MCP-specific policy precision use this namespace to preserve distinctions such as capability negotiation, prompt fetches, resource reads/subscriptions, and notifications.
