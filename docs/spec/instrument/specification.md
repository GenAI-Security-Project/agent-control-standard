# ACS v0.1.0 — Instrument Specification

**Version:** `0.1.0`

The Instrument pillar covers real-time interception, evaluation, and enforcement of agent behavior. It defines the wire format, the capability-negotiation handshake, the hook taxonomy, the disposition vocabulary, the SessionContext and Intent model, replay protection, and signature semantics. Trace (event emission) and Inspect (AgBOM) are co-equal v0.1.0 pillars covered in their own pages.

A deployment that implements **ACS-Core** (this section's mandatory baseline) is v0.1.0-conformant. Additional capabilities (Trace event emission, AgBOM serialization, field-level provenance, cryptographic signatures, strengthened audit chains) are organized as **conformance profiles** (see [Conformance](../conformance.md)).

## 1. Design Principles

1. **Opinionated on contract, permissive on implementation.** The wire format and semantics are locked. Engines, crypto suites, OS, and transport are deployment-owned.
2. **The agent MUST NOT have knowledge of hooks.** Provenance fields, when emitted, MUST be populated outside the LLM's output path.
3. **Facts on the wire; classification in policy.** Provenance fields (`origin`, `source_id`, `derived_from`) are populated by deterministic framework code at channel boundaries, never by the LLM. v0.1 keeps trust *classification* off the mandatory wire surface: Guardians derive trust from `origin` + `source_id` against local policy. The wire format reserves an OPTIONAL `trust` enum for vendor implementations that elect to carry the classification in the envelope; when populated, the monotonicity rule applies (§7).
4. **Three pillars, tiered conformance.** Instrument, Trace, and Inspect are all defined in v0.1.0. None is deferred. ACS-Core is the mandatory baseline; Trace, Inspect, Provenance, Crypto, and Audit are normative profiles deployments advertise via handshake negotiation.

## 2. Architecture

Two parties on the wire:

- **Observed Agent**: the LLM-backed system being monitored. Implements ACS endpoints (or the stdio analog) and sends hook traffic to the Guardian.
- **Guardian Agent**: the policy enforcement point. Two internal layers:
    - **Deterministic layer** (Cedar/Rego): always runs first.
    - **Agent layer** (LLM): invoked only when the deterministic layer's chain config delegates (`*`, `on_ask`, or pattern-based).

### 2.1 End-to-end flow

```
Observed Agent                                Guardian Agent
══════════════                                ══════════════
     │                                              │
     │ 1. Hook fires; framework builds JSON-RPC      │
     │ 2. Send (HTTP POST or stdio write)            │
     ├──────────────────────────────────────────────>│
     │                                              │ 3. Validate envelope, signature, replay
     │                                              │ 4. Load SessionContext, Intent
     │                                              │ 5. Deterministic layer evaluates
     │                                              │ 6. If delegated, agent layer reasons
     │                                              │ 7. Build decision envelope
     │ 8. Receive response                           │
     │<──────────────────────────────────────────────┤
     │ 9. Enforce decision (allow/deny/modify/ask/defer)
     │ 10. Audit entry written to SessionContext
```

A worked example appears in [ACS in Action](../../topics/ACS_in_action_example.md).

## 3. Wire Format

| Element | Choice |
|---|---|
| Envelope | JSON-RPC 2.0, with top-level `acs_version` |
| Transports | HTTP(S) and stdio (Content-Length framing, UTF-8) |
| Method namespaces | `steps/*`, `protocols/A2A/*`, `protocols/MCP/*`, `agbom/*`, `system/*`, `handshake/*`, `trace/*` (reserved) |
| Wrapped methods | `protocols/MCP/*` is the canonical v0.1 namespace for MCP wrapping (e.g. `protocols/MCP/tools/call`). The `wrapped:` prefix is an alternative explicit-version form for deployments that pin a specific protocol version on the wire (e.g. `wrapped:mcp-2025-06-18/tools/call`). Both are valid; `protocols/*` is preferred. A2A wrapping deferred to v0.2. |
| Error code range | `-32000` to `-32099` reserved for ACS |
| Response shape | Discriminated union: `{ "type": "final", ... }` |
| Forward compat | Accept `X.Y.Z` matching major version; ignore unknown fields |

Streaming and notifications are not supported in v0.1.0. Batching is permitted as standard JSON-RPC 2.0 — Guardians SHOULD accept array-shaped requests and return an array of correlated responses, but ACS does not add atomicity, ordering, or cross-request dependency semantics in v0.1. Each request in a batch is evaluated independently, in declared order, with each carrying its own `request_id` and (if signed) its own signature. A Guardian that does not support batching MUST return `-32600 Invalid Request` for array-shaped inputs so the Observed Agent can fall back to sequential requests.

The full envelope schemas are [`request-envelope.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/request-envelope.json) and [`response-envelope.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/response-envelope.json).

## 4. Capability Negotiation Handshake

Required at session start, before any hook traffic. Wire method: `handshake/hello`. Schema: [`handshake.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/handshake.json) (`$defs/ClientHello` and `$defs/ServerHello`).

**Observed Agent → Guardian Agent (ClientHello):** `acs_versions_supported`, `methods_implemented`, `transports_supported`, `max_payload_size_bytes`, `provenance_producer`, `wrapped_protocols`, `profiles_supported` (conformance profiles the client implements; see [Conformance](../conformance.md)).

**Guardian Agent → Observed Agent (ServerHello):** `negotiated_version`, `methods_evaluated`, `selected_transport`, `signature_algorithms_supported`, `timeout_config` (default and per-method), `on_decision_failure` (failure posture, §6.4), `skew_window_ms` (request-timestamp skew tolerance for replay protection, §10.3), `approver_types_supported`, `policy_requires_provenance`, `agbom_serializations_supported` (Inspect-pillar serialization formats the Guardian renders on request), `trace_emission` (whether the Guardian emits OTel and/or OCSF for the Trace pillar, plus optional OTLP collector endpoint), `profiles_accepted`.

Version mismatch terminates with `UNSUPPORTED_VERSION` (`-32001`, §17.1). Unknown fields MUST be ignored. If the client declares `provenance_producer: "none"` and the Guardian's `policy_requires_provenance` is true, the Guardian MUST refuse the session at handshake time with `PROVENANCE_REQUIRED` (`-32002`, §17.1) rather than silently degrading enforcement.

### 4.1 Handshake failure (normative)

`on_decision_failure` is negotiated in the handshake, so it cannot govern a handshake that never completes. When `handshake/hello` fails — the Guardian is unreachable, silent past the deployment's connection timeout, or errors without producing a ServerHello — the Observed Agent applies its **startup posture**, configured out of band: `proceed` starts the session unguarded, `refuse` does not start it. The default is `proceed`, matching `on_decision_failure`, so a Guardian outage does not block new sessions.

A Guardian that answers with a refusal (`SESSION_REFUSED`, `UNSUPPORTED_VERSION`, `PROVENANCE_REQUIRED`) has decided; the startup posture applies only when no answer arrives. A session started unguarded MUST be recorded in the deployment's own audit log — there is no Guardian to receive the event — and SHOULD be surfaced on Trace events when the deployment claims ACS-Trace. The Observed Agent SHOULD retry the handshake for subsequent sessions. Whether a Guardian can attach mid-flight to a session that started unguarded is undefined in v0.1; renegotiation is deferred to v0.2 alongside `system/handshake_renegotiate` (§13).

## 5. Hook Taxonomy

Hook details, payloads, and per-hook examples are catalogued on the [Hooks](./hooks.md) page. The native `steps/*` set is:

| # | Method | Trigger |
|---|---|---|
| 1 | `sessionStart` | Session initiation, before any other `steps/*` hook for the `session_id` |
| 2 | `agentTrigger` | Agent activation |
| 3 | `turnStart` | Beginning of an agent turn |
| 4 | `userMessage` | User input received |
| 5 | `agentResponse` | Agent output before reaching the user |
| 6 | `knowledgeRetrieval` | RAG / knowledge lookup |
| 7 | `memoryContextRetrieval` | Memory read |
| 8 | `memoryStore` | Memory write |
| 9 | `toolCallRequest` | Before tool execution |
| 10 | `toolCallResult` | After tool execution, before agent ingestion |
| 11 | `preCompact` | Before context-window compaction; decision-eligible |
| 12 | `postCompact` | After compaction; carries the new summary's payload and provenance |
| 13 | `subagentStart` | A subagent is spawned (in-process delegation) |
| 14 | `subagentStop` | A subagent has terminated |
| 15 | `skillRegister` | Skill enters the available set, before it can load; decision-eligible |
| 16 | `skillLoad` | Registered skill activates into a session, before its actions run; decision-eligible |
| 17 | `skillUnload` | Skill leaves the active set |
| 18 | `turnEnd` | End of an agent turn |
| 19 | `sessionEnd` | Session termination, audit finalization |

Wrapped: `protocols/MCP/*` (specified in v0.1; see [Extending MCP](./extend_mcp.md)). The `protocols/A2A/*` namespace is reserved; wrapping specification deferred to v0.2.

Inspect-pillar methods (`agbom/*`): `agbom/snapshot` and `agbom/changed` (see [Inspect](../inspect/README.md)). System methods (`system/*`): `system/ping` (§13). These are not Instrument hooks (they're the wire surface for Inspect and transport-control) but they share the request-envelope shape, and `agbom/*` participates in the SessionContext audit chain.

## 6. Disposition Vocabulary

| Disposition | Meaning | Required fields |
|---|---|---|
| `ALLOW` | Proceed | none (`reasoning` RECOMMENDED when user-visible audit trails are expected) |
| `DENY` | Block | `reasoning` |
| `MODIFY` | Proceed with changes (covers redaction via `modifications.redactions`; composition rules in [§6.3](#63-modify-composition-normative)) | `reasoning`, `modifications` |
| `ASK` | Pause and request approval (substituted with `DEFER` or `DENY` for approver-incapable clients; see [§9.2](#92-approver-incapable-clients-normative)) | `reasoning`, `ask_details` |
| `DEFER` | Verdict not yet reachable | `reasoning`, `defer_details` |

DEFER reasons: `insufficient_context`, `conflicting_policies`, `low_confidence`, `pending_dependency`. DEFER MUST include `resolution_method`, `resolution_timeout_ms`, and `timeout_decision` (default `deny`). Cascading deferrals MUST be bounded per session.

`timeout_decision` defaulting to `deny` is deliberately the opposite of `on_decision_failure` defaulting to `proceed` (§6.4). An expired DEFER is a Guardian that flagged a concern and failed to resolve it, not one that never answered: a degraded Guardian that can still emit DEFER fails closed where a silent one fails open.

### 6.1 Decision result fields

The decision envelope ([`response-envelope.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/response-envelope.json)) carries a fixed set of fields that compose to support audit, observability, and cross-paradigm enforcement:

| Field | Required | Purpose |
|---|---|---|
| `decision` | yes | The verdict, one of the five dispositions above. |
| `reasoning` | conditional | Single human-renderable explanation. Serves both end-user display and audit/agent-internal consumption; deployments wanting different text per audience SHOULD compose them client-side from `reasoning` + `policy_data` + `reason_codes`. |
| `policy_references` | no | Array of `{policy_id, policy_version, policy_name, rule_id}`, the rules that fired. `policy_version` is OPTIONAL and deployment-defined, but SHOULD be populated when replay or ledger-backed policy state matters. A single decision MAY cite multiple entries when several paradigms reject the same action; audit replay walks the list to reconstruct contributions. |
| `reason_codes` | no | Array of machine-readable categorization strings. Free vocabulary in v0.1. UIs and meta-policies SHOULD switch on these rather than parsing reasoning text or rule IDs. |
| `policy_data` | no | Free-form structured payload for paradigm- or policy-specific facts. When multiple paradigms fire, conventionally keyed by paradigm name (`{ "ibac": {...}, "fides": {...}, "aarm": {...} }`). |
| `cited_provenance_ids` | no | Array of `provenance_id`s whose facts drove this decision. Standard top-level surface for "which provenance objects mattered". |
| `modifications` / `ask_details` / `defer_details` | conditional | Disposition-specific payloads. |
| `metadata` | no | ACS-defined evaluator/observability metadata: `evaluator` (`deterministic`/`agent`/`composite`), `evaluator_version`, `evaluation_duration_ms`, `model_id` (required when `evaluator` is `agent` or `composite`), `confidence`. NOT for policy-emitted facts — those go in `policy_data`. |

### 6.2 Paradigm composition

These fields support the v0.1 paradigm targets (FIDES, CaMeL, AARM-style cumulative-context, IBAC) without per-paradigm wire extensions. A FIDES P-T denial cites the violating lineage in `cited_provenance_ids` and exposes the violating-argument path in `policy_data`. An IBAC intent-mismatch DEFER routes through `defer_details` while exposing the requested capability and closest `Intent.parsed` match in `policy_data`. An AARM cumulative-context denial cites `earliest_untrusted_step_id` in `cited_provenance_ids` and reproduces the relevant lookback state in `policy_data`. When a deployment composes paradigms (e.g., IBAC outer + FIDES inner across an A2A boundary) a single decision MAY cite all of them: `policy_references` with one entry per paradigm, `reason_codes` with one or more codes per paradigm, `policy_data` keyed by paradigm.

### 6.3 MODIFY composition (normative)

`modifications` carries one of two mutually exclusive shapes:

- **Wholesale replacement.** `modified_content` replaces the entire payload. It is exclusive: a MODIFY that carries `modified_content` MUST NOT also carry `redactions` or `parameter_overrides`, because path-addressed edits have nothing to address inside an opaque replacement string.
- **Structured edits.** `redactions` and `parameter_overrides` MAY appear together, but their targets MUST be disjoint: no `redactions` path may address the same field as a `parameter_overrides` key, nor an ancestor or descendant of it. Disjoint edits commute, so the effective payload is well-defined with no apply-order rule.

A Guardian MUST NOT emit a `modifications` object that violates either rule. An Observed Agent that receives one cannot determine the Guardian's intent and MUST fail closed, treating the decision as `DENY`, and SHOULD record an audit event.

The disjoint-target rule is deliberately narrower than a precedence rule. A fixed apply-order would force every overlap to silently pick a winner, and either order has a failure mode: applying overrides last can re-expose a field a redaction just removed, and applying redactions last lets arbitrary replacement text overwrite a value an override deliberately sanitized. Requiring disjoint targets removes the conflict rather than resolving it by an order the Guardian cannot observe.

The provenance of a value introduced by `parameter_overrides` (its `origin`, and whether a Guardian may raise the trust of data it rewrites) is a separate question deferred to a later version alongside the audit-chain integrity work. v0.1 defines no Guardian-injected `origin`.

### 6.4 Honoring decisions (normative)

A hook is a control point only if the Observed Agent waits for the verdict and applies it. For every step it submits, the Observed Agent MUST wait for the Guardian's decision, up to the negotiated timeout (`timeout_config`, §4), and MUST apply it: `ALLOW` proceeds, `DENY` blocks the action, `MODIFY` proceeds with the modified payload (§6.3), `ASK` pauses for approval, `DEFER` suspends pending resolution. A framework that emits hooks but proceeds without applying the verdict is not conformant.

A step suffers a **decision failure** when no usable decision arrives within the negotiated timeout: the Guardian stays silent, the transport fails (connection refused, TLS failure, malformed response), or the Guardian returns an error instead of a decision. All three resolve the same way: the Observed Agent applies the deployment's failure posture, declared as `on_decision_failure` in the handshake (§4) and defaulting to `proceed` (fail-open) so that a slow, erroring, or unreachable Guardian does not halt production. A deployment MAY set `on_decision_failure: deny` (fail-closed). The negotiated timeout bounds every failure mode: an error from the §17.1 registry carries a recovery action the agent MAY attempt within the remaining budget, and an unambiguous failure (a refused connection) MAY resolve immediately rather than waiting out the clock.

Every step that proceeds without a decision MUST be recorded as an audit event, so the bypass is visible rather than silent. When a decision does arrive within the timeout, the agent MUST honor it regardless of the posture. Fail-open trades enforcement for availability under disruption: an adversary who can disrupt the channel converts control into audit. Deployments for which that trade is unacceptable set `on_decision_failure: deny`.

## 7. Provenance

The Provenance concept and its fields are defined in [Concepts › Provenance](../../concepts/provenance.md) (normative). This section specifies the wire shape and the v0.1 trust-classification stance.

Provenance attaches to data-bearing fields (`Message.content`, `KnowledgeRetrievalResult`, `ToolCallResult.outputs`, `ToolArgumentValue`, A2A payload). Whether it is present is governed at the session level by the handshake's `provenance_producer` (§4), not chosen per field at emit time:

- Under **`deterministic`**, the producer MUST attach a Provenance object to **every** data-bearing field in every hook payload it emits. Partial population within a producing session is non-conformant: provenance is all-or-nothing per session. This is the conformance bar for the **ACS-Provenance** profile.
- Under **`none`**, the producer emits no Provenance objects. A Guardian whose policy requires provenance MUST refuse such a session at handshake time (§4) rather than accept provenance-free payloads.

The base hook payload schemas therefore mark `provenance` OPTIONAL so that ACS-Core (pure IBAC and other paradigms that need no information-flow tracking) validates. Deployments claiming ACS-Provenance validate payloads against the strict `*.acs-provenance.json` variant of each data-bearing hook, which restores `provenance` to the required set. When a Provenance object is emitted, all of its own required fields MUST be populated. Schema: [`provenance.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/provenance.json).

| Field | Required | Type | Notes |
|---|---|---|---|
| `provenance_id` | yes | string | Unique within session |
| `origin` | yes | enum | `user_input`, `system`, `tool_output`, `retrieved`, `agent_generated`, `a2a_inbound`, `external` |
| `source_id` | no | string | Identifier within origin |
| `derived_from` | no | string[] | Lineage: array of `provenance_id`s |

### 7.1 Optional `trust` enum

The wire format reserves an OPTIONAL `trust` enum (`trusted`, `untrusted`, `unknown`) so vendor Guardian implementations can carry channel classification in the envelope rather than derive it in policy. v0.1 does not require Guardians to populate it. The expected v0.1 default is for Guardians to derive trust from `origin` + `source_id` against local policy: it keeps the wire format minimal, avoids creating labeled-trusted regions that downstream code stops scrutinizing, and prevents optional-field defaults from ossifying into a de-facto security model. Reserving the field on the wire preserves the option to populate it in a future version (or in a vendor extension today) without a wire-format break.

When a deployment **does** populate `trust`:

- The framework, not the LLM, MUST attach the label, deterministically, based on which channel data crossed. `trust` is never a content judgment and never a producer claim.
- For data with `origin: agent_generated`, the framework MUST compute `trust` as the minimum trust of the entries in `derived_from` (monotonicity rule). No amount of LLM processing launders untrusted data into trusted data.
- Receivers (especially across A2A or multi-Guardian boundaries) MUST treat the field as a hint and re-derive trust against local policy keyed off `origin` + `source_id` rather than honor a remote-asserted label at face value.

### 7.2 Default channel-to-trust mapping

Used both by Guardians that derive trust in policy and by vendor implementations that populate `trust` on the wire. Deployments MAY override in policy but SHOULD record overrides in audit metadata.

| Origin | Default trust |
|---|---|
| `user_input` | `trusted` |
| `system` | `trusted` |
| `tool_output` | `untrusted` |
| `retrieved` | `untrusted` |
| `a2a_inbound` | `untrusted` |
| `external` | `untrusted` |
| `agent_generated` | minimum trust of `derived_from` lineage |

Provenance MUST be populated by deterministic code outside the LLM's output path. Implementations MUST NOT instruct the LLM to produce it. The agent declares `provenance_producer: "deterministic" | "none"` in the handshake; a `none` producer emits no Provenance objects, and Guardians whose policies require Provenance MUST refuse the session at handshake time rather than silently degrading enforcement. LLM-authored Provenance is not a conformant producer mode because it makes an untrusted runtime output responsible for its own lineage.

## 8. SessionContext and Intent

State the Guardian Agent maintains across a session. The Guardian commits the chain head (`chain_hash`) on the wire in its response for every step where it writes a ContextEntry (§8.6), so the chain is externally observable rather than purely Guardian-internal. The Observed Agent MAY also send `session_id` and a `chain_hash` for cross-checking.

The chain root is established by the first ContextEntry the Guardian writes for a `session_id`, with `previous_hash: null`. This entry is normally produced by `sessionStart`; deployments that do not emit `sessionStart` MAY allow the Guardian to implicitly initialize the chain at the first content-bearing hook, but this is discouraged because it leaves no place to attach session-level identity, policy, or Intent before content enters.

**SessionContext:** `session_id`, `chain_hash` (rolling SHA-256), `entries` (append-only `ContextEntry`), `provenance_summary`, `intent` (optional).

The SessionContext container is intentionally not schematized in v0.1. The wire-visible commitment (`chain_hash`) and the structurally-interesting children (`ContextEntry`, `ProvenanceSummary`, `Intent`) are each defined as portable schemas with normative computation rules; the container that holds them is server-side state and remains implementation-defined. Cross-Guardian interoperability is achieved through the standardized wire artifacts, not through a standardized container format.

### 8.1 ContextEntry

Schema: [`context-entry.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/context-entry.json). Append-only entry in the audit chain.

- **Required:** `entry_id`, `step_id`, `step_type`, `entry_hash`.
- **SHOULD:** `request_hash` (lowercase-hex SHA-256 of the JCS-canonicalized request envelope params; without this the chain commits only to step metadata, not to request content, so deployments claiming the **ACS-Audit** profile MUST populate `request_hash`), `timestamp`, `provenance_summary`, `previous_hash` (required for every entry except the first).

Storage representation is implementation-defined; this spec constrains the canonical form used for hashing, not how Guardians store entries internally.

### 8.2 Chain hashing (normative)

`entry_hash = lowercase-hex(SHA-256(content_bytes || prev_hash_bytes))` where:

1. `content_bytes` is the UTF-8 encoding of the RFC 8785 (JCS) canonicalization of the ContextEntry object with `entry_hash` and `previous_hash` fields REMOVED;
2. `prev_hash_bytes` is the raw 32-byte decoding of `previous_hash`, or the empty byte string if `previous_hash` is null/absent (first entry in the session);
3. `||` denotes byte concatenation.

Conformant Guardians MUST compute `entry_hash` this way; otherwise chains computed by different implementations will not match and cross-Guardian audit comparison breaks. Alternative canonicalization schemes are not permitted in v0.1.

### 8.3 ProvenanceSummary

Schema: [`provenance-summary.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/provenance-summary.json). Optional. Condensed view of provenance facts at the entry level (what entered at this step) and at the session level (cumulative across the session). All fields are OPTIONAL — Guardians populate only what their policies consume. Available v0.1 fields: `origins_seen`, `entry_count`, `entry_count_by_origin`, `earliest_step_id_by_origin`, `max_lineage_depth`. v0.1 carries origin-derived aggregates only; trust-derived aggregates are computed Guardian-internally because v0.1 keeps trust classification in policy. The session-level summary is the monotonic aggregation of entry-level summaries.

### 8.4 Intent

Intent is OPTIONAL and is defined in [Concepts › Intent](../../concepts/intent.md) (normative). Wire fields: `raw`, `parsed` (capability list), `parser_provenance` (REQUIRED if `parsed` present; `origin` MUST be `user_input`), `scope_mode`.

**Intent immutability enforcement (normative).** The invariant is defined in [Concepts › Intent](../../concepts/intent.md): once established (via `sessionStart` or the first `agentTrigger` for the session), `Intent.parsed` is fixed and may grow only through an approver's `intent_extension` via the ASK flow (§9.1). The framework MUST enforce it: any attempt to modify `Intent.parsed` by the runtime LLM, by tool outputs, or by data crossing an `untrusted` channel MUST be ignored or rejected, and SHOULD be recorded as an audit event. This rule is load-bearing for IBAC's central security claim: the capability set is fixed before untrusted data enters and can grow only through explicit, audited approver action.

### 8.5 Size-based archival (optional)

Guardian Agents MAY archive entries when SessionContext exceeds a configurable byte threshold (suggested 64 KB). Archival MUST preserve `chain_hash`, `provenance_summary`, and `intent`. A mismatched `chain_hash` SHOULD trigger an audit event.

### 8.6 Chain head publication (normative)

The audit chain is only tamper-evident to an outside party if its head is committed where that party can see it. A Guardian that keeps `chain_hash` private can drop an entry (for example a DENY), recompute the chain forward, and present a clean history later, with no on-wire signal of the rewrite.

For every step where the Guardian writes a ContextEntry (the content-bearing steps), the Guardian MUST include the resulting `chain_hash` in its response, and that `chain_hash` MUST be covered by the response signature (§10). Publishing the head as each decision is made lets an observer that records traffic detect any later rewrite, because the true sequence was already witnessed.

`CHAIN_MISMATCH` is the named integrity condition, exposed two ways for two detectors. A Guardian that receives an Observed Agent's `chain_hash` (cross-check) that disagrees with its own computed head MAY DENY with `reason_codes: ["chain_mismatch"]`, or return the `CHAIN_MISMATCH` error (`-32007`, §17.1) when it cannot proceed at all. An Observed Agent or external auditor that finds a published `chain_hash` inconsistent with the recomputed chain SHOULD treat it as an integrity event, not a transient error.

Tamper-evidence here is bounded by the signature in use. Under the HMAC baseline the published, signed head gives integrity against a network tamperer and lets a key-holder verify the chain, but it does not bind the Guardian itself: the Guardian holds the symmetric key and can re-sign a rewritten head. Non-repudiation, proving to a third party that a specific Guardian issued a specific head, requires the asymmetric ACS-Crypto profile. The baseline detects accidental divergence and cross-Guardian disagreement; defeating a determined, compromised Guardian is a profile-level guarantee, not a Core one.

## 9. Approver Model

ASK approvers MAY be human, agent, or service. `ask_details.approver = { type, id, endpoint }`. The Approver receives an ACS-shaped request and returns an ACS-shaped decision. Approver authentication is REQUIRED. Guardian MUST verify approver identity against policy.

Single-hop only in v0.1. Approvers MUST NOT return ASK. Quorum and recursive ASK deferred to v0.2.

### 9.1 Intent extension via ASK (normative)

When a Guardian raises ASK because a request is outside `Intent.parsed`, the approver's grant MAY include an `intent_extension` field (see [`ask-details.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/ask-details.json)) containing capabilities to add to `Intent.parsed`. The extension's `scope` selects between `this_request` (capabilities apply only to the in-flight request) and `session` (capabilities are appended to `Intent.parsed` for the remainder of the session).

On `scope: session`, the Guardian MUST:

1. Append the capabilities to `Intent.parsed`.
2. Write a ContextEntry with `step_type: "intent_extension"` recording the approver identity, the granted capabilities, and the originating ASK's `step_id`.
3. Carry the extension's `provenance` forward distinct from the original `parser_provenance` so audits can distinguish parser-derived capabilities from approver-extended ones.

Intent extensions are subject to the session's `scope_mode`: a Guardian operating under `scope_mode: strict` MUST NOT honor extensions that would add capabilities the deployment policy forbids in strict mode. This mechanism is the only conformant path to mutate `Intent.parsed` after Intent is committed.

### 9.2 Approver-incapable clients (normative)

Some Observed Agents (IDE plugins, headless automation, runtimes whose enforcement model is allow/deny only) have no way to route an `ASK` disposition. The Guardian determines client ASK-handling capability by deployment-defined means such as agent identity bound at handshake, policy keyed on `agent_id`, organizational configuration, or any other out-of-band signal the deployment trusts. ACS does not put this declaration on the wire in v0.1; it is part of the Guardian's policy bundle.

When the Guardian determines that the client cannot resolve `ASK`, the Guardian MUST NOT return `ASK`. The Guardian MUST instead substitute one of:

1. `DEFER` with `timeout_decision: "deny"`: when the underlying issue might resolve through retry, an out-of-band escalation, or a later state change. The deferred verdict still counts toward cascading-deferral limits (§6).
2. `DENY` with `reason_codes: ["approver_unavailable"]` and `reasoning` that names the missing capability: when no recovery path exists.

The choice is policy-driven: deployments SHOULD prefer `DEFER` when the request is potentially recoverable through a different surface, and `DENY` when the action is unconditionally outside the client's reachable authority.

This rule preserves the security guarantee (actions that would have been `ASK`'d in an approver-capable deployment are not silently allowed) while letting clients without approver UX participate in ACS sessions as fully conformant ACS-Core deployments.

## 10. Cryptographic Signatures

A signature over the §10 canonical input is REQUIRED in ACS-Core. The signature envelope is `{ algorithm, value, key_id }`, the algorithm drawn from the registry below and the per-direction supported set declared in the handshake. `HMAC-SHA256` is the baseline that satisfies the requirement; ACS-Core does not require asymmetric or post-quantum signatures, which are the ACS-Crypto profile (§10.1). The per-session HMAC key is `HKDF`-derived from deployment-provided input keying material (a pre-shared secret, or a transport channel binding such as a TLS exporter) together with the `session_id`. ACS v0.1 defines no in-band key-exchange: a deployment with neither a shared secret nor a secure transport cannot use the HMAC baseline and satisfies the requirement with an ACS-Crypto algorithm whose key distribution it manages out of band.

**Signed input.** The signed input for every algorithm is the RFC 8785 (JCS) canonicalization of the request or response envelope with the `signature` field removed, encoded as UTF-8. This binds the signature to the whole envelope, including `method`, `metadata.session_id`, `request_id`, and `timestamp`, so a captured signature cannot be lifted into a different envelope (for example, re-wrapping a signed `toolCallResult` under a different `session_id`). A verifier MUST recompute this canonical form and MUST reject a signature that does not cover it (`SIGNATURE_INVALID`, §17.1). The input is fixed by this rule, not declared per message: a discoverable `signed_fields` would let a producer advertise partial coverage that omits `session_id`, reopening the gap this closes. Alternative canonicalization is not permitted in v0.1, matching the chain-hash rule in §8.

### 10.1 Algorithm registry

The registry is crypto-agile: the `{ algorithm, value, key_id }` envelope supports any registered algorithm, and the handshake declares which algorithms each side supports. v0.1 prioritizes adoption breadth over cryptographic maximalism: signatures are already field-optional, and a spec that ships without PQC mandates protects more deployments than a spec that mandates PQC and doesn't ship. PQC algorithms from NIST FIPS 203–205 (2024) are registered and available; a future version is expected to promote PQC to RECOMMENDED once ecosystem support matures.

| Algorithm | Class | v0.1.0 status |
|---|---|---|
| `HMAC-SHA256` | Symmetric MAC | RECOMMENDED. Shared-secret integrity; simplest deployment path. Sufficient for same-host and trusted-network topologies where the threat is accidental tampering or replay. |
| `ECDSA-P256` | Classical asymmetric | OPTIONAL. Strongest current ecosystem support across Java, Node, .NET, HSMs, and major cloud KMS providers. |
| `RSA-PSS-SHA256` | Classical asymmetric | OPTIONAL. Legacy interop; deployments with existing RSA PKI. |
| `ML-DSA-65` | PQC, lattice (FIPS 204) | OPTIONAL. ~128-bit post-quantum security; ~3.3 KB signatures. Recommended for deployments shipping PQC libraries today. |
| `ML-DSA-44` | PQC, lattice | OPTIONAL. Low-bandwidth profile. |
| `ML-DSA-87` | PQC, lattice | OPTIONAL. High-security profile. |
| `SLH-DSA-128s` | PQC, hash (FIPS 205) | OPTIONAL. Algorithmic diversity vs. ML-DSA's lattice assumption. Caution: ~7.8 KB signatures, signing takes hundreds of milliseconds, unsuitable for hot-path Guardian responses without careful latency budgeting. |
| `SLH-DSA-128f` | PQC, hash | OPTIONAL. Faster signing; larger signatures. |
| `ML-DSA-65+ECDSA-P256` | Hybrid | OPTIONAL. Transitional composite for PQC forward-resistance with classical co-signature. |
| `ML-DSA-65+RSA-PSS-SHA256` | Hybrid | OPTIONAL. Transitional composite. |

**PQC migration intent.** The long-term direction is PQC-primary. A future ACS version is expected to promote `ML-DSA-65` to RECOMMENDED and eventually deprecate classical-only algorithms, but the timeline depends on ecosystem readiness: library maturity across Java/Node/.NET, HSM/KMS support breadth, and operational experience at scale. The crypto-agile envelope ensures that migration requires no wire-format changes; only the handshake-negotiated algorithm set shifts.

### 10.2 Hybrid signature value encoding

For any algorithm of the form `<PQC>+<CLASSICAL>`, the `value` field carries the concatenation `len(pqc_sig) || pqc_sig || len(classical_sig) || classical_sig`, where each `len` is a 4-byte big-endian unsigned integer and the whole blob is base64-encoded for wire transit. Verifiers MUST verify both component signatures over the canonical input defined in §10; failure of either component is a signature failure (`SIGNATURE_INVALID`, §17.1). The same `key_id` resolves to a hybrid key descriptor that pins both component public keys.

### 10.3 Replay protection

`request_id` (UUID), `timestamp` (ISO 8601), and optional `nonce` (16–64 bytes). Guardians MUST reject requests whose `timestamp` is more than the negotiated skew window (`skew_window_ms` in ServerHello, §4; RECOMMENDED default 300000) in the past or future, returning `TIMESTAMP_OUT_OF_WINDOW` (`-32006`, §17.1), MUST reject duplicate `request_id` values within the session with `REPLAY_DETECTED` (`-32005`, §17.1), and SHOULD reject duplicate `nonce` values within a sliding window the deployment configures (also `REPLAY_DETECTED`). The Observed Agent uses `skew_window_ms` for clock-drift diagnostics.

## 11. Platform / OS Independence

ACS MUST be deployable across IDE, SaaS, on-prem on Linux/Windows/macOS/mobile/browser. Normative:

- Resource identifiers MUST use URI form (`file:///C:/...`, `posix:///etc/...`, `https://...`).
- Capability vocabulary uses abstract names (`filesystem.delete`, `network.egress`, `process.execute`).
- Identity descriptors carry a `type` discriminator (`posix_uid`, `windows_sid`, `oauth_subject`, `cert_subject`, …). Schema owned by the Identity workstream.
- Authentication mechanism declared in handshake; spec mandates none.

## 12. Policy Engine and Agent Layers

### 12.1 Policy engine interface

Spec defines the **interface** to the deterministic-layer engine, not the engine.

**Input:** request envelope + SessionContext + Intent + provenance. **Output:** decision envelope, plus optional `delegate_to: "agent"`.

| Engine | Status |
|---|---|
| OPA / Rego | v0.1 starting reference |
| Cedar | v0.2 fast-follow |

Custom engines plug in by respecting the interface. ACS layers conventions on top: modification format, reasoning format, no external HTTP calls in canonical policies, bundle layout, baseline policy bundle.

### 12.2 Agent layer

Invoked by the deterministic layer's chain config. Receives the same input plus the deterministic layer's intermediate output. Returns a decision envelope.

- Prompt MUST treat untrusted data as data, not instructions. Untrusted fields MUST be wrapped/quoted.
- MUST NOT have access to deterministic-layer policy code.
- Decisions MUST be logged with reasoning, model identifier, confidence (when available).
- Timeouts follow the handshake's `timeout_config`.

OPTIONAL for v0.1.0. Deterministic-only deployments are fully conformant.

## 13. Liveness / System Methods

A liveness method is required for connection-health checks, transport-debugging, and timeout tuning. It carries no enforcement semantics and is not part of the audit chain.

**Method:** `system/ping`. Schema: [`hooks/system-ping.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/hooks/system-ping.json).

**Request payload.** Standard ACS envelope with `method: "system/ping"` and `payload: { "echo": "<optional string>" }`.

**Response.** Standard ACS decision envelope with `decision: "allow"` and a `payload` object carrying `{ "status": "ok", "echo": "<request.echo>", "server_timestamp": "<iso-8601>" }`.

**Normative rules:**

- Guardians MUST always return `decision: "allow"` for `system/ping` regardless of policy, signature, or session state. The method does not represent a controllable agent action.
- `system/ping` MUST NOT be written into SessionContext as a ContextEntry; it does not participate in the chain hash.
- `system/ping` MUST NOT require a signature even if the session otherwise requires signatures, so that liveness probing remains possible during signature-rotation or key-resolution failures.
- The signature exemption means a successful ping does not prove the enforcement path is healthy: a Guardian can answer pings while rejecting every signed hook, for example during a key-resolution outage (`SIGNATURE_INVALID`, §17.1). Deployments SHOULD monitor hook-path decision failures (§6.4) directly rather than infer enforcement health from ping alone.
- Connection failure or response timeout for `system/ping` is a transport-level signal that the Observed Agent MAY use to renegotiate transport, re-handshake, or fail over; it MUST NOT be interpreted as an enforcement event.
- `system/ping` is the only method in the `system/*` namespace defined in v0.1.0. The namespace is reserved for future low-level transport/control methods (e.g. `system/handshake_renegotiate` in v0.2).

## 14. Multi-Tenancy

`tenant_id` reserved as an optional envelope field. No isolation rules in v0.1. Per-tenant policy scoping, SessionContext isolation, audit boundaries, and cross-tenant A2A rules deferred to v0.2.

## 15. Out of Scope (Deferred)

| Feature | Deferred to | Reason |
|---|---|---|
| Streaming + wrapped streaming methods | v0.2 | SSE, interruption, chunk-level policy is too much surface |
| Batching atomicity, ordering, cross-request dependencies | v0.2 | Standard JSON-RPC 2.0 batching is permitted in v0.1; ACS-specific atomicity / ordering / dependency rules wait for the streaming spec |
| Sensitivity / four-level timeout model | v0.2 | Categorization-from-facts is non-trivial; v0.1 uses a single handshake-negotiated default timeout |
| Recursive ASK + quorum | v0.2 | Bounded delegation and tie-breaking need careful spec |
| Multi-tenant isolation rules | v0.2 | Touches policy, SessionContext, audit, A2A |
| `protocols/A2A/*` wrapping specification | v0.2 | A2A hook wrapping is reserved (namespace exists); detailed method mapping waits |
| AgBOM federation across A2A peers | v0.2 | Single-agent AgBOM is in v0.1; federated views need an A2A-side discovery method first |
| gRPC, unix_socket transports | v0.2+ | HTTP + stdio cover IDE/SaaS/on-prem in v0.1 |
| PQC as RECOMMENDED default | Future | Promote `ML-DSA-65` once ecosystem readiness justifies it |
| Classical-only signature deprecation | Future | Deprecate classical algorithms once PQC-only is universal |

## 16. Roadmap

| Version | Theme | Highlights |
|---|---|---|
| **v0.1.0** | Baseline + profiles | ACS-Core (mandatory), ACS-Trace, ACS-Inspect/Inspect-Dynamic, ACS-Provenance, ACS-Crypto, ACS-Audit profiles |
| **v0.2.0** | Async + composition | Streaming, wrapped streaming, batching atomicity / ordering / dependency semantics, recursive ASK, quorum, multi-tenant isolation, policy-author attestation profile, Cedar binding, connection reuse, sensitivity-tier timeout model, AgBOM federation across A2A peers |
| **v0.3.0+** | Reach + transport | gRPC and unix_socket transports, A2A/MCP `deny`/`modify` extensions, classical-only signature deprecation, full deployment-mode taxonomy |

## 17. Error Handling

ACS uses standard [JSON-RPC 2.0 error codes](https://www.jsonrpc.org/specification#error_object). The `-32000` to `-32099` range is reserved for ACS-specific errors, enumerated in §17.1.

| Code | Meaning | Typical use |
|---|---|---|
| `-32700` | Parse error | Invalid JSON payload |
| `-32600` | Invalid Request | Not a valid JSON-RPC Request, or array-shaped input to a Guardian that does not support batching |
| `-32601` | Method not found | The requested ACS method does not exist |
| `-32602` | Invalid params | `params` are invalid (wrong type, missing required field) |
| `-32603` | Internal error | Unexpected server error |
| `-32000` to `-32099` | ACS-specific | See the registry in §17.1 |

### 17.1 ACS error code registry

Every mandated refusal maps to a fixed code, so an SDK can branch on the code without parsing prose. An error response MAY carry a `data` object; when present it SHOULD include a machine-readable `reason` and a human-readable `message`, plus the per-code fields noted below.

| Code | Name | Raised when | Observed Agent recovery |
|---|---|---|---|
| `-32000` | `SESSION_REFUSED` | Guardian policy refuses the session and no more specific code applies (for example an `agent_id` the policy does not permit). | Do not retry without a policy or configuration change; read `data.reason`. |
| `-32001` | `UNSUPPORTED_VERSION` | No common `acs_version` at handshake (§4). | Retry the handshake with a version from `data.supported_versions`. |
| `-32002` | `PROVENANCE_REQUIRED` | Policy requires provenance but the client declared `provenance_producer: "none"` (§4, §7). | Re-handshake as a `deterministic` producer, or connect to a Guardian that does not require provenance. |
| `-32003` | `CAPABILITY_NOT_NEGOTIATED` | A method or profile was exercised that the handshake did not negotiate for this session (§4). | Re-handshake to negotiate the method or profile named in `data.method`. |
| `-32004` | `SIGNATURE_INVALID` | A required signature is missing, malformed, or fails verification (§10). | Re-sign the request; if it persists, re-resolve `key_id`. |
| `-32005` | `REPLAY_DETECTED` | Duplicate `request_id` or `nonce` within the session (§10.3). | Regenerate `request_id` (and `nonce`) and retry. |
| `-32006` | `TIMESTAMP_OUT_OF_WINDOW` | `timestamp` falls outside the negotiated skew window (§10.3); `data.skew_window_ms` carries the window. | Correct clock drift and retry within the window. |
| `-32007` | `CHAIN_MISMATCH` | The client's `chain_hash` does not match the Guardian's computed head (§8.6). Also exposable as a deny `reason_code: "chain_mismatch"` when the Guardian can still return a decision. | Re-fetch session state; a persistent mismatch is an integrity event, not a transient error. |

`system/ping` MUST NOT return an ACS-specific error, so liveness probing survives signature-rotation and key-resolution failures (§13).
