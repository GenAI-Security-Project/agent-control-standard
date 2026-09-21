# Differences from the TypeScript tree

The Go implementation answers the same decisions as [`../agt/`](../../agt/) for
every step covered by 49 recorded sessions. The compared fields are disposition,
reason codes, policy references, reasoning and modifications
(`agtbridge.TestRecordedCases`). This document lists every deliberate difference
between the two implementations and explains the reason.

ACS is the authority. The TypeScript implementation is the reference for
behavior that ACS leaves to the policy engine. Where ACS v0.1.0 is silent, the Go
implementation chooses the smallest behavior that preserves interoperability.
The tables record only choices a reader cannot derive directly from the public
API.

## Protocol

| Behavior | TypeScript tree | Go implementation | Why |
| --- | --- | --- | --- |
| Signatures | Nothing is signed or verified. | Every request but `system/ping` must carry an HMAC-SHA256 signature over the §10 input, and every answer to a request that authenticated is signed, an error at `error.signature`; a ping's answer only when the ping was. | ACS-Core requires it (§10). An unsigned ping must not obtain the session key's signature over an answer whose identifiers the caller chose. A TypeScript host shim sends no signature, so it cannot talk to this Guardian until it signs. |
| HKDF parameters | Not applicable. | The signer derives a 32-byte session key with HKDF-SHA256. It supplies no salt and uses the UTF-8 bytes of `session_id` as the HKDF `info` input. `salt` and `info` are inputs to HKDF; they are not fields in an ACS message. | §10 requires HKDF but does not define the hash function, salt, `info` input or output length. Two implementations must use the same values to verify each other's signatures. |
| Session key binding | Not applicable. | The handshake records its `key_id`; a later step signed with another key that verifies is answered DENY `key_not_bound`, signed with that key, and nothing enters the session. | One key holder must not write into a session another key opened; an error in place of a decision would fall to the agent's failure posture. |
| ServerHello signature | Not applicable. | Signed at `result.signature`, with `AcsResult.signature`'s shape and the same §10 input. | ACS-Core requires a signature on every answer; `handshake.json` gives the ServerHello no member for it and admits unknown members. |
| Partial Observed Agent | The TypeScript host adapter declares only the two tool hooks it can emit. | The Guardian negotiates the subset an Observed Agent offers and refuses an unnegotiated hook with `CAPABILITY_NOT_NEGOTIATED`; it does not require a tool-only harness to claim every ACS-Core hook. | `methods_implemented` is a capability declaration in §4. ACS-Core is a deployment conformance claim, not a requirement to misrepresent a partial harness. |
| Replay protection | None. | A repeated `request_id` or nonce in a session is -32005, a replayed handshake and a step after sessionEnd included; a timestamp outside `skew_window_ms` is -32006. | §10.3. |
| Chain digest | SHA-256 over a seven-element JSON array of the tree's own fields, from sixty-four zeros. | The §8.2 digest over the RFC 8785 form of a `context-entry.json` entry, from the empty string. | §8.2 permits no other canonicalization; chains from different implementations must compare. |
| Chain head | Written to a log, not sent. | `chain_hash` on every answer for a step with a ContextEntry, covered by the signature. | §8.6. |
| Handshake | Constants; the ClientHello is not read. | Negotiated: version, the methods offered by the Observed Agent that this Guardian evaluates, transport, timeouts, skew window and posture. `profiles_accepted` is the supported intersection of `profiles_supported`, so a partial Observed Agent need not claim `acs-core`. A second handshake for a negotiated session is refused, unless it repeats the same ClientHello under the session's key, which returns the negotiated ServerHello. | §4; `methods_implemented` and `profiles_supported` declare the Observed Agent's capabilities. v0.1 defines no renegotiation; an Observed Agent that restarts must still learn its session's terms. |
| Hooks evaluated | `steps/toolCallRequest` and `steps/toolCallResult`. | All nineteen native hooks, each held to the dispositions hooks.md permits it. | ACS-Core's hook floor. |
| Rules the hooks give the Guardian | None. | A skillLoad no allowed skillRegister approved is DENY `skill_unverifiable`; a postCompact summary whose lineage is not the compacted entries' is recorded with `lineage_mismatch`; `metadata.turn_id` is written onto each entry. | `skill-load.json`, `post-compact.json` and `turn-start.json` put these on the Guardian. |
| Wrapped MCP | Not implemented. | `protocols/MCP/*` and `wrapped:mcp-<version>/*` are governed, the explicit form at the version the Observed Agent declared. AGT decides a wrapped `tools/call` with the tool gates. The projection preserves every standard MCP result shape and addresses a redaction back into the MCP message. An override names a member of `params.arguments`. MCP identifiers are compared by their canonical JSON values, not their original spelling. A call the decision stops is not remembered, so no response can be answered as though it ran. | ACS-Core's floor on `integration` includes it. A tool called through MCP must not escape the gates a direct call meets. |
| A disposition a hook does not permit | Sent as the engine returned it. | DENY where the hook permits DENY; otherwise ALLOW with reason code `disposition_not_permitted`, and an audit event. | hooks.md fixes each hook's dispositions; postCompact and the audit-only hooks permit no DENY. |
| Undispatched or undefined method | -32011, from the reserved ACS range. | -32601 for a method ACS does not define, -32003 for one it defines and the session did not negotiate. | §17.1 defines no -32011; a code in the reserved range that the registry does not define extends the standard. |
| Invalid envelope | DENY `envelope_invalid` when addressable, else -32010. | -32600 for an envelope that fails `request-envelope.json`, -32602 for a payload that fails its method's schema. | §17 assigns -32602 to invalid params. The Observed Agent sent a request it must correct, and receives no decision to apply. |
| Oversize body | -32010. | -32600. | Same reason. |
| Guardian defect | -32020. | -32603. | Same reason. |
| Engine calls | Unbounded. | At most `MaxEngineCalls` at once; a call the Guardian stopped waiting for holds its place until the engine returns, and a step that finds none is DENY `engine_saturated`. An engine's per-session state is bounded by `MaxPolicyStateBytes`. | An engine that ignores cancellation, or state an agent can grow, must not exhaust the process. |
| Evaluation failure | DENY `evaluation_failed`, reasoning the failure's message. | DENY `evaluation_failed`, reasoning "the policy engine failed"; the engine's message goes to the audit log as a `failure` event. | The only recorded difference in the replay. A provider's error can name internals, so it stays off the wire. |
| Store failure | Not applicable. | A signed DENY `store_unavailable`, the store's message in the audit log. | An authenticated step answered with an error would fall to the failure posture, which proceeds by default. |
| Outbound schema check | Checked and logged; the answer is sent unchanged. | A decision that would fail `response-envelope.json` is replaced by DENY `evaluation_failed` before it is signed, and the signed bytes are checked again before they are sent. | An answer the Observed Agent must reject is a decision failure, which under the default posture proceeds. A custom `Signer` can return a malformed signature. |
| Schemas | Read at the first request from `../../specification/v0.1.0/` by relative path. | Compiled at start from a byte-identical embedded copy; `internal/schema.TestSchemasMatchSpecification` fails when the copy differs by one byte. | A Go module in a subdirectory is fetched without the rest of the repository, so a library user has no relative path to read. The test keeps the property the relative path gave. |
| Payload validation | The two dispatched hooks. | Every method's payload schema. | The Guardian reads only what validation checked. |
| Concurrency | Steps of one session interleave. | One session's steps are ordered under `SessionContextStore.Lock`; sessions run in parallel. A store with an expiring claim renews it, cancels `lockCtx` if ownership is lost and fences each mutation against the claim. | Otherwise two replicas can write one session out of order. |
| Session store | In memory, with a configurable least-recently-written session cap. | In memory by default, behind `SessionContextStore`. Bounded in sessions, entries, replay reservations and skill approvals; a session is removed only after `SessionRetention` without a write, never sooner than two skew windows, and a full store refuses the new session or step. | The Go store keeps replay history until every accepted timestamp is stale. A deployment can provide a durable store without changing the Guardian. |

## AGT

AGT's ACS policy-engine runtime is a Rust core with bindings for Node, Python,
.NET and Rust, and no official Go binding. AGT also publishes a separate
general-purpose Go SDK; it does not expose this manifest runtime. The TypeScript
tree uses the npm package `agent-control-specification`. Its native runtime
invokes the `opa` command-line program. The Go implementation
evaluates the same policy files, unchanged, with OPA's Go library in process.
It implements only the AGT runtime behavior used by the checked-in manifest.
The recorded cases show that this behavior produces the same decisions.

| Behavior | TypeScript tree | Go implementation | Why |
| --- | --- | --- | --- |
| AGT runtime | AGT's Rust core at the `agt.lock` commit. | `agtbridge` implements manifest loading, policy input, the tool registry, the `egress` annotator, verdict normalization and every `runtime_error:*` denial used by the checked-in manifest. | No official Go binding exists for this runtime. Startup fails if the manifest uses an unsupported feature: `extends`, `approval`, Cedar, another annotator type, a remote bundle or an intervention point other than the two tool gates. |
| OPA | The `opa` binary the npm package bundles, with a 5-second timeout. | OPA's Go library, in process, under the Guardian's decision timeout. | One command with the Go toolchain; nothing to install. |
| An escalate verdict | Sent as `ask` without `ask_details`, which fails the response schema. | An ASK with `ask_details` when an approver is configured (`agtbridge.Options.Approver`); otherwise DENY with `approver_unavailable`. | An ASK must name its approver (§9); AGT's manifest names none for ACS. |
| Methods AGT has no configured point for | Not dispatched. | Allowed, with the step in the chain. | AGT does not govern them, and the Guardian still records them. |
| Information-flow labels | Kept in the session store. | Kept in the session store as the engine's `PolicyState`. An absent `result_labels` leaves the labels unchanged; an explicit empty array clears them. | The protocol packages know nothing of AGT, and the labels must live and die with the session. |
| `mapping.yaml` | Read without validation. | Validated at start: every source, wrap, decision and modification rule the translation reads. | A broken table stops the Guardian at start rather than denying at the first step that reaches it. |
| Host tool names | Each host-facing mapping names the tools that host exposes. | `policy.tool_aliases` maps a host tool name to a manifest tool name for policy evaluation; the signed ACS request and audit chain retain the original name. | A deployment can reuse one policy manifest across hosts without misrepresenting the tool identity on the ACS wire. |
| Finding the AGT tree | Anchored to the source file's own path. | `cmd/guardian` reads `policy.deployment_dir`, `policy.manifest` and `policy.mapping` from its required YAML configuration. Paths follow the configuration file, never the process working directory. | A compiled binary must be runnable outside its source checkout. |
| `ACS_MANIFEST_PATH` | Selects a manifest, for the drift demo. | `policy.manifest`, optionally overridden by `ACS__POLICY__MANIFEST`, selects a manifest inside the declared deployment directory. | The process has one explicit configuration contract; it rejects a manifest path outside its deployment directory. |
| `ACS_OPA_PATH`, `ACS_OPA_TIMEOUT_MS` | Select and bound the `opa` binary. | Not applicable. | No binary. |

## Operation

| Behavior | TypeScript tree | Go implementation | Why |
| --- | --- | --- | --- |
| Envelope log | Synchronous appends on the decision path, unbounded. | A background writer with a bounded queue; the envelope file keeps the TypeScript tree's line shape, and audit events go to a second file. | A slow disk must not delay a decision. |
| Audit events | None; the host shim writes its own. | The events §6.5 and §9.2 require, the §8.4 intent rejection, the §8.6 chain mismatch, every replaced disposition, a postCompact lineage mismatch, and each failure of the engine, the store or the signer with its detail. | ACS names them as the Guardian's; the detail of a failure stays off the wire. |
| Readiness | None. | `/healthz` answers while the process runs; `/readyz` and `/acs` answer once the engine is compiled. | A Guardian answering before its engine loads turns every step into a decision failure. |
| Shutdown | Stops the server. | Stops accepting, lets steps in flight finish for one grace period, cancels the remaining work, and allows a second grace period to deliver its DENY answers before forced close. A request still arriving is cancelled too. Audit records receive another full grace period to flush; failure to flush makes the command exit with an error. | A dropped answer is a decision failure, which proceeds by default. Separate bounded phases preserve cancellation answers without letting an unresponsive peer, provider or audit log block shutdown forever. |
| Prototype-key guards | The host adapter refuses `__proto__`, `constructor` and `prototype` as hookmap path segments (`reserved-segments.ts`). | None. | JSON decodes into Go maps and structs, which have no prototype chain. |

## Measured policy limits

The Go implementation decides as the TypeScript tree does, so it inherits the policies' and
AGT's runtime's limits as well as their decisions. The TypeScript README lists
the egress gate's soft spots under "Operational debt"; these were measured
against the Go implementation with the checked-in policies. Each is recorded, not fixed: fixing
it here alone would make the two trees disagree, and the fix belongs to the
policies or AGT's runtime, for both.

| Input | Decision |
| --- | --- |
| `curl https://evil.example.net/` | DENY `egress_destination_not_allowed` |
| `curl HTTPS://evil.example.net/` | ALLOW: the extractor matches only a lowercase scheme. |
| `curl ftp://evil.example.net/` | ALLOW: only `http` and `https` are read. |
| `curl https://docs.example.com/ https://evil.example.net/` | ALLOW: only the first destination is read. |
| `curl evil.example.net` | ALLOW: a bare host is not read. |
| A tool result whose second output holds a token | ALLOW: the redaction rule reads `outputs[0]` only. |

Run the checked-in policies as a demonstration of the protocol, not as an egress
control.
