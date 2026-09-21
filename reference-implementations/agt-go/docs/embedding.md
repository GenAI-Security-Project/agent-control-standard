# Embed the Guardian in your own host

A host with its own policy engine, key custody or database runs this Guardian without
forking it. ACS defines the envelope, the signed input, the chain digest, the
dispositions and the error codes, and the Guardian keeps all of them. ACS leaves four
things to the deployment, and each is an interface in package `guardian`.

| Interface | ACS leaves to the deployment | Default |
| --- | --- | --- |
| `PolicyEngine` | The policy engine (§12.1). | `agtbridge.Engine` in `cmd/guardian`; required in `guardian.Config`. |
| `Signer` | The keys and the signature algorithm (§10). | `guardian.HMACSigner`; required. |
| `SessionContextStore` | Where SessionContext lives (§8.1). | `guardian.MemorySessionContextStore` when nil. |
| `AuditLog` | The "deployment's own audit log" (§4, §6.4, §6.5, §8.4). | Records nothing when nil; `guardian.JSONLAuditLog` in `cmd/guardian`. |

Mount the Guardian as an `http.Handler` at your own route, or call
`Guardian.Handle(ctx, body)` from any transport. Resolve what you need from the request
first - a tenant, an endpoint - and put it in `ctx`. The Guardian passes `ctx` to all four
interfaces and never reads it.

[`examples/custom-engine`](../examples/custom-engine/) is a complete host in its own module.

## One step, in order

```mermaid
sequenceDiagram
    participant OA as Observed Agent
    participant G as Guardian
    participant AL as AuditLog
    participant S as Signer
    participant SC as SessionContextStore
    participant PE as PolicyEngine
    OA->>G: POST, signed envelope
    G->>AL: Envelope(inbound)
    G->>S: Verify(session, signed input, signature)
    Note over G: -32004 if it fails; -32600 on the envelope schema; -32006 outside the skew window
    G->>SC: Lock(session)
    G->>SC: Load(session)
    Note over G: -32602 on the payload; the Intent, chain_hash and skill-load rules
    G->>SC: SkillApproved, for a skillLoad
    G->>SC: Append(reservation, expected head, ContextEntry, lineage)
    Note over G: -32005 on a repeated request_id or nonce
    G->>PE: Decide(envelope, SessionContext)
    PE-->>G: PolicyDecision
    Note over G: required fields, §6.5 and §9.2 substitutions, hook rules, deferral bound, lineage
    G->>SC: Append(intent_extension), for a session grant
    G->>SC: Conclude(head, ASK, deferral, engine state, skill approval)
    G->>AL: Event, for each substitution and failure
    G->>SC: release
    G->>S: Sign(session, key_id, signed input)
    G->>AL: Envelope(outbound)
    G-->>OA: signed decision with chain_hash
```

| Method | `AuditLog` | `Signer` | `SessionContextStore` | `PolicyEngine` |
| --- | --- | --- | --- | --- |
| `handshake/hello` | both envelopes | `Verify`, `Sign` | `Lock`, `Negotiate` | `Policy()` only, read once at `guardian.New` |
| a native hook, `protocols/MCP/*` | both envelopes, events | `Verify`, `Sign` | `Lock`, `Load`, `Append`; `Reserve` after sessionEnd; `Conclude`, `SkillApproved` as the step needs | `Decide` |
| `system/ping` | both envelopes | `Verify` and `Sign` only when the ping is signed | none | none |

Sessions run in parallel; the steps of one session are decided one at a time, from `Lock`
to its release once the answer is built. No interface calls another, and none calls the
Guardian.

The store keeps the negotiated `ServerHello`. Every replica uses that saved handshake for the
session's timeout, timestamp window, negotiated methods, version and approver types. A
replacement replica may have a different configuration for new sessions; it cannot change
the terms of an existing session.

Once a step is authenticated and names a negotiated method, the Guardian answers every
store, engine and internal failure with a signed DENY. An error would leave the Observed
Agent to its failure posture, which proceeds by default. A failure's detail goes to the
`AuditLog` as a `failure` event, and the wire carries a fixed message. If the `Signer`
itself cannot sign, the Guardian can only return an unsigned internal error.

## PolicyEngine

The exported [`PolicyEngine`](../guardian/policy_engine.go) declaration is the
API contract.

`Decide` receives the validated request envelope, its payload as raw JSON that passed the
method's schema or its wrapped protocol's handler, and the SessionContext after this
step's ContextEntry was appended. It runs under the negotiated decision timeout; `ctx`
ends when that timeout or the Guardian's shutdown grace expires, and the Guardian stops
waiting then even if `Decide` has not returned. Calls for different sessions may run at
the same time. Each call receives its own copy; the engine must not mutate it.

What comes back and what the Guardian does with it:

| The engine returns | The Guardian answers |
| --- | --- |
| an error, a panic, or no answer before the deadline | DENY `evaluation_failed`, or `shutting_down` during a shutdown: the step is already in the chain |
| no call, because `MaxEngineCalls` calls are still running | DENY `engine_saturated`; a call the Guardian stopped waiting for keeps its place until the engine returns |
| a decision missing a field its disposition requires, or a MODIFY breaking §6.3 | DENY `evaluation_failed` |
| `DelegateToAgent` | DENY `agent_layer_unavailable`; this Guardian has no agent layer |
| a disposition the hook does not permit | DENY, or ALLOW where the hook permits no DENY, with reason code `disposition_not_permitted` |
| `Client.CannotApplyModify` with a MODIFY | DENY `modify_unsupported`, or ALLOW at postCompact (PR #21's proposed §6.5) |
| `Config.AskSubstitution` set to `deny` or `defer` with an ASK | the configured §9.2 substitute for this endpoint |
| `Client.CannotResolveAsk` with an ASK | `Client.AskSubstitute`, DEFER or DENY (§9.2) |
| a DEFER past the session's bound | DENY `deferral_bound_exceeded` |
| a `Grant` for a step the session was not answered ASK for | DENY `grant_invalid` |
| a `Grant` scoped to the session | an `intent_extension` ContextEntry recording the approver, the capabilities and the extension's provenance, and the Intent grown by the capabilities (§9.1) |
| valid JSON in `State` | kept with the session and given back as `SessionContext.PolicyState` on its later steps; invalid JSON is DENY `evaluation_failed`; larger than `MaxPolicyStateBytes` is DENY `policy_state_too_large` |

What the engine must guarantee:

- **Client capability is yours to know.** ACS puts neither MODIFY nor ASK capability on the
  wire. `Config.AskSubstitution` is the endpoint-wide §9.2 choice. An engine that needs a
  more specific trusted policy signal reports it in `PolicyDecision.Client`.
- **The engine authenticates approvals.** ACS v0.1.0 defines no wire method for
  sending an approver's answer to the Guardian. A deployment passes the answer
  to its engine through its own channel. The engine authenticates the approver
  and applies the session's `scope_mode` (§9, §9.1) before returning a `Grant`.
- **State across steps goes in `State`.** An engine that keeps its own per-session memory
  loses it to a restart or another replica; `State` lives and dies with the session.
- **`Policy()` is read once**, at `guardian.New`, for the ServerHello.

## Signer

The exported [`Signer`](../guardian/signer.go) declaration is the API contract.

The Guardian builds `input`, the RFC 8785 form of the envelope without its `signature`
([canonical-form.md](canonical-form.md)); a `Signer` only checks or signs those bytes. The
keys never leave it.

- `Verify` returns an error wrapping `guardian.ErrSignatureInvalid` for a signature that
  does not verify. Any error is answered -32004; any other error is also recorded as a
  `failure` event.
- `Sign` receives the `key_id` that verified the request. A symmetric signer may reuse
  that key. An asymmetric signer chooses its response key and identifies it in the
  returned signature. A signature that would not pass `response-envelope.json` is never
  sent.
- `Verify` and `Sign` must return when `ctx` ends. Request cancellation and Guardian
  shutdown use that context to stop an external key service that is still waiting.
- The Guardian binds a session to the `key_id` and `metadata.agent_id` of its handshake.
  A later step with either value changed is refused before anything is appended.

## SessionContextStore

The exported [`SessionContextStore`](../guardian/session_context_store.go)
declaration is the API contract.

The Guardian computes every `entry_hash`; the store decides only where things are kept and
who may write them.

- **`Lock` orders a session across every Guardian that shares the store.** A step uses the
  returned `lockCtx` from before `Load` until its answer is built, the policy engine
  included. An expiring claim must be renewed while the Guardian holds it, and every
  mutation must check that the claim is still owned and unexpired. Cancel `lockCtx` with
  `guardian.ErrSessionLockLost` when ownership is lost. Cancellation is cooperative, so a
  policy engine must stop promptly when `lockCtx` ends. Do not hold a database connection
  for the full engine call.
- **`Append` wholly succeeds or changes nothing:** reserve the `request_id` and nonce
  (`ErrReplayDetected` when either was seen in the session), check the head equals
  `ExpectedHead` (`ErrHeadMoved` when it does not, or when the session is gone), append the
  entry, make its `entry_hash` the head, record the step's lineage, set the Intent when
  given, close the session when asked. The Guardian answers DENY `session_contended` when
  the expected head changed.
- **`Negotiate` and `Reserve` refuse replays too.** A replayed handshake is
  `ErrReplayDetected`, not `ErrAlreadyNegotiated`; `Reserve` consumes a `request_id` for a
  step answered without an entry, a step after sessionEnd.
- **A bound is a refusal.** A store at capacity returns `ErrStoreFull` and the Guardian
  refuses the session or denies the step. Never drop a session to make room within the
  skew window: its handshake could be replayed into a new one.
- **`Load` returns a copy.** Nothing the caller changes reaches the store.
- **Archived entries keep lineage.** `Session.Lineage` contains a key for every appended
  `step_id`, including steps with no provenance. A store may archive `Session.Entries`, but
  keeps those lineage keys so `steps/postCompact` can validate `entries_compacted`.
- **`Conclude` is one operation.** It checks the head, then records the ASK step, the
  deferral, the engine's state and, for an allowed skillRegister, the skill approval, all or
  nothing. The approval spans sessions - a skill registered in one loads in a later one
  (`skill-load.json`) - so key it by `skill_id` and digest.
- **Keep a session for two negotiated skew windows.** A session and the `request_id`s and
  nonces it reserved stay at least twice its saved `ServerHello.skew_window_ms` after its
  last write. A request accepted at the future edge of the window must become stale before
  its replay history can be removed.

A store may write its own record beside each ContextEntry in the same transaction - its
own audit chain, say. It may keep fewer entries than it appended (§8.5 archival), but
`Session.Head` must always be the last `entry_hash`.

Run `guardiantest.TestSessionContextStore` against your store. An in-memory store cannot
prove a database's atomicity; that test run against your real database can.

## AuditLog

The exported [`AuditLog`](../guardian/audit_log.go) declaration is the API
contract.

Both methods return nothing and must not block or panic: a slow audit log must never turn
a governed step into an ungoverned one. Calls may run concurrently. Queue, write in the
background, and report your own failures. `Envelope` receives its own copy of every
request that parsed and every answer, as sent. `Event` receives the audit events the
standard requires of the Guardian - `modify_unsupported`, `ask_substituted`, `intent_mutation_rejected`,
`chain_mismatch` - and `disposition_not_permitted`, `lineage_mismatch` and `failure`,
which the Guardian records so no decision changes silently and no failure goes unrecorded.

## Add behavior around the Guardian

The Guardian has no callback system. Add surrounding behavior at the existing
transport, policy-engine and audit boundaries.

- **Around the transport:** the Guardian is an `http.Handler`, so ordinary Go middleware
  wraps it, and the host serves its own routes beside it on its own mux.
- **Around the decision:** `PolicyEngine` is an interface, so an engine wraps another -
  to consult a second source, or to remember a case it will answer when the same step
  arrives again.
- **After the answer:** `AuditLog.Envelope` receives every answer exactly as it was sent,
  the Guardian's own substitutions included, so a host that must act on a decision reads
  the decision the Observed Agent received, not the one the engine proposed.
