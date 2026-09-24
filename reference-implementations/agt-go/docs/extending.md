# Extend the Guardian

The four interfaces are the Guardian's extension points. Your own implementation can
replace any of them, with your own engine, key custody, database or audit destination,
and the Guardian keeps everything ACS defines. This page lists what each
implementation must do;
[architecture](architecture.md#how-a-request-moves-through-the-guardian) shows when each one is called.
[`examples/custom-engine`](../examples/custom-engine/) implements all four without AGT.

## PolicyEngine

Declared in [`policy_engine.go`](../guardian/policy_engine.go).

- **`Decide` receives**
  - the validated request envelope;
  - its payload as raw JSON that passed the method's schema, or its wrapped protocol's
    handler;
  - the SessionContext after this step's ContextEntry was appended, as its own copy, which
    the engine must not change.
- **Timing**
  - `Decide` runs under the negotiated decision timeout.
  - `ctx` ends when that timeout or the Guardian's shutdown grace expires. The Guardian
    stops waiting then, even if `Decide` has not returned.
  - Calls for different sessions may run at the same time.
- **What the Guardian does with the answer**

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

- **The engine must**
  - **know the Observed Agent's capability itself.** ACS puts neither MODIFY nor ASK capability on
    the wire.
    - `Config.AskSubstitution` is the endpoint-wide §9.2 choice.
    - A more specific trusted signal goes in `PolicyDecision.Client`.
  - **authenticate approvals.** ACS v0.1.0 defines no wire method for sending an approver's
    answer to the Guardian.
    - The engine receives the answer by its own means.
    - It authenticates the approver and applies the session's `scope_mode` (§9, §9.1)
      before returning a `Grant`.
  - **keep state across steps in `State`.** Its own per-session memory is lost to a restart
    or another replica; `State` lives and dies with the session.
- `Policy()` is read once, at `guardian.New`, for the ServerHello.

## Signer

Declared in [`signer.go`](../guardian/signer.go).

- The Guardian builds `input`: the RFC 8785 form of the envelope without its `signature`
  ([canonical-form.md](canonical-form.md)).
  - A `Signer` only checks or signs those bytes. The keys never leave it.
- **`Verify`**
  - returns an error wrapping `guardian.ErrSignatureInvalid` for a signature that does not
    verify;
  - any error is answered -32004; any other error is also recorded as a `failure` event.
- **`Sign`**
  - receives the `key_id` that verified the request;
  - a symmetric signer may reuse that key; an asymmetric signer chooses its response key and
    identifies it in the returned signature;
  - a signature that would not pass `response-envelope.json` is never sent.
- **Both** must return when `ctx` ends. Request cancellation and Guardian shutdown use that
  context to stop an external key service that is still waiting.
- **Session binding.** The Guardian binds a session to the `key_id` and `metadata.agent_id`
  of its handshake. A later step with either value changed is refused before anything is
  appended.

## SessionContextStore

Declared in [`session_context_store.go`](../guardian/session_context_store.go).

The Guardian computes every `entry_hash`. The store decides only where things are kept and
who may write them.

- **`Lock`** orders a session across every Guardian that shares the store.
  - A step uses the returned `lockCtx` from before `Load` until its answer is built, the
    policy engine included.
  - An expiring claim must be renewed while the Guardian holds it, and every mutation must
    check that the claim is still owned and unexpired.
  - Cancel `lockCtx` with `guardian.ErrSessionLockLost` when ownership is lost.
    Cancellation is cooperative, so a policy engine must stop promptly when `lockCtx` ends.
  - Do not hold a database connection for the full engine call.
- **`Load`** returns a copy. Nothing the caller changes reaches the store.
- **`Append`** wholly succeeds or changes nothing:
  - reserve the `request_id` and nonce (`ErrReplayDetected` when either was seen in the
    session);
  - check the head equals `ExpectedHead` (`ErrHeadMoved` when it does not, or when the
    session is gone);
  - append the entry and make its `entry_hash` the head;
  - record the step's lineage, set the Intent when given, close the session when asked.
  - The Guardian answers DENY `session_contended` when the expected head changed.
- **`Negotiate` and `Reserve`** refuse replays too.
  - A replayed handshake is `ErrReplayDetected`, not `ErrAlreadyNegotiated`.
  - `Reserve` consumes a `request_id` for a step answered without an entry, a step after
    sessionEnd.
- **`Conclude`** is one operation.
  - It checks the head, then records the ASK step, the deferral, the engine's state and,
    for an allowed skillRegister, the skill approval, all or nothing.
  - The approval spans sessions: a skill registered in one loads in a later one
    (`skill-load.json`). Key it by `skill_id` and digest.
- **Bounds**
  - A store at capacity returns `ErrStoreFull`, and the Guardian refuses the session or
    denies the step.
  - Never drop a session to make room within the skew window: its handshake could be
    replayed into a new one.
- **Retention**
  - A session, and the `request_id`s and nonces it reserved, stay at least twice its saved
    `ServerHello.skew_window_ms` after its last write. A request accepted at the future
    edge of the window must become stale before its replay history can be removed.
  - A store may archive `Session.Entries` and keep fewer entries than it appended (§8.5),
    but `Session.Head` must always be the last `entry_hash`.
  - `Session.Lineage` keeps a key for every appended `step_id`, including steps with no
    provenance, so `steps/postCompact` can validate `entries_compacted`.
- A store may write its own record beside each ContextEntry in the same transaction, its
  own audit chain for example.
- Run `guardiantest.TestSessionContextStore` against your store. An in-memory store cannot
  prove a database's atomicity; that test run against your real database can.

## AuditLog

Declared in [`audit_log.go`](../guardian/audit_log.go).

- Both methods return nothing and must not block or panic: a slow audit log must never turn
  a governed step into an ungoverned one.
  - Calls may run concurrently. Queue, write in the background, and report your own
    failures.
- **`Envelope`** receives its own copy of every request that parsed and every answer, as
  sent.
- **`Event`** receives
  - the audit events the standard requires of the Guardian: `modify_unsupported`,
    `ask_substituted`, `intent_mutation_rejected`, `chain_mismatch`;
  - and `disposition_not_permitted`, `lineage_mismatch` and `failure`, which the Guardian
    records so no decision changes silently and no failure goes unrecorded.

## Add behavior around the Guardian

The Guardian has no callback system. Add surrounding behavior at the existing boundaries:

- **Around the transport:** the Guardian is an `http.Handler`, so ordinary Go middleware
  wraps it, and the host serves its own routes beside it on its own mux.
- **Around the decision:** `PolicyEngine` is an interface, so an engine wraps another, to
  consult a second source or to remember a case it will answer when the same step arrives
  again.
- **After the answer:** `AuditLog.Envelope` receives every answer exactly as it was sent,
  the Guardian's own substitutions included. A host that must act on a decision reads the
  decision the Observed Agent received, not the one the engine proposed.
