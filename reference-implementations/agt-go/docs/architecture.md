# Architecture

## What the Guardian is made of

The Guardian is the core. It implements the ACS rules: the handshake, signature
checks, replay protection, session ordering, the hash chain, the nineteen hooks
and wrapped MCP. Everything ACS leaves open sits behind four
interfaces, which are also the extension points.

```mermaid
flowchart LR
    Codex["Codex"] -->|runs| CH["acs-codex-hook"]
    OpenCode["OpenCode"] -->|"plugin acs.ts runs"| OH["acs-opencode-hook"]
    CH --> HA["hostadapter.Client, sending through observedagent.Client"]
    OH --> HA
    HA -->|"POST /acs, signed request"| G["guardian.Guardian"]
    G -.->|"signed decision"| HA
    G --> S["Signer"]
    G --> SC["SessionContextStore"]
    G --> AL["AuditLog"]
    G --> PE["PolicyEngine"]
```

Solid arrows are calls. The dashed arrow is the signed decision coming back.

### The four interfaces

| Interface | Declared in | What ACS leaves open | Implementation in this module |
| --- | --- | --- | --- |
| `PolicyEngine` | [`guardian/policy_engine.go`](../guardian/policy_engine.go) | The policy decision (§12.1). | `agtbridge.Engine`, running AGT's Rego policies |
| `Signer` | [`guardian/signer.go`](../guardian/signer.go) | Keys and signatures (§10). | `guardian.HMACSigner`, HMAC-SHA256 |
| `SessionContextStore` | [`guardian/session_context_store.go`](../guardian/session_context_store.go) | Where session state and its hash chain live (§8). | `guardian.MemorySessionContextStore`, bounded and in memory |
| `AuditLog` | [`guardian/audit_log.go`](../guardian/audit_log.go) | Where the audit records go. | `guardian.JSONLAuditLog`, JSONL files |

Your own implementation can replace any of them without changing the core. The Guardian
package does not depend on AGT: `agtbridge` is the engine the standalone command
plugs in. [Extend the Guardian](extending.md) lists what your own implementation of each interface must do.

### How AGT is used

AGT ships its policy runtime for Node, Python, .NET and Rust, but not for Go;
its separate general-purpose Go SDK does not expose this runtime.
The TypeScript reference reaches it through AGT's Node package, whose Rust
runtime calls the OPA command-line program. The Go Guardian runs the same
checked-in AGT Rego policies, unchanged, with OPA's Go library in process.

`agtbridge` implements the part of AGT's runtime that the checked-in manifest
uses. It loads the manifest, builds the policy input, runs the `egress`
annotation, converts verdicts and keeps policy state. On the recorded sessions
it decides as AGT does. A manifest that needs a feature outside
that part, such as Cedar policies or `extends`, stops startup with a message
that names it. [Differences](differences.md#agt) lists the boundary.

## How a request moves through the Guardian

Every participant and call on these diagrams is a type or method in this module.

### The store calls on these diagrams

| Call | Why |
| --- | --- |
| `Lock` | Only one step of a session runs at a time, across every Guardian sharing the store, until `release`. |
| `Load` | Reads the session while it is locked, so it cannot change underneath. |
| `Negotiate` | Saves a new session's handshake terms. |
| `Append` | Records the step in the chain before it is decided, and rejects a repeated request. |
| `SkillApproved` | Tells whether a skill with this digest was approved at registration. |
| `Conclude` | Keeps what the decision leaves for later steps. Skipped when there is nothing to keep. |

### The handshake

Every session starts with `handshake/hello`. The PolicyEngine is not asked.

```mermaid
sequenceDiagram
    participant OA as observedagent.Client
    participant G as guardian.Guardian
    participant S as Signer
    participant SC as SessionContextStore
    OA->>G: handshake/hello with a ClientHello
    G->>S: Verify
    G->>SC: Lock
    G->>SC: Load
    alt no session yet
        Note over G: negotiates the terms from the ClientHello and its own offer
        G->>SC: Negotiate: save the ClientHello and the ServerHello
    else the session exists
        Note over G: the same ClientHello, key and agent get the saved ServerHello back, anything else is refused
    end
    G->>SC: release
    G->>S: Sign
    G-->>OA: ServerHello
```

### One step, in order

Every step takes the same path, in four stages.

```mermaid
sequenceDiagram
    participant OA as observedagent.Client
    participant G as guardian.Guardian
    participant AL as AuditLog
    participant S as Signer
    participant SC as SessionContextStore
    participant PE as PolicyEngine
    rect rgba(128, 128, 128, 0.08)
    Note over OA,S: A. Receive and authenticate
    OA->>G: signed request
    G->>AL: Envelope(inbound)
    G->>S: Verify
    end
    rect rgba(128, 128, 128, 0.16)
    Note over G,SC: B. Take the session
    G->>SC: Lock
    G->>SC: Load
    end
    rect rgba(128, 128, 128, 0.08)
    Note over G,PE: C. Record and decide
    Note over G: ACS rules that deny without the policy, see below
    G->>SC: Append
    opt no ACS rule denied the step
        G->>PE: Decide
        PE-->>G: PolicyDecision
    end
    opt the decision leaves something to keep
        G->>SC: Conclude
    end
    G->>SC: release
    end
    rect rgba(128, 128, 128, 0.16)
    Note over OA,S: D. Answer
    G->>S: Sign
    G->>AL: Envelope(outbound)
    G-->>OA: signed decision
    end
```

### ACS rules that deny without the policy

```mermaid
flowchart LR
    A["before Append"] --> B{"Intent differs from<br/>the one set earlier?"}
    B -->|no| C{"chain_hash differs from<br/>the session head?"}
    C -->|no| D{"skillLoad without an<br/>approved skillRegister?"}
    D -->|no| E["Append, then Decide"]
    B -->|yes| X["DENY intent_mismatch"]
    C -->|yes| Y["DENY chain_mismatch"]
    D -->|yes| Z["DENY skill_unverifiable"]
    X & Y & Z --> F["Append, no Decide"]
```

Three more steps get their own handling: `steps/sessionEnd` closes the session, a
`steps/postCompact` summary has its lineage checked, and a `protocols/MCP/*` message is
checked by the MCP handler.

### The skill scenario

```mermaid
sequenceDiagram
    participant OA as observedagent.Client
    participant G as guardian.Guardian
    participant SC as SessionContextStore
    participant PE as PolicyEngine
    Note over OA,PE: Install the skill, once
    OA->>G: steps/skillRegister(skill_id, digest)
    G->>PE: Decide
    PE-->>G: ALLOW or DENY
    opt ALLOW
        G->>SC: Conclude: save the approval of skill_id and digest
    end
    G-->>OA: ALLOW or DENY
    Note over OA,PE: Load the skill, in this or any later session
    OA->>G: steps/skillLoad(skill_id, digest)
    G->>SC: SkillApproved(skill_id, digest)
    alt approved
        G->>PE: Decide
        PE-->>G: ALLOW or DENY
        G-->>OA: ALLOW or DENY
    else not approved
        G-->>OA: DENY skill_unverifiable
    end
```

### The ASK scenario

```mermaid
sequenceDiagram
    participant OA as observedagent.Client
    participant G as guardian.Guardian
    participant SC as SessionContextStore
    participant PE as PolicyEngine
    OA->>G: step A
    G->>PE: Decide
    PE-->>G: ASK
    G->>SC: Conclude: step A waits for an answer
    G-->>OA: ASK
    Note over PE: learns the approver's answer by its own means, or from step B
    OA->>G: step B, later
    G->>PE: Decide
    PE-->>G: decision with a Grant that answers step A
    G->>SC: Append(intent_extension), when the Grant covers the rest of the session
    G-->>OA: decision
```

ACS v0.1.0 defines no wire method for the approver's answer (#175).

### The DEFER scenario

```mermaid
sequenceDiagram
    participant OA as observedagent.Client
    participant G as guardian.Guardian
    participant SC as SessionContextStore
    participant PE as PolicyEngine
    OA->>G: step A
    G->>PE: Decide
    PE-->>G: DEFER
    G->>SC: Conclude: count one more deferral in the session
    G-->>OA: DEFER
    Note over PE: resolves the deferred case by its own means
    Note over OA: waits, then sends the same action again
    OA->>G: step B, later
    G->>PE: Decide
    PE-->>G: final decision
    G-->>OA: final decision
```

ACS v0.1.0 defines no way to tell the Observed Agent that a DEFER is resolved (#14), so the
Observed Agent sends the action again. An engine that has not resolved the case answers DEFER again. A
session gets at most `MaxDeferrals` DEFER answers, 3 by default; the next one is DENY
`deferral_bound_exceeded`.

### Calls by method

| Method | `AuditLog` | `Signer` | `SessionContextStore` | `PolicyEngine` |
| --- | --- | --- | --- | --- |
| `handshake/hello` | both envelopes | `Verify`, `Sign` | `Lock`, `Load`, `Negotiate`; `Reserve` for a repeated handshake | `Policy()` only, read once at `guardian.New` |
| a native hook, `protocols/MCP/*` | both envelopes, events | `Verify`, `Sign` | `Lock`, `Load`, `Append`; `Reserve` after sessionEnd; `Conclude`, `SkillApproved` as the step needs | `Decide` |
| `system/ping` | both envelopes | `Verify` and `Sign` only when the ping is signed | none | none |

- Sessions run in parallel. No interface calls another, and none calls the Guardian.
- The store keeps the negotiated `ServerHello`.
  - Every replica uses it for the session's timeout, timestamp window, negotiated methods,
    version and approver types.
  - A replica with a different configuration applies it to new sessions only.
- Once a step is authenticated and names a negotiated method, every store, engine and
  internal failure is answered with a signed DENY.
  - An error would leave the Observed Agent to its failure posture, which proceeds by
    default.
  - The failure's detail goes to the `AuditLog` as a `failure` event; the wire carries a
    fixed message.
  - If the `Signer` itself cannot sign, the Guardian can only return an unsigned internal
    error.

## Read the code in this order

1. **Types and interfaces.** [`acs/`](../acs/) holds the ACS wire types: envelopes,
   the handshake, decisions, hook payloads and SessionContext objects. The four
   interface files are in [the table above](#the-four-interfaces).
2. **The built-in implementations.**
   [`guardian/hmac_signer.go`](../guardian/hmac_signer.go) signs the canonical form
   built in [`internal/jcs/`](../internal/jcs/) and
   [`internal/envelope/`](../internal/envelope/); [canonical form](canonical-form.md)
   explains the bytes.
   [`guardian/memory_session_context_store.go`](../guardian/memory_session_context_store.go)
   keeps sessions and the hash chain from [`internal/chain/`](../internal/chain/), and
   [`guardian/guardiantest/`](../guardian/guardiantest/) is the test suite any store
   must pass. [`guardian/jsonl_audit_log.go`](../guardian/jsonl_audit_log.go) writes
   audit records.
3. **The core.** `Guardian.answer` in [`guardian/guardian.go`](../guardian/guardian.go)
   validates, authenticates and routes each request. `handshake` and `step` in
   [`guardian/step.go`](../guardian/step.go) take it to a signed answer;
   [one step, in order](#one-step-in-order) draws the same path.
   The helpers: [`internal/schema/`](../internal/schema/) validates against the
   specification's schemas, [`internal/handshake/`](../internal/handshake/) negotiates
   the session, [`internal/method/`](../internal/method/) routes the nineteen hooks,
   [`internal/disposition/`](../internal/disposition/) checks each decision and
   [`internal/mcp/`](../internal/mcp/) reads wrapped MCP messages.
   [`cmd/guardian/`](../cmd/guardian/) is the standalone program around the core.
4. **The AGT engine.** [`agtbridge/`](../agtbridge/), described in
   [how AGT is used](#how-agt-is-used).
5. **The Observed Agent side.** [`internal/observedagent/`](../internal/observedagent/) is the
   bundled Observed Agent client: it signs requests and checks answers, and the
   tests drive the Guardian through it.
   [`internal/hostadapter/`](../internal/hostadapter/) builds a host integration on
   it, and [`examples/codex/`](../examples/codex/) and
   [`examples/opencode/`](../examples/opencode/) are the two host adapters.
   [`examples/custom-engine/`](../examples/custom-engine/) implements all four
   interfaces without AGT.
