# Frequently Asked Questions

This page answers questions ACS gets from enterprise security teams, framework implementers, researchers working on agent-security paradigms, and the press. If your question is not answered here, open an issue or join the working group.

> **This section is non-normative.** It explains the standard in plain language and defines nothing. Where this page and a specification document disagree, the specification governs. [Conformance Profiles](../spec/conformance.md) is the normative statement of what each profile requires.

---

## About ACS

### What is ACS?

ACS (Agent Control Standard) is a runtime governance specification for AI agents. It defines how an agent reports the actions it is about to take, how an external policy engine ("Guardian Agent") responds with a decision, what behavior the agent must exhibit in response, and what audit record the interaction leaves behind. The spec is organized into three pillars:

```
   ┌──────────────────────────────────┐  ┌──────────────────────────────────┐  ┌──────────────────────────────────┐
   │ Instrument                       │  │ Trace                            │  │ Inspect                          │
   │ Runtime hooks + dispositions     │  │ Deterministic event emission     │  │ Agent Bill of Materials          │
   │                                  │  │                                  │  │                                  │
   │ • 19 lifecycle hooks (steps/*)   │  │ • OTel semconv mappings,         │  │ • Canonical AgBOM schema         │
   │ • Disposition vocabulary         │  │   one per step                   │  │ • CycloneDX 1.6 serialization    │
   │   (allow / deny / modify /       │  │ • OCSF event-class mappings,     │  │ • SPDX 3.0 serialization         │
   │    ask / defer)                  │  │   one per step                   │  │ • SWID serialization             │
   │ • Two-layer Guardian             │  │ • Deployment emits at least      │  │ • agbom/snapshot at session start│
   │ • Approver model (ASK)           │  │   one of OTel / OCSF             │  │ • agbom/changed on every         │
   │ • SessionContext + Intent        │  │ • Decision-as-span-event rule    │  │   mid-session mutation           │
   │ • Replay protection              │  │ • Provenance carried forward     │  │                                  │
   │ • JSON-RPC 2.0 envelope          │  │   onto every emitted event       │  │                                  │
   │ • HMAC-SHA256 baseline signature │  │                                  │  │                                  │
   │ • Liveness (system/ping)         │  │                                  │  │                                  │
   └──────────────────────────────────┘  └──────────────────────────────────┘  └──────────────────────────────────┘
```

The full picture is in [Core Concepts](./core_concepts.md).

### Why does this need a standard?

Today, every agent framework logs differently, gates differently, and exposes a different set of interception points. An enterprise running agents across multiple coding assistants, IDE copilots, and runtime frameworks writes a custom integration per framework for one security policy. ACS removes that duplication: a single Guardian, written once against the standard, governs every framework that adopts it.

### What is a hook?

A hook is a **checkpoint** the framework pauses at whenever the agent is about to do something consequential: call a tool, read or write memory, send a message, hand off to a sub-agent, load a skill. At the checkpoint the framework sends the proposed action and its context to the Guardian, and at decision-eligible hooks waits for the decision before proceeding.

The analogy: airport security. Every passenger crosses the same set of checkpoints before boarding. A passenger cannot bypass a checkpoint by being important or being in a hurry, and the framework cannot bypass a hook either. The checkpoint asks one question — should this proceed? — and the outcomes look familiar: most passengers walk through (`allow`), some are turned away (`deny`), some surrender the water bottle and continue (`modify`), some get pulled aside for a supervisor's judgment (`ask`), and some wait while a question gets resolved (`defer`). At the fourteen decision-eligible hooks the journey continues based on the answer; the audit-only hooks are cameras rather than gates — everything is recorded on the way through.

ACS defines 19 `steps/*` lifecycle hooks. Fourteen of them are decision-eligible, meaning the Guardian can stop or change what happens next. The other five fire after the fact and are audit-only records: `postCompact`, `subagentStop`, `skillUnload`, `turnEnd`, and `sessionEnd`. Size your policy work and latency budget against the fourteen. The `agbom/*` methods are also decision-eligible, and `system/ping` is not, since a Guardian always answers it with `allow` ([§13](../spec/instrument/specification.md#13-liveness-system-methods)).

The audit-only hooks matter too: they are how the audit chain learns that the thing finished.

### How does it all combine in one session?

Four moves, in order:

1. **Session starts.** The framework and Guardian shake hands and declare what each supports. The framework sends an Agent Bill of Materials (AgBOM) listing what the agent is composed of: models, tools, MCP servers, skills.
2. **The agent runs.** Every consequential action fires a hook before it executes. The Guardian decides. The framework honors the decision.
3. **Everything is recorded.** Every decision lands in a hash-chained audit log. Every step emits OpenTelemetry and OCSF events into the SIEM the security team already uses. If the agent picks up a new tool or loads a skill mid-session, the AgBOM updates and the Guardian sees it.
4. **Session ends.** The audit chain is sealed and signed. The whole session is reconstructible from the record.

That is the three pillars at work: **Instrument** (the hooks and decisions), **Trace** (the events flowing into the SIEM), **Inspect** (the AgBOM tracking what is there). One spec, one Guardian, one audit chain across whatever frameworks the deployment runs.

### Who needs ACS?

Three groups, with different motivations:

- **Enterprise security teams** running multiple AI agents (coding assistants, IDE copilots, internal automations) need one policy that governs all of them. ACS gives them one runtime control envelope — wire contract, Guardian, audit chain, Trace events into the SIEM, AgBOM into supply-chain tooling — that works across every conformant framework, instead of building each piece per framework.
- **Framework and platform builders** need a way to make their security story portable. Adopting ACS means their customers' existing security investments work against the framework on day one, without bespoke integration.
- **Compliance and audit functions** need their agent governance to produce a record an outside auditor will trust — tamper-evident, cryptographically signed, and reconstructible after the fact. The first two groups want to prevent the wrong action in real time; this group needs to *prove* what happened, months later, in a form that survives a regulator's challenge. ACS-Audit (hash-chained audit log committing to request content) plus ACS-Crypto (signed envelopes, post-quantum-ready) produce that record; most off-the-shelf agent platforms cannot.

This is true even for a single agent on a single framework. ACS adds four concrete things on top of what the framework provides: actions intercepted before they execute (the framework calls the Guardian and waits before sending the email or making the API call), a hash-chained audit log of every action and decision, a policy authority that sits outside the agent's LLM context, and OTel + OCSF event streams the SIEM consumes without bespoke parsing.

On that third one, be precise about what "outside" buys you. A deterministic Guardian running Cedar or Rego evaluates policy the agent's context cannot reach. A deployment that also enables the optional LLM-backed Agent layer puts a second model in the path, and that model does read attacker-reachable content, which is why [§12.2](../spec/instrument/specification.md#122-agent-layer) requires it to treat untrusted data as data and to wrap untrusted fields. The deterministic layer always runs first.

### What is new here?

Existing efforts solve one slice each. Vendor governance tools come with each vendor's own policy library and policy language, work only against the frameworks the vendor has integrated, and produce the vendor's own audit format. Research frameworks like FIDES, CaMeL, and IBAC define *enforcement mechanisms* (information flow control, intent-bound authority, capability separation) but not what to enforce and not a wire contract. Observability standards like OpenTelemetry and OCSF record what happened but do not gate what is about to happen. ACS is the contract that lets all of these compose: vendors compete on Guardian quality, paradigms ride on top, observability stacks consume the resulting events.

### Who is behind ACS?

ACS is an OWASP project. It is a vendor-neutral community effort: workstream leads come from multiple organizations, no single company owns or steers the standard, and every pull request goes through community review.

Work is split across five workstreams, each owning a slice of the standard and running its own review. **[GOVERNANCE.md](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/GOVERNANCE.md) is the authoritative roster**, naming the project lead, the two leads per workstream, and the founding credit. It is kept in sync with repository write access and `CODEOWNERS`, which a table copied into this page would not be. Read it there rather than here.

Contribution guidance is in [CONTRIBUTING.md](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/CONTRIBUTING.md).

---

## Scope and boundaries

### Is ACS another agent framework?

No. Agent frameworks and ACS sit at different layers. A framework builds the agent — it gives developers the tools, memory, planning, orchestration, and model choice to construct one. ACS is a **runtime governance specification**: it defines both the wire contract between the framework and a Guardian and the behavior the framework must exhibit (for example, the framework must wait for the Guardian's decision before acting on it). Any agent framework can be ACS-conformant; ACS doesn't compete with frameworks, it's the standard they conform to so an enterprise's security infrastructure can hold the agent accountable.

### Does ACS replace MCP or A2A?

No. ACS wraps them. MCP messages flow through `protocols/MCP/*` ACS methods so the same Guardian can govern an MCP tool call as a native tool call. A2A wrapping arrives in v0.2 ([Specification §extend_a2a](../spec/instrument/a2a/extend_a2a.md)). The composition rule: every protocol-spanning message crosses an ACS hook on the way out and on the way back.

### Does ACS define what policies to enforce?

No. ACS defines the contract for asking the policy and honoring its answer. The policy itself is the deployment's choice: deterministic rules in OPA/Rego, a Cedar policy bundle, an LLM-backed reasoner under the Agent layer, or any combination. v0.1 leaves the policy language unconstrained and the policy library to the deployment.

### Is ACS just observability?

No. ACS grew out of an earlier effort called **AOS (Agent Observability Standard)**, which covered event emission alone. Runtime enforcement became the working group's central concern as the spec matured, so it gained hooks that fire **before** an action executes, dispositions the agent honors (`allow`, `deny`, `modify`, `ask`, `defer`), and the runtime behavior that goes with them. The rename to ACS reflects that wider scope.

Observability is now one of three pillars. Trace records what happened, Instrument gates what is about to happen, and Inspect inventories what the agent is made of. A deployment can run Trace alone and get a strong audit stream, though the enforcement property comes from Instrument.

### Does ACS prevent prompt injection?

No, and no runtime mechanism can. Current research finds essentially every production LLM remains vulnerable to some form of prompt injection. What ACS adds is that the agent acting on injected reasoning becomes visible and gateable, rather than silent.

One caveat belongs here rather than buried further down. The default failure posture is fail-open with a mandatory audit record, so an attacker who can stall or break the Guardian channel converts enforcement into audit. Deployments that will not accept that trade set `on_decision_failure: deny`. See [what happens when the Guardian fails](#what-happens-when-the-guardian-fails).

The mechanism is **deviation detection**. ACS requires the agent to declare what it is doing this session (its intent) and to send each proposed action through a Guardian before executing it. The Guardian compares the action against three things: the declared intent, the policy library, and the trust basis of the data driving the action. An injected agent generally deviates on at least one of those three, and the Guardian denies, modifies, or escalates the action before it runs.

Injection still happens. The LLM's reasoning still gets corrupted by attacker-controlled input. But the action it would have taken becomes visible, gated, and auditable, which is a strictly stronger property than asking the model to ignore attacker instructions in the first place.

---

## For framework implementers

### How do I make my framework ACS-conformant?

Implement **ACS-Core**. [Conformance Profiles](../spec/conformance.md) is the authority on exactly what that requires and at what strength. Rather than restate it here and let the two drift apart, this answer describes the shape of the work.

You are building ten things:

- **A handshake.** `handshake/hello`, where both sides declare what they support and negotiate the session.
- **An envelope.** JSON-RPC 2.0 carrying `request_id`, `timestamp`, `acs_version`, and `metadata`.
- **A hook surface.** Enough of the lifecycle that a Guardian sees the session start, the agent's inputs and outputs, tool calls going out and coming back, sub-agent spawns where the framework has them (`subagentStart` — the gate against cross-agent propagation), and the session end.
- **The disposition vocabulary.** `allow`, `deny`, `ask`, and `defer` are Core requirements; `modify` support is recommended. A Guardian substitutes `deny` for clients that cannot apply `modify` ([Specification §6.5](../spec/instrument/specification.md#65-modify-incapable-clients-normative)).
- **Session state.** `session_id`, a rolling `chain_hash`, and an append-only ContextEntry chain whose head the Guardian publishes on content-bearing responses. Intent is optional at Core and load-bearing for IBAC deployments.
- **Replay protection.** A UUID `request_id` and a `timestamp` on every request, which the Guardian checks.
- **Baseline integrity.** An HMAC-SHA256 signature over the canonical envelope, keyed per session via HKDF.
- **Decision honoring.** Wait for the verdict and apply it. On timeout, transport failure, or an error with no decision, apply the negotiated `on_decision_failure` posture (`proceed` by default, which is fail-open) and record every fail-open proceed as an audit event.
- **Liveness.** `system/ping`, or a declared alternative (transport keepalive, process supervision, or continuous hook traffic).
- **Wrapped MCP.** `protocols/MCP/*` when sessions involve MCP. `tools/call` may collapse into the generic tool hooks; the wrapped forms carry what those hooks cannot see (capability negotiation, prompt fetches, resource reads, notifications).

The remaining hooks (`turnStart`/`turnEnd`, `preCompact`/`postCompact`, `subagentStop`, `knowledgeRetrieval`, `memoryContextRetrieval`, `memoryStore`, `skillRegister`/`skillLoad`/`skillUnload`) are defined in the spec and worth implementing wherever your framework can observe the matching event. The handshake declares what you implement and the Guardian negotiates against it.

Check the conformance chapter for which of these are strictly required and which your deployment can decline and still claim ACS-Core. That line moves as the spec evolves, and this page deliberately does not duplicate it.

ACS-Core asks for none of field-level Provenance, Trace event emission, AgBOM, asymmetric or post-quantum signatures, or `request_hash` on ContextEntry. Those are optional profiles you layer on.

```
                       ┌────────────────────────┐
                       │  ACS-Core (mandatory)  │
                       └────────────────────────┘
                                   │
       ┌─────────────┬─────────────┼─────────────┬─────────────┐
       │             │             │             │             │
       ▼             ▼             ▼             ▼             ▼
   ┌─────────┐ ┌─────────┐  ┌─────────────┐ ┌──────────┐ ┌──────────┐
   │acs-trace│ │acs-     │  │ acs-        │ │acs-crypto│ │acs-audit │
   │         │ │inspect  │  │ provenance  │ │          │ │          │
   └─────────┘ └────┬────┘  └─────────────┘ └──────────┘ └──────────┘
                    │
                    ▼
            ┌──────────────────┐
            │ acs-inspect-     │
            │ dynamic          │
            └──────────────────┘
```

Profiles compose: a minimal IDE harness declares `["acs-core"]`; a full-coverage enterprise deployment declares all seven. The handshake makes the choice explicit and the Guardian negotiates accordingly.

### What if my framework does not have a particular hook surface?

The framework advertises in `methods_implemented` at handshake time exactly the hooks whose events it can observe. The Guardian's `methods_evaluated` response names the subset it will actually evaluate against policy, and the Guardian may refuse the session if a hook its policy requires is absent. So the negotiation is explicit on both sides — the framework says what it can emit, the Guardian says what it needs to see, and they either agree to proceed or the session does not start.

The conformance line is between *not having the surface* and *suppressing the hook for an event that did happen*. The first is fine and negotiated explicitly. The second is non-conformant: a framework that observed the event and skipped the hook is in violation, regardless of which surrounding hooks it did fire.

### Does ACS require a specific transport, cryptography, or identity system?

No, same principle for all three: ACS specifies the category (you need a transport, you need signed envelopes, you need an identity scheme) and catalogs the options the spec defines; the deployment picks which.

- **Transport.** v0.1 defines HTTP(S) (for SaaS, on-prem, multi-tenant Guardians) and stdio (for IDE-embedded Guardians); gRPC and unix sockets are deferred to v0.2. The handshake declares which is in use, and the envelope and method semantics are transport-agnostic.
- **Cryptography.** ACS-Core's baseline is HMAC-SHA256, which any deployment can satisfy without infrastructure investment. ACS-Crypto adds asymmetric and post-quantum algorithms (ML-DSA-65 primary, SLH-DSA-128s backup, hybrid composites for transitional deployments) for deployments that need non-repudiation or PQC readiness.
- **Identity.** SPIFFE, OIDC, mTLS, and organizational PKI are all deployment choices; ACS reserves `policy_references[].policy_version` as a stable pointer so audit replay works regardless of the scheme.

**ACS catalogs what exists; the deployment picks what to use.**

### Where is the schema?

JSON Schemas for every envelope and hook payload are under [`specification/v0.1.0/`](https://github.com/GenAI-Security-Project/agent-control-standard/tree/main/specification/v0.1.0). Data-bearing hooks ship two variants: the base schema (permissive, where `provenance` is optional) and the `*.acs-provenance.json` strict variant required by the ACS-Provenance profile.

---

## For enterprises

### How do I deploy ACS?

Four steps:

1. **Pick or build a Guardian.** Options: in-house implementation, vendor product, or open-source reference implementation.
2. **Deploy the Guardian in your security perimeter** — the same place you put other policy enforcement infrastructure (VPC, behind your auth boundary).
3. **Configure each agent platform to point its hook surface at the Guardian** — over HTTP(S) for SaaS, on-prem, and multi-tenant deployments; over stdio for IDE-embedded ones.
4. **Populate the Guardian's policy library and declare your profiles in the handshake** — `acs-core` is mandatory; add `acs-trace`, `acs-inspect`, `acs-provenance`, `acs-crypto`, and `acs-audit` as your deployment needs.

### Does ACS work in IDE, SaaS, and on-prem deployments?

Yes. The IDE case (coding assistants and IDE copilots) uses stdio transport with implicit process-spawn authentication. The SaaS case uses HTTP(S) with mTLS or bearer tokens. The on-prem case can use either, depending on whether the Guardian is in the same process tree or accessed over the network. The handshake negotiates which transport, which auth, and which profiles apply.

### What is the operational overhead?

Depends on the implementation, and the project has published no benchmark, so this answer describes the shape of the cost rather than quoting numbers.

Each gated action costs one Guardian round trip. Hooks fire on actions that cross out into the real world (tool calls, memory writes, external messages), so the count scales with action volume rather than token volume. A deterministic Guardian on Cedar or Rego, co-located with the agent, is the cheap case. Latency then depends on where the Guardian runs, how the transport is configured, and how much policy it evaluates, which is why the honest answer is to measure your own deployment rather than trust a range quoted here.

Two costs are easy to miss when estimating. Where the adapter spawns a process per hook rather than holding a connection, that spawn can dominate the Guardian's own evaluation time. And a deployment that routes some escalations to the optional LLM-backed Guardian layer pays inference cost per escalation on top, which is the tuning knob.

### What happens when the Guardian fails?

The default is fail-open with mandatory audit: if the Guardian times out, the transport fails, or the Guardian returns an error, the action proceeds and the bypass is recorded as an audit event. Deployments that prefer fail-closed flip one field in the handshake (`on_decision_failure: deny`). One subtlety: when the Guardian responds with DEFER and the resolution itself times out, that fails closed by default. Silence fails open; expressed-but-unresolved concerns fail closed. See [Specification §6.4](../spec/instrument/specification.md#64-honoring-decisions-normative).

```
              ┌────────────────┐
              │ Hook submitted │
              └────────────────┘
                       │
                       ▼
              ┌────────────────┐
              │   Guardian     │
              └────────────────┘
                │            │
       responds │            │  no response in time
       in time  │            │  (timeout / error / silence)
                ▼            ▼
   ┌──────────────────┐  ┌──────────────────────────────┐
   │  Apply decision  │  │  Decision failure            │
   │                  │  │                              │
   │  allow / deny /  │  │  default:  proceed           │
   │  modify / ask /  │  │            + audit event     │
   │  defer           │  │                              │
   │                  │  │  opt-in:   deny  (blocked)   │
   └──────────────────┘  └──────────────────────────────┘
```

### Does ACS handle multi-tenancy?

The wire reserves an optional `tenant_id` field in v0.1. Detailed multi-tenant isolation (per-tenant policy scoping, SessionContext isolation, cross-tenant A2A rules) is deferred to v0.2 when SaaS Guardian providers need it. The v0.1 commitment is the field, so deployments adopting ACS today do not face a breaking-change migration when isolation rules ship.

### How does ACS integrate with my existing security stack?

Through the Trace pillar. ACS-Trace requires every step to emit at least one of an OpenTelemetry span or an OCSF event with the required attributes. So any SIEM or observability back-end that accepts OpenTelemetry or OCSF consumes ACS events the same way it consumes anything else. The Inspect pillar emits an Agent Bill of Materials in CycloneDX, SPDX, or SWID, which feeds standard SBOM and supply-chain tooling.

### How does ACS map to OWASP Top 10, NIST AI RMF, and the EU AI Act?

ACS exposes control points and audit surface; the deployment's policy library decides what gets caught. The mapping is mechanism-to-control, not promise-to-eliminate.

**[OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):**

| OWASP risk | ACS mechanism |
|---|---|
| ASI01 Agent Goal Hijack | `Intent.parsed` is established at session start or the first `agentTrigger` and is immutable to the runtime LLM; IBAC-style policy checks actions against it, while `userMessage` and `agentTrigger` gate new inputs before they enter reasoning |
| ASI02 Tool Misuse & Exploitation | `toolCallRequest` gates every outward action before execution; where `modify` is supported, policy can redact or override arguments in flight |
| ASI03 Identity & Privilege Abuse | Core hook envelopes carry replay protection and a signature using a per-session HKDF-derived key; `subagentStart.intent_derivation` lets policy deny delegation that would widen the parent's authority |
| ASI04 Agentic Supply Chain Vulnerabilities | AgBOM inventories components and `agbom/changed` is decision-eligible on mutation; `skillRegister` exposes the definition, `declared_capabilities`, digest, and `registration_provenance` for vetting before any action runs, and `skillLoad` correlates each activation to an approved `(skill_id, digest)` |
| ASI05 Unexpected Code Execution (RCE) | Process, code, and shell actions that escape the agent's reasoning context cross `toolCallRequest` before execution, so policy sees the exact command or code proposed |
| ASI06 Memory & Context Poisoning | `memoryStore` and `memoryContextRetrieval` gate memory writes and reads; with ACS-Provenance, lineage travels with stored content and `preCompact` / `postCompact` bind a summary to the entries it compacts |
| ASI07 Insecure Inter-Agent Communication | In-process spawning crosses the decision-eligible `subagentStart`; `subagentStop` records termination when emitted. Core hook envelopes carry replay protection and a baseline signature; A2A wrapping (`protocols/A2A/*`) is reserved for v0.2 |
| ASI08 Cascading Failures | A Guardian `deny` at `subagentStart` stops a spawn cascade at the boundary; parent and child session references preserve the propagation path in the audit record |
| ASI09 Human-Agent Trust Exploitation | ASK routes decisions to a human approver as a wire-level primitive; `agentResponse` gates agent output before delivery and records the proposed response together with the Guardian's decision |
| ASI10 Rogue Agents | Handshake identity and, with ACS-Inspect, the AgBOM baseline the agent's composition; continuous hook traffic makes behavior observable, and the Guardian can deny at any decision-eligible hook |

**NIST AI RMF:** the framework requires identification, measurement, and management of AI risks, with traceability and human-control obligations. ACS contributes the runtime traceability layer — ACS-Audit's hash-chained record, ACS-Inspect's AgBOM, ACS-Trace's events — and the ASK disposition gives human oversight as a wire-level primitive.

**EU AI Act (high-risk AI systems):** requires logging that allows post-hoc reconstruction, transparency obligations, and human oversight. ACS-Audit's `request_hash`-committing chain produces a tamper-evident reconstruction surface; ACS-Inspect's AgBOM identifies the components, models, and data sources used; ACS-Crypto's signed envelopes give non-repudiation. DEFER and ASK dispositions give human-oversight checkpoints expressible at the wire level.

A deployment claiming `acs-core` + `acs-provenance` + `acs-inspect` + `acs-audit` + `acs-crypto` covers the bulk of the surface across all three frameworks at the protocol level. Whether the coverage catches a specific attack or satisfies a specific auditor depends on the policy library and the deployment's procedures.

---

## For researchers and paradigm authors

### Does ACS support FIDES, CaMeL, IBAC, or AARM?

Yes, all four, on the same wire contract. ACS is paradigm-neutral on the contract and lets paradigm-specific intent ride on existing fields (`policy_data`, `reason_codes`, `cited_provenance_ids`, `policy_references`).

```
   ┌─────────┐                                            ┌──────────────────────────────────┐
   │  FIDES  │ ───► label joins from lineage ───────────► │ ACS-Provenance                   │
   │         │                                            │ + cited_provenance_ids           │
   └─────────┘                                            └──────────────────────────────────┘
   ┌─────────┐                                            ┌──────────────────────────────────┐
   │  CaMeL  │ ───► per-argument dependency graph ──────► │ Per-arg provenance               │
   │         │                                            │ + cited_provenance_ids           │
   └─────────┘                                            └──────────────────────────────────┘
   ┌─────────┐                                            ┌──────────────────────────────────┐
   │  IBAC   │ ───► authority bound at intent commit ───► │ SessionContext + Intent          │
   │         │                                            │ + ASK + dispositions             │
   └─────────┘                                            └──────────────────────────────────┘
   ┌─────────┐                                            ┌──────────────────────────────────┐
   │  AARM   │ ───► interception + tamper-evident      ──►│ Dispositions                     │
   │         │      receipts                              │ + ACS-Audit chain                │
   └─────────┘                                            └──────────────────────────────────┘
```

How each paradigm composes with ACS:

- **FIDES** — uses ACS-Provenance lineage from each hook payload to run its integrity / confidentiality label arithmetic. ACS carries the `origin`, `source_id`, and `derived_from` facts; the FIDES Guardian computes the label joins and decides what the planner sees.
- **CaMeL** — uses per-argument provenance to reconstruct the data-flow dependency graph, then applies its capability calculus against tool calls. ACS carries the dependency facts; the CaMeL Guardian runs the policy against them.
- **IBAC** — uses SessionContext + Intent for authority binding, the ASK disposition for approver-driven extensions, and the authorize-before-action flow for enforcement. ACS carries the wire fields and enforces `Intent.parsed` immutability; the IBAC Guardian provides the intent parser, capability-matching logic, and approver UX.
- **AARM** — maps to ACS-Core almost directly. AARM-style deployments declare ACS-Audit for the tamper-evident receipt chain and adopt AARM's receipt conventions on top.

The pattern across all four: ACS contributes the wire format and runtime behavior; the paradigm contributes the policy substance. Together they make the paradigm portable across any conformant framework.

### How is ACS different from those research artifacts?

The papers define enforcement *mechanisms* (label-based information flow, intent-bound authority, capability separation, interception with receipts) and prove what guarantees those mechanisms give. They do not define what to enforce (still the deployment's policy library), and they do not ship a wire contract a security team can deploy against frameworks they do not control. ACS sits at a different layer: the mechanism stays the paradigm's; the wire format and runtime behavior that let the mechanism cross frameworks is ACS's.

Beyond that layer difference, ACS specifies five things none of AARM, FIDES, CaMeL, IBAC, or Conseca specifies:

1. **A complete wire envelope** — JSON-RPC 2.0 with required fields, disposition vocabulary (allow / deny / modify / ask / defer), replay protection, baseline HMAC-SHA256 integrity. The actual bytes a framework emits.
2. **A concrete hook taxonomy** — 22 named methods, being the 19 `steps/*` lifecycle hooks plus `agbom/snapshot`, `agbom/changed`, and `system/ping`, each with a JSON schema and a fixed firing context. The research frameworks describe abstract control points (`intent.parse`, `action.authorize`, `context.ingest`); ACS defines them as concrete wire methods with payloads.
3. **Three-pillar coverage in one spec** — Instrument (runtime control), Trace (observability), Inspect (inventory). Each research framework addresses one slice.
4. **Conformance profiles** — declarable tiers (`acs-core`, `acs-trace`, `acs-inspect`, `acs-inspect-dynamic`, `acs-provenance`, `acs-crypto`, `acs-audit`) letting deployments mix capabilities and Guardians negotiate compatibility at handshake time.
5. **Runtime behavior contract** — the agent waits for the Guardian's decision, honors the disposition, records fail-open proceeds. AARM describes the architecture; ACS specifies the conformance behavior.

The composition story is the practical payoff: one Guardian can run FIDES, IBAC, and AARM-style enforcement against the same hook payloads at the same time, because the wire stays paradigm-neutral.

### Where do I plug in a new paradigm?

ACS is intentionally extensible without wire surgery. A new paradigm names itself a key in `policy_data` (conventionally lowercase, e.g. `"my-paradigm": { ... }`), defines its `reason_codes` vocabulary, optionally proposes a conformance profile if it needs a declarable capability tier, and writes a binding to one of the reference policy engines (OPA/Rego is the v0.1 reference). The wire contract stays neutral. See [Spec Review Principle 4](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/SPEC_REVIEW_PRINCIPLES.md#4-the-wire-is-paradigm-neutral-new-paradigms-ride-existing-elements-first).

### Will ACS adopt my paradigm into the core spec?

When a paradigm needs a wire signal that no existing field can carry, yes. That is the bar for promoting something from `policy_data` into a top-level field. Field-level Provenance was promoted because trust-laundering across summaries and memory writes is unrecoverable from logs (Spec Review Principle 3). Most paradigms do not cross that bar and ride existing elements indefinitely, which is the intended behavior.

---

## Versioning and roadmap

### What is in v0.1.0?

ACS-Core (mandatory), and six optional profiles: ACS-Trace, ACS-Inspect, ACS-Inspect-Dynamic, ACS-Provenance, ACS-Crypto, ACS-Audit. Full content lock and the design record are in [Conformance Profiles](../spec/conformance.md) and the [v0.1.0 schemas](https://github.com/GenAI-Security-Project/agent-control-standard/tree/main/specification/v0.1.0).

### What is coming in v0.2?

A2A wrapping (the `protocols/A2A/*` namespace is reserved in v0.1), the sensitivity / timeout model with method/capability mapping rules, multi-tenant isolation rules, batching and streaming hook semantics, and a Policy Attestation profile that binds policy references to verifiable author signatures. Conformance test machinery and a public registry are also v0.2 work.

### How do I follow or contribute?

The repo is [GenAI-Security-Project/agent-control-standard](https://github.com/GenAI-Security-Project/agent-control-standard). Working-group calls and contribution guidance are in [CONTRIBUTING.md](https://github.com/GenAI-Security-Project/agent-control-standard/blob/main/CONTRIBUTING.md). Issues are open across all three pillars.
