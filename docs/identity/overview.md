# Identity for Agents Overview

> **Note:** This is a working document. It is not intended to be comprehensive and will evolve as the ACS Identity workstream matures. Content, scope, and recommendations are subject to change.
>

There are 5 unique identity challenges that this standard aims to solve, where existing use cases that traditional identity models cannot support. It does not propose a wire format or normative requirements yet. Those will follow once the working group has aligned. This is an evolving space and we are taking a conservative approach with normative requirements.

For taxonomy and definitions, see [Core Concepts](../topics/core_concepts.md), which introduces identity alongside the pillars and links back here.

## What's Changing with Agents

For decades, application security worked because software was deterministic.

A traditional application follows a predefined execution path. Security teams can inspect the code, review dependencies, define permissions, and understand expected behavior before deployment. Identity policies can be established in advance because the software's capabilities are known before it runs. A car rental website cannot suddenly provide therapy advice, manage payroll, or execute financial transactions because those capabilities do not exist in its code.

```text
Traditional Software

Code
  ↓
Dependencies
  ↓
Permissions
  ↓
Execution

Behavior Known Before Runtime
```

Large Language Models (LLMs) introduced a fundamentally different execution model. Unlike traditional software, an LLM does not execute a fixed sequence of instructions. It generates outputs probabilistically based on its training data, prompts, and context. The same prompt can produce different outputs across executions.

```text
Prompt
  ↓
Model Reasoning
  ↓
Generated Output

Behavior Determined At Runtime
```

This introduced non-determinism into systems that had previously been predictable. On its own, however, an LLM is mostly generating text. Agents act, plan, call tools, invoke other agents, and reach production systems in milliseconds. Today most of them act under a borrowed human identity or a single static service account. That breaks accountability, breaks least-privilege, and makes the ACS Trace pillar lie about who did what.

At runtime an agent determines:

- What tool to call
- What data to retrieve
- Which API to invoke
- Whether to delegate to another agent
- What action to perform

The effective execution path is assembled dynamically while the system is running.

```text
Agent

Goal
  ↓
Model Reasoning
  ↓
Tool Selection
  ↓
Data Retrieval
  ↓
Delegation
  ↓
Action

Behavior Composed During Runtime
```

Two executions of the same agent on the same task can take entirely different paths. Recent academic work characterizes this as agents resolving capability *probabilistically* at runtime rather than at build time — see *SOK: A Taxonomy of Attack Vectors and Defense Strategies for Agentic Supply Chain Runtime* ([arXiv:2602.19555](https://arxiv.org/abs/2602.19555)), which describes how agentic systems shift the attack surface from build-time dependencies to *inference-time* dependencies assembled from untrusted data and probabilistic capability resolution. Unlike traditional software, where dependencies are resolved before deployment, agentic systems assemble portions of their effective execution context at runtime. Retrieved documents, tool outputs, external APIs, memory entries, and other agents become runtime dependencies selected through probabilistic reasoning rather than predetermined code paths.

This breaks the assumptions identity standards were designed around. Human identity standards assume a long-lived principal, a session, and a narrow blast radius per action. Workload identity standards assume the workload's behavior is determined by its code. Neither holds for agents.

Traditional identity models assume:

- The actor is known
- The execution path is known
- The permissions are known
- The delegation chain is known

Agent systems invalidate all four assumptions.

The question is no longer:

> Who is the principal?

The question becomes:

> Who is acting, on whose behalf, for what purpose, using what authority, through which delegation chain, at this moment?

That is the runtime identity problem ACS aims to solve.

An agent has a goal, a set of tools, some memory, and a model that decides at runtime what to call next, in what order, with what arguments. The effective code path is composed in the moment, by a non-deterministic component, based on whatever the agent just read. The supply chain you signed off on at build time is not the supply chain that executes.

A single tool call can chain through nine or more identities: the human user, the platform, the orchestrator, one or more sub-agents, the model, the tool, the downstream API, the trigger source, and the data subject. Each hop needs its own scope. Each hop needs to be verifiable. Today, identity at runtime is usually one or two of those at best.

```text
Human ──delegates──▶ Orchestrator Agent ──delegates──▶ Sub-Agent ──invokes──▶ Tool ──acts on──▶ Resource
   │                       │                              │                     │
   │                       ▼                              ▼                     ▼
   │              ingests RAG / docs / web      may spawn more sub-agents   external write
   │              (untrusted instructions)                                   (irreversible)
   │
   └──── audit subject: which link in this chain, under which intent? ────────────────▶
```

Agent systems are introducing a new class of failures where every token is valid, every API call is authorized, and the outcome is still a security incident.

---

## The 5 Unique Runtime Identity Challenges for Agents

These are the five unique runtime identity challenges that distinguish agent systems from human or workload identity. Each one is a place where existing standards fall short and where the ACS Identity workstream is concentrating its effort. The list is deliberately tight: every challenge below is genuinely distinct and together they cover the runtime surface that today's identity standards do not.

A concrete example that illustrates several of these challenges is Palo Alto Networks Unit 42's 2025 research, *[Agent Session Smuggling in Agent2Agent Systems](https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/)*. In the demonstrated attack, a malicious agent injected hidden instructions into a legitimate Agent2Agent (A2A) session. The victim agent subsequently disclosed sensitive information and performed unauthorized actions while using valid credentials and authorized APIs. Authentication and authorization succeeded. The failure occurred because the runtime could not distinguish user intent from adversarial instructions introduced during execution. This illustrates the central identity challenge of agent systems.

| # | Challenge / Question | Why It's Challenging | Standards Today That Aren't Sufficient | What Needs to Change for Runtime | ACS Mechanism |
|---|---|---|---|---|---|
| 1 | **Chain Integrity**<br/>*Can the full delegation chain be named and verified end-to-end?* | A single agent task can chain through five to ten identities: user → orchestrator → sub-agent → tool → downstream API. Two failures compound: the chain is not *named* (audit collapses into "the agent did it"), and the chain is not *verifiable* (downstream resources cannot confirm the chain without trusting every intermediary). In practice the full chain is often not reconstructable end-to-end, and there is a known class of attacks where the chain itself can be spliced. | **[OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) access tokens** identify the bearer, not the chain.<br/>**[OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) ID tokens** name the human at the start but lose granularity at each hop.<br/>**[SPIFFE SVIDs](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)** identify the workload but not which call within it.<br/>**[OAuth Token Exchange (RFC 8693)](https://www.rfc-editor.org/rfc/rfc8693)** defines nested `act` claims that can express a chain, but per [§4.1](https://www.rfc-editor.org/rfc/rfc8693#section-4.1) *"prior actors identified by any nested `act` claims are informational only and are not to be considered in access control decisions."* The chain is recorded, not normatively enforceable.<br/>**[OAuth Identity Chaining draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/)** and **[Transaction Tokens draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/)** address parts but specify neither chain verification rules nor revocation propagation as required runtime behavior.<br/>**[W3C Trace Context](https://www.w3.org/TR/trace-context/)** correlates but [does not authenticate](https://www.w3.org/TR/trace-context/#privacy-of-traceparent-field). | Every action must produce, at the moment of execution, a signed record that names the specific link in the chain and lets any participant (including the downstream resource) verify the entire chain end-to-end without trusting any intermediary. Cryptographic chain structure, mandatory scope attenuation at every hop, revocation propagation. | Pending |
| 2 | **Over-Privilege**<br/>*Was this action within the agent's purpose?* | Agents inherit broad standing privileges. Service accounts. Long-lived API keys. OAuth scopes designed for human applications. One compromised agent has the union of every permission anyone has ever granted to it. The fix is not bigger scopes; the fix is no standing privilege. | **[OAuth scopes (RFC 6749 §3.3)](https://www.rfc-editor.org/rfc/rfc6749#section-3.3)** are coarse, deployment-defined strings (e.g. `read`, `write`, `repo`). Per **[RFC 9396 §1](https://www.rfc-editor.org/rfc/rfc9396#section-1)**, scope is "sufficient... for coarse-grained authorization requests" but "not sufficient to specify fine-grained authorization requirements" — it does not express per-action, per-resource, per-data-cell intent.<br/>**RBAC and ABAC** scope by role or attribute, granted once, evaluated coarsely.<br/>**AIMS** does not require **[RAR (RFC 9396)](https://www.rfc-editor.org/rfc/rfc9396)** and treats scope semantics as deployment-specific. | Credentials minted just before the call, scoped to one downstream callee, structured (per-action, per-resource), expired in minutes. Authorization evaluated per-call against the immutable intent for the run, not per-session. | Pending |
| 3 | **Token Theft Resistance**<br/>*If a token leaks from agent memory, is it useless to the attacker?* | The agent threat model breaks OAuth's bearer-token assumption entirely. Prompt injection can exfiltrate tokens from memory. Tool outputs can leak tokens. Sub-agents can replay tokens. Logs and crash dumps capture tokens. Long-lived refresh tokens in agent memory are the worst case: a durable credential held in storage that any indirect prompt injection can read. | **[OAuth 2.0 Bearer Tokens (RFC 6750 §1.2)](https://www.rfc-editor.org/rfc/rfc6750#section-1.2)** explicitly treat possession as sufficient: *"Using a bearer token does not require a bearer to prove possession of cryptographic key material."*<br/>**API keys** are bearer secrets by definition.<br/>**[OAuth refresh tokens (RFC 6749 §1.5)](https://www.rfc-editor.org/rfc/rfc6749#section-1.5)** were designed for the same user returning later to resume a session, which does not describe how agents work.<br/>**[DPoP (RFC 9449)](https://www.rfc-editor.org/rfc/rfc9449)** and **[OAuth 2.0 Mutual-TLS Certificate-Bound Access Tokens (RFC 8705)](https://www.rfc-editor.org/rfc/rfc8705)** solve sender-constraint but are optional extensions that most deployments do not enforce.<br/>None of these are required by the OAuth core. | All non-trivial tokens sender-constrained (DPoP or mTLS) so a leaked token is useless without the corresponding private key. Aggressive lifetime ceilings measured in minutes or seconds, not hours. No long-lived secrets in model-visible context. Credentials fetched at task start, used within a tight window, discarded at task end. | Pending |
| 4 | **Last-Mile Enforcement**<br/>*Did the resource actually enforce the decision, on every call, inside the runtime?* | The moment the action reaches a production system. All upstream identity work either holds here or fails here. Most systems today cannot distinguish an authorized action by an agent acting in good faith from the same call by an agent hijacked by indirect prompt injection. Gateway-only enforcement misses tool calls and sub-agent invocations that never cross a gateway. Cached decisions miss revocation, scope change, and freshly-discovered taint. | **API gateways and service meshes** enforce at the edge; agent tool calls never reach them.<br/>**[OAuth 2.0 resource servers (RFC 6749 §1.1)](https://www.rfc-editor.org/rfc/rfc6749#section-1.1)** validate the token but not the action's relationship to intent.<br/>**[mTLS (RFC 8705)](https://www.rfc-editor.org/rfc/rfc8705)** and **[SPIFFE](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)** establish workload identity but do not enforce per-action policy.<br/>None fire inside the agent runtime where the decision is made. | Enforcement fires at every tool call, inside the agent runtime, before the action executes. The runtime verifies identity, scope, taint, freshness, and intent on every call. The LLM call cost dwarfs the re-authorization cost, so caching decisions is not required for performance. Default-deny verified by a negative test in CI. | **Partially specified.** The ACS Instrument spec already defines the honoring-decisions contract in [§6.4 (Honoring Decisions, Normative)](../spec/instrument/specification.md#64-honoring-decisions-normative): the Observed Agent MUST wait for the Guardian's decision up to the negotiated timeout, MUST apply it, and MUST record every fail-open proceed as an audit event. Note the spec's current default on timeout is **fail-open with audit**, which is in tension with this row's default-deny / no-cache goal; whether identity-tier actions should tighten that to fail-closed is an open work item for this workstream. |
| 5 | **Proof of Intent**<br/>*Was the action bound to an immutable, declared purpose that survives mid-task reframing?* | OAuth scopes say what the user *can* do. They do not say what the user *is doing right now*. Without intent binding at runtime, every agent action is a guess about user authorization. The agent's reasoning can be reframed mid-task by an instruction hidden in a document or a tool output. The original intent has to survive that. This is the hardest of the five, because it is the only one OAuth cannot patch with an extension: the underlying problem is non-deterministic client behavior under adversarial inputs. | **None at the identity layer.** Intent is implicit in the OAuth consent screen and discarded after token issuance.<br/>**[RFC 9396 RAR](https://www.rfc-editor.org/rfc/rfc9396)** can carry purpose claims as `authorization_details` data but does not bind them as runtime invariants against the LLM client.<br/>**IBAC (Intent-Based Access Control)** is research-stage with no IETF/W3C standard track.<br/>No production standard treats intent as a first-class, immutable, normatively-enforced runtime invariant. | Intent treated as a first-class governance concept with a normative immutability invariant. Intent must flow across all three ACS pillars: Instrument fires decisions against it, Trace records it as a span attribute, Inspect catalogs what it authorized. Intent extension permitted only through an explicit, human-approved path. | Pending |

---

## What this Identity workstream is not trying to do

- **Replace existing Identity Standards like OAuth, OIDC, SPIFFE.** ACS-Identity composes with them.
- **Specify a new agent framework.** The mechanisms must work for any framework that can emit a signed action record.

## How ACS-Identity composes with the rest of ACS

ACS-Identity is one of eight cross-cutting concepts (Identity, Provenance, Trust, Intent, Capability, Skill, Agents, Session Lifecycle). It produces signals that the three pillars consume:

- **Instrument** fires authorization decisions against identity + intent + taint.
- **Trace** records each chain link as a span attribute (signed, verifiable).
- **Inspect** catalogs which agent, under which intent, exercised which capability.

Identity does not solve any of the five challenges alone. It composes with Provenance (taint), Capability (what the agent is allowed to do at all), and Intent (what it is doing right now).

## Read Next

- [ACS in Action](../topics/ACS_in_action_example.md)
