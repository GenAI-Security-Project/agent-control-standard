# Identity for Agents Overview

> **Note:** This is a working document. It is not intended to be comprehensive and will evolve as the ACS Identity workstream matures. Content, scope, and recommendations are subject to change.
>

Agents expose five runtime identity challenges that traditional identity models do not fully address. This working document describes those challenges without proposing a wire format or normative requirements. Those will follow once the working group has aligned.

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

An agent has a goal, a set of tools, some memory, and a model that decides at runtime what to call next. The tools, runtime, and prompts may remain the supply chain approved at build time. What changes at runtime is control flow: which tool runs, in which order, with which arguments, based on what the agent just read.

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

Agent systems expose failures where every token is valid, every API call is authorized, and the outcome is still a security incident. Identity supports governance and forensics in these cases, but does not close this failure class. Instrument and Intent must check the action against the declared purpose and handle injected instructions.

---

## Five Runtime Identity Challenges for Agents

The Identity workstream focuses on these five challenges. Over-privilege and token theft are long-standing identity problems. Agents add runtime control flow and exposure to untrusted instructions, so identity controls need to work with action-level enforcement.

A concrete example is Palo Alto Networks Unit 42's 2025 research, *[Agent Session Smuggling in Agent2Agent Systems](https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/)*. A malicious agent injected hidden instructions into a legitimate Agent2Agent (A2A) session. The victim disclosed sensitive information while using valid credentials and authorized APIs.

Authentication and authorization succeeded. The gap was distinguishing user intent from injected instructions, a control and Intent problem. Identity records help reconstruct who acted; [Instrument](../spec/instrument/specification.md) and [Intent](../concepts/intent.md) address whether that action should proceed.

| Challenge | Runtime question |
|---|---|
| [Chain Integrity](#chain-integrity) | Who delegated to this caller? |
| [Over-Privilege](#over-privilege) | Is this action within the granted authority? |
| [Token Theft Resistance](#token-theft-resistance) | Can a stolen credential be replayed? |
| [Last-Mile Enforcement](#last-mile-enforcement) | Does the runtime enforce the decision before acting? |
| [Proof of Intent](#proof-of-intent) | Does the action match the declared purpose? |

### Chain Integrity

A task can cross a user, orchestrator, sub-agents, tools, and downstream APIs. Naming and verifying these links supports trace reconstruction and forensics. OAuth access tokens, OIDC ID tokens, and SPIFFE workload identifiers do not by themselves establish that full history.

[OAuth Token Exchange (RFC 8693 §4.1)](https://www.rfc-editor.org/rfc/rfc8693#section-4.1) permits nested `act` claims. Prior actors in nested claims are informational only, not inputs to access control decisions. [W3C Trace Context](https://www.w3.org/TR/trace-context/#privacy-of-traceparent-field) provides correlation, not authentication.

Enforcement over a deep delegation chain is a separate, unsettled design question. A deployment needs verified delegation grants, trusted issuers, scope attenuation rules, and revocation handling before a Guardian can consume such a chain as authority. Merely recording or signing a chain does not define those rules.

For example, a deployment could use this Guardian rule, expressed as pseudocode rather than an ACS requirement:

```text
deny if any delegation grant fails signature, audience, expiry, or revocation checks
deny if any child grant expands its parent's scope
deny if the immediate caller does not match the final grant's delegate
deny if the requested action is outside the final grant's scope
otherwise evaluate the remaining action and intent policy
```

This rule consumes separately verified delegation grants, not informational nested `act` history. Its deep-chain validation cost, trust model, and failure handling need deployment-specific testing. Identity Chaining and Transaction Tokens drafts inform this work; ACS does not yet specify a general deep-chain enforcement mechanism.

### Over-Privilege

Broad service accounts and standing grants give a compromised agent authority beyond its current task. [OAuth scopes](https://www.rfc-editor.org/rfc/rfc6749#section-3.3) can be coarse. [Rich Authorization Requests (RAR, RFC 9396)](https://www.rfc-editor.org/rfc/rfc9396) can express per-action and per-resource authorization.

Prefer credentials scoped to the downstream callee and the requested action. Evaluate each call against the declared intent rather than treating a session-wide grant as sufficient. These are workstream goals, not new normative ACS requirements.

### Token Theft Resistance

A bearer API key or an opaque bearer token is usable by whoever holds it. Not every API-key scheme is a bearer scheme: AWS SigV4 uses a secret key to sign requests without sending that key. Prompt-visible credentials, tool outputs, logs, and crash dumps can expose secrets.

[DPoP (RFC 9449)](https://www.rfc-editor.org/rfc/rfc9449) and [mTLS-bound tokens (RFC 8705)](https://www.rfc-editor.org/rfc/rfc8705) constrain token use to a key holder. Keep private keys and long-lived secrets outside model-visible context. Short lifetimes reduce exposure but do not prevent harmful use during the validity window.

For a high-risk action, use an action-bound, single-use credential where the risk warrants it, with replay prevention at the resource. A short lifetime alone is not the control. Sender constraints also depend on protecting the corresponding private key.

### Last-Mile Enforcement

Gateway-only checks miss calls that stay inside an agent runtime. Validate identity, scope, freshness, taint, and intent before the action executes. A valid token alone cannot distinguish the intended action from an injected one.

The Identity workstream's default posture is **fail-closed** (`deny`), following the leads' decision in [issue #32](https://github.com/GenAI-Security-Project/agent-control-standard/issues/32). Any fail-open or fail-cached exception needs an explicit risk justification, bounded scope and duration, and trace evidence. An attacker must not gain permission by making the Guardian unreachable.

[Instrument §6.4](../spec/instrument/specification.md#64-honoring-decisions-normative) defines the honoring-decisions contract. Reconciliation of its timeout wording with the agreed fail-closed default is tracked in issue #32; this overview does not change the normative contract.

### Proof of Intent

OAuth scopes express what a principal can do, not what the principal intends for the current task. RAR can carry structured authorization details, but those details do not detect injected instructions or enforce purpose during execution.

Bind decisions to the declared intent and require explicit human approval for changes to that purpose. Instrument evaluates actions against it, Trace records the decisions, and Inspect catalogs the capabilities exercised. Identity supplies attribution; runtime controls check whether the action matches the purpose.

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
