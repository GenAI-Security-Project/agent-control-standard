# Authorization Paradigms and Policy Engines

ACS separates the **wire contract** from **policy evaluation**. A Guardian Agent does not have to implement any research authorization paradigm. The handshake negotiates [conformance profiles](../spec/conformance.md) rather than paradigm names, and no wire field declares which paradigm a Guardian runs.

Most deployments start with conventional access-control rules that allow or deny on caller identity, role, tool, and resource. Research and architectural models such as IBAC, FIDES, CaMeL, and AARM are **optional policy and citation styles** that ride on existing Instrument fields ([Specification §6.2](../spec/instrument/specification.md#62-paradigm-composition)).

> **Scope and status.** This page is non-normative. It covers Instrument-side policy evaluation and optional citation conventions ([Specification §6.2](../spec/instrument/specification.md#62-paradigm-composition), [§12](../spec/instrument/specification.md#12-policy-engine-and-agent-layers)). Cross-cutting definitions for [Intent](../concepts/intent.md), [Capability](../concepts/capability.md), [Provenance](../concepts/provenance.md), and [Trust basis](../concepts/trust.md) remain in [Concepts](../concepts/README.md).

## Policy engines vs. authorization paradigms

Keep two layers distinct:

- **Policy engine** — the runtime that evaluates rules inside the Guardian's deterministic layer ([§12.1](../spec/instrument/specification.md#121-policy-engine-interface)). It takes the request envelope, SessionContext, optional Intent, and optional provenance, and returns a decision envelope (or delegates to the optional LLM agent layer in [§12.2](../spec/instrument/specification.md#122-agent-layer)).
- **Authorization paradigm** — the security model those rules express (for example, static RBAC/ABAC, intent-scoped capability checks, or information-flow taint tracking).

ACS specifies the Guardian interface, not the engine:

| Engine | ACS status | Role |
|---|---|---|
| [OPA / Rego](https://www.openpolicyagent.org/) | v0.1 starting reference | General-purpose deterministic policy language for identity, role, resource, intent, or provenance rules |
| [Cedar](https://www.cedarpolicy.com/) | Planned v0.2 binding | Typed authorization policy language targeting the same Guardian interface ([§12.1](../spec/instrument/specification.md#121-policy-engine-interface), [§16](../spec/instrument/specification.md#16-roadmap)) |
| Custom or vendor engines | Supported in v0.1 | Any policy runtime that consumes the ACS input shape and returns a conformant decision envelope |

To try working Rego and OPA policy backends in the shipped reference Guardians, see [Choose a policy backend](./reference-implementations.md#choose-a-policy-backend).

An ordinary OPA/Rego rule needs no research paradigm at all. The illustrative snippet below restricts `email.send` to internal `@example.com` recipients for employees (the exact OPA input/output binding is implementation-defined in v0.1; see [§12.1](../spec/instrument/specification.md#121-policy-engine-interface)):

```rego
package acs.email

import rego.v1

is_email_send if {
  input.method == "steps/toolCallRequest"
  input.params.payload.tool.name == "email.send"
}

is_employee if {
  "employee" in input.params.metadata.user_context.roles
}

has_string_recipient if {
  is_string(input.params.payload.arguments.recipient.value)
}

is_internal_recipient if {
  has_string_recipient
  endswith(input.params.payload.arguments.recipient.value, "@example.com")
}

decision := {
  "decision": "deny",
  "reasoning": "Caller role is not authorized to send email.",
  "reason_codes": ["role_not_authorized"],
  "policy_references": [
    {"policy_id": "acme-email-baseline", "policy_version": "v1", "rule_id": "require-employee-role"}
  ],
} if {
  is_email_send
  not is_employee
} else := {
  "decision": "deny",
  "reasoning": "Email recipient must be a string address.",
  "reason_codes": ["invalid_recipient"],
  "policy_references": [
    {"policy_id": "acme-email-baseline", "policy_version": "v1", "rule_id": "require-string-recipient"}
  ],
} if {
  is_email_send
  not has_string_recipient
} else := {
  "decision": "deny",
  "reasoning": "External email recipients are not allowed for this role.",
  "reason_codes": ["external_recipient_denied"],
  "policy_references": [
    {"policy_id": "acme-email-baseline", "policy_version": "v1", "rule_id": "internal-recipients-only"}
  ],
} if {
  is_email_send
  not is_internal_recipient
} else := {
  "decision": "allow",
  "policy_references": [
    {"policy_id": "acme-email-baseline", "policy_version": "v1", "rule_id": "allow-employee-internal-email"}
  ],
} if {
  is_email_send
}
```

## Optional authorization paradigms

Four published agent-security architectures appear across ACS documentation. None is mandatory, none is negotiated by name in `handshake/hello`, and each uses existing ACS profiles and decision fields (`policy_references`, `reason_codes`, `policy_data`, and `cited_provenance_ids`) as an optional citation convention.

| Paradigm | Core idea | ACS profiles used | Wire fields cited | v0.1 mapping completeness |
|---|---|---|---|---|
| **IBAC** | Bind runtime actions to an immutable task-scoped `Intent` committed before untrusted data enters | `acs-core` (`acs-provenance` not required) | `SessionContext.intent`, `ASK` (`intent_extension`), `policy_data.ibac` | **Partial (wire fields and immutability).** ACS defines `Intent`, immutability (§8.4), and `ask_details.intent_extension` (§9.1), while v0.1 leaves ASK answer delivery ([issue #175](https://github.com/GenAI-Security-Project/agent-control-standard/issues/175)) and capability-to-`Intent.parsed` matching ([issue #385](https://github.com/GenAI-Security-Project/agent-control-standard/issues/385)) open; intent parsing stays Guardian-internal. |
| **FIDES** | Deterministic information-flow control with confidentiality/integrity labels across tool calls and compaction | `acs-core`, `acs-provenance` | Per-field `Provenance` (`origin`, `source_id`, `derived_from`), `preCompact`/`postCompact`, `cited_provenance_ids`, `policy_data.fides` | **Partial (wire-data level).** ACS carries factual lineage; label lattice arithmetic, P-T/P-F rules, and planner hiding/revealing primitives live in the Guardian and framework. |
| **CaMeL** | Separate trusted control flow from untrusted data via a synthesized program and per-argument capability checks | `acs-core`, `acs-provenance` | Per-argument `ToolArgumentValue.provenance` (`derived_from` graph) on `steps/toolCallRequest`, `cited_provenance_ids`, `policy_data.camel` | **Partial (enforcement-boundary level).** ACS enforces tool-call boundaries and carries argument lineage; the dual-LLM architecture and custom interpreter live inside the Observed Agent framework. |
| **AARM** | Pre-execution interception of autonomous actions with identity binding, cumulative context tracking, and tamper-evident receipts | `acs-core`, `acs-audit` (plus `acs-crypto` for non-repudiable receipts and `acs-provenance` for cumulative-taint rules) | Dispositions, `chain_hash`, `request_hash`, `turnStart`/`turnEnd`, `provenance_summary`, `cited_provenance_ids`, `policy_data.aarm` | **High-level alignment.** The formal requirement-by-requirement R1–R9 mapping and gap analysis is tracked in [issue #213](https://github.com/GenAI-Security-Project/agent-control-standard/issues/213). |

### IBAC (Intent-Based Access Control)

**Source:** [ibac.dev](https://ibac.dev/) — Jordan Potti, *Intent-Based Access Control: Securing Agentic AI Through Fine-Grained Authorization* ([PDF](https://ibac.dev/ibac-paper.pdf), 2026). IBAC is an emerging agentic authorization model with no IETF or W3C standards track.

**What it is:** Instead of granting an agent every permission the user's static role holds, IBAC parses the user's request into a task-scoped capability set before untrusted data enters, then blocks any tool call outside that set.

**How it maps to ACS:**

- `steps/sessionStart` (and optionally `steps/agentTrigger`) establishes `Intent` (`raw`, `parsed`, `parser_provenance`, `scope_mode`).
- [Specification §8.4](../spec/instrument/specification.md#84-intent) makes `Intent.parsed` immutable to the runtime LLM and untrusted channels.
- [Specification §9.1](../spec/instrument/specification.md#91-intent-extension-via-ask-normative) lets an approver extend `Intent.parsed` explicitly via `ASK` (`intent_extension`).
- Decisions cite `policy_references`, `reason_codes`, and an optional `policy_data.ibac` object.

**Completeness:** Partial at the wire layer. ACS defines the `Intent` payload fields, the immutability invariant ([§8.4](../spec/instrument/specification.md#84-intent)), and `ask_details.intent_extension` ([§9.1](../spec/instrument/specification.md#91-intent-extension-via-ask-normative)), while two interoperability gaps remain open in v0.1: how an approver's `ASK` answer is delivered back to the Guardian ([issue #175](https://github.com/GenAI-Security-Project/agent-control-standard/issues/175)) and how `toolCallRequest.payload.capability` compares to `Intent.parsed` ([issue #385](https://github.com/GenAI-Security-Project/agent-control-standard/issues/385)). The intent parser, fine-grained authorization store, and capability matcher are implementation-defined inside the Guardian.

### FIDES (Flow Integrity Deterministic Enforcement System)

**Source:** Manuel Costa et al. (Microsoft Research), *Securing AI Agents with Information-Flow Control* ([arXiv:2505.23643](https://arxiv.org/abs/2505.23643), 2025).

**What it is:** An information-flow control (IFC) model for AI agents that attaches integrity and confidentiality labels to inputs and tool outputs and enforces deterministic flow rules (such as planner-taint `P-T` and flow `P-F` checks) before consequential tool calls run.

**How it maps to ACS:**

- The Observed Agent claims the `acs-provenance` profile and attaches factual `Provenance` objects (`provenance_id`, `origin`, `source_id`, `derived_from`) to every data-bearing field ([§7](../spec/instrument/specification.md#7-provenance)).
- `steps/preCompact` and `steps/postCompact` preserve lineage across context-window compaction ([Hooks](../spec/instrument/hooks.md#precompact)).
- The Guardian derives trust/integrity labels from `origin` + `source_id` against local policy ([§7.1](../spec/instrument/specification.md#71-optional-trust-enum)), cites the relevant IDs in `cited_provenance_ids`, and records flow facts in `policy_data.fides`.

**Completeness:** Partial at the wire-data layer. ACS supplies factual lineage and interception hooks, while FIDES's label lattice arithmetic and planner-side variable-hiding/revealing primitives are implemented outside the wire contract.

### CaMeL (CApabilities for MachinE Learning)

**Source:** Edoardo Debenedetti et al. (Google, Google DeepMind, ETH Zurich), *Defeating Prompt Injections by Design* ([arXiv:2503.18813](https://arxiv.org/abs/2503.18813), 2025).

**What it is:** A dual-LLM architecture where a Privileged LLM synthesizes a restricted program from the trusted user prompt, a Quarantined LLM extracts structured values from untrusted data, and a custom interpreter enforces capability checks on every tool-call argument using its data-flow graph.

**How it maps to ACS:**

- Under `acs-provenance`, each argument on `steps/toolCallRequest` carries its own `ToolArgumentValue.provenance` with `derived_from` lineage.
- The Guardian inspects the per-argument dependency graph, cites the violating nodes in `cited_provenance_ids`, and reports the dependency violation in `policy_data.camel`.

**Completeness:** Partial at the enforcement boundary. ACS standardizes per-argument provenance and pre-execution tool gating, but CaMeL's dual-LLM split and program interpreter are internal to the Observed Agent framework.

### AARM (Autonomous Action Runtime Management)

**Source:** *Autonomous Action Runtime Management (AARM): A System Specification for Securing AI-Driven Actions at Runtime* ([arXiv:2602.09433](https://arxiv.org/abs/2602.09433); [aarm.dev](https://aarm.dev/), Cloud Security Alliance).

**What it is:** A system-level specification defining requirements (Core R1–R6 and Extended R7–R9) for intercepting autonomous agent actions before execution, binding identity and context, tracking cumulative drift/taint, and emitting tamper-evident action receipts.

**How it maps to ACS:**

- `acs-core` covers pre-execution interception, dispositions, decision honoring, and baseline signed envelopes.
- `acs-audit` adds `request_hash` to the hash-chained `ContextEntry` log; `acs-crypto` adds asymmetric/post-quantum signatures when third parties need to verify receipts without sharing a symmetric key.
- `steps/turnStart`, `steps/turnEnd`, `provenance_summary`, and `acs-provenance` support cumulative-context lookback rules, cited in `cited_provenance_ids` and `policy_data.aarm`.

**Completeness:** High-level alignment only on this page. A formal requirement-by-requirement R1–R9 mapping and gap analysis reviewed with the AARM authors is tracked in [issue #213](https://github.com/GenAI-Security-Project/agent-control-standard/issues/213).

## Composing rules and paradigms

A single Guardian can combine an ordinary identity/role policy with any mix of IBAC-, FIDES-, CaMeL-, or AARM-style checks on the same wire payload ([§6.2](../spec/instrument/specification.md#62-paradigm-composition)). `policy_references` is a list, `reason_codes` aggregates machine-readable codes, and `policy_data` is an open object conventionally keyed by rule or paradigm name.

## Read Next

- [ACS in Action](./ACS_in_action_example.md) — worked walkthrough starting with a plain OPA/Rego rule, followed by optional paradigm citation examples
- [Run a Guardian](./reference-implementations.md) — try the shipped OPA and AGT Rego backends locally
- [Specification §6.2 — Paradigm composition](../spec/instrument/specification.md#62-paradigm-composition)
- [Specification §12 — Policy engine and agent layers](../spec/instrument/specification.md#12-policy-engine-and-agent-layers)
- [Conformance Profiles](../spec/conformance.md)
