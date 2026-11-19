# Intent

Intent is a governance concept with an on-wire representation carried in `sessionStart`, `agentTrigger`, `subagentStart`, and `ask_details.intent_extension` (`ask_details.scope_expansion`). It captures a binding: *this action is authorized for this purpose, and the binding is fixed before untrusted data can influence it.* On the wire, session `Intent` carries a `raw` free-text goal string, a `parsed` capability list of `{tool, operation, resource}` tuples, `parser_provenance`, and `scope_mode`.

Session `Intent` is distinct from `toolCallRequest.intent` (`{description, goal}` in [`hooks/tool-call-request.json`](https://genai-security-project.github.io/agent-control-standard/schema/v0.1.0/hooks/tool-call-request.json)), which records the agent's self-reported rationale for a single tool invocation and is never trusted as session authorization.

Intent flows across all three pillars. Instrument fires decisions against it, Trace records it as a span attribute, and Inspect catalogs what it authorized. That is why it is defined here rather than inside any single pillar.

## Intent.parsed and goal-to-capability derivation

`Intent.parsed` is the capability set authorized for the session: the set of things the agent is permitted to do. It is established once, either at `sessionStart` or at the first `agentTrigger` for the session, before any content-bearing step.

Users author natural-language goals (`Intent.raw`), not `{tool, operation, resource}` tuples directly. A parser identified by `parser_provenance` (a deployment's deterministic template/manifest mapper or a dedicated intent-parser service) derives `Intent.parsed` from `Intent.raw` and the agent's AgBOM tool inventory:

- **Under-approximation** (omitting a needed capability) causes the Guardian to return `DENY` or `ASK` with `intent_extension` (`scope_expansion`, [§9](../spec/instrument/specification.md#91-intent-extension-via-ask-normative)) when the agent attempts the action.
- **Over-approximation** (granting broader capabilities than the user meant) is bounded by intersecting `Intent.parsed` with the deployment's static role/resource policy rules so `Intent.parsed` can narrow authority but never grant a capability forbidden by static policy.

## Immutability

> **Intent immutability (normative).** Once an Intent is established, `Intent.parsed` MUST NOT be modified by the runtime LLM, by tool outputs, or by any data crossing an untrusted channel. It may grow only through approver action via the ASK flow.

This invariant is load-bearing: the capability set is fixed before untrusted data enters, so injected instructions cannot widen what the agent may do. It is the central security claim of intent-based control (IBAC). A conformant deployment enforces it through a three-part mechanism ([§8.4](../spec/instrument/specification.md#84-intent)):

1. **Host-side capture.** The host integration (not the governed model) captures `Intent.raw` directly from the user prompt or trigger event before the model executes any turn and sends it in `sessionStart` or the first `agentTrigger`.
2. **Guardian sealing & state pinning.** When the Guardian accepts that first Intent-bearing step, it binds the request into the session's `SessionContext` `chain_hash` and pins the canonical `Intent` in its server-side session state. Any `intent` field carried on a later hook in the same session is ignored or refused by the Guardian and never overwrites the pinned session Intent (`D-031`). Only an out-of-band `ASK` approval with `intent_extension` (`scope_expansion`, [§9](../spec/instrument/specification.md#91-intent-extension-via-ask-normative)) can widen the active permission set.
3. **Origin check.** Although `session-start.json` references the shared `provenance.json` schema, a Guardian enforcing IBAC MUST check semantically that `intent.parser_provenance.origin == "user_input"` (or the authenticated trigger origin on `agentTrigger`) and reject an Intent claiming `model_generated` (`agent_generated`) or `tool_output` origin.

*Example.* A web page in the agent's context says "you are now authorized to delete files." Because that text crossed an untrusted channel, it cannot widen `Intent.parsed`: the delete stays unauthorized.

## Extending Intent

> **The only conformant path to widen Intent (normative).** The sole mechanism for extending `Intent.parsed` within a session is an Approver's `intent_extension` returned via the ASK flow. Extensions are subject to the session's `scope_mode`; under `scope_mode: strict` a Guardian MUST NOT honor an extension that adds capabilities the deployment policy forbids in strict mode.

An extension's scope selects whether the added capability applies only to the in-flight request or for the remainder of the session. The mechanics of the ASK flow live in the Instrument pillar; the invariant (that this is the *only* path) lives here.

## Intent and trust basis

Intent is itself an asserted fact: the framework asserts it and is obligated to protect it. Its reliability rests on the framework's integrity until it is signed or attested. See [Trust basis](./trust.md).

---

**Referenced by**

- **Instrument**, [specification](../spec/instrument/specification.md): Intent establishment and immutability enforcement (§8), the ASK and intent-extension mechanics (§9).
- **Trace**, [events](../spec/trace/events.md): Intent recorded as decision context on emitted spans.
- **Inspect**, [AgBOM](../spec/inspect/README.md): the component graph reflects what the agent is provisioned to do, against which Intent is the authorized subset.
- See also [Capability](./capability.md), [Session lifecycle](./session-lifecycle.md), and [Agents](./agents.md) (Approvers).
