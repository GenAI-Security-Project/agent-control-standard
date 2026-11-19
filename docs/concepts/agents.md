# Agents

ACS governs the relationship between two agents and, when human or service approval is needed, a third party.

## Observed Agent

The AI agent under governance. It implements the ACS wire contract, emits hooks at each decision point in its lifecycle, and enforces the dispositions it receives. The Observed Agent is the subject of every AgBOM snapshot and the origin of every Trace event.

The Observed Agent emits; it does not adjudicate its own actions. That separation is the core of the model.

## Guardian Agent

The policy enforcement and decision point. It receives hooks from the Observed Agent, evaluates them against deployment policy, and returns a disposition: `allow`, `deny`, `modify`, `ask`, or `defer`. It consumes AgBOM for inventory-dependent policy and emits Trace events for the decisions it makes.

**Guardian identity** names the deciding Guardian service or instance as its own principal—distinct from the policy document (`policy_references`) and from the policy author ([Conformance](../spec/conformance.md)). In v0.1, neither `ServerHello` (`handshake.json`) nor `response-envelope.json` carries a Guardian principal identifier field; a signed response identifies the Guardian's configured signing key through `signature.key_id` ([Specification §10](../spec/instrument/specification.md#10-cryptographic-signatures)).

> **Decision logging (normative).** A Guardian MUST log every decision with its reasoning, the evaluator's model identifier, and confidence when available.

## Approver

A party the Guardian consults when a request falls outside standing policy and an `ask` disposition is raised. An Approver MAY be human, agent, or service. It receives an ACS-shaped request and returns an ACS-shaped decision.

> **Approver authentication (normative).** Approver authentication is REQUIRED. The Guardian MUST verify the Approver's identity against policy before honoring the returned decision.

The Approver's grant MAY extend `Intent.parsed` through an `intent_extension` (see [Intent](./intent.md)). In v0.1 this is single-hop: Approvers MUST NOT themselves return `ask`.

*Example.* An agent requests a wire transfer outside its standing Intent. The Guardian raises `ask`; a human Approver authenticates and returns `allow` with an `intent_extension` scoped to that single request.

## Trust between agents

What the Observed Agent puts on the wire is asserted by the Observed Agent. The Guardian decides whether to rely on it. How much weight a given fact carries depends on its [trust basis](./trust.md), not on the fact that it arrived.

---

**Referenced by**

- **Instrument**, [specification](../spec/instrument/specification.md): the Observed Agent emits hooks; the Guardian returns dispositions; Approvers participate via the ASK flow (§9).
- **Trace**, [events](../spec/trace/events.md): every event names the evaluator; Guardian decisions become spans and OCSF findings.
- **Inspect**, [AgBOM](../spec/inspect/README.md): the AgBOM is the Observed Agent's component graph.
- See also [Identity](./identity.md) for how each party's identity is established.
