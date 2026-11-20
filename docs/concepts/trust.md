# Trust basis

Every fact ACS carries has a *trust basis*: the grounds on which a Guardian may rely on it. ACS never assumes a wire fact is true. It makes the basis explicit, so policy can require a minimum.

Trust basis is a property of every fact, not a field on the wire. ACS carries no single `trust` value. Instead, *how a fact was produced* determines how far up the spectrum it sits.

## The spectrum

Trust basis runs from asserted to attested. Each rung is a stronger ground for reliance than the one before.

### Asserted

The emitter says so; reliance equals reliance on the emitter. Unsigned Trace events, tool outputs, `agent_generated` content, and Intent before any signature are asserted facts. The Guardian must decide independently whether to trust them. This is the default for anything on the wire that nothing stronger backs.

### Deterministically attached

Framework code, not the LLM, attaches the fact from a structural property of how the data moved. Two cases qualify: a [Provenance](./provenance.md) record's `origin`, `source_id`, and `derived_from`, assigned by the framework under `provenance_producer: deterministic`; and the AgBOM `registration_provenance` (framework-declared versus runtime-discovered). The model cannot influence either, which makes them stronger than assertions. They are only as trustworthy as the framework that attaches them.

### Cryptographically attested

The fact is bound by a signature or a hash chain and is verifiable without trusting the emitter at evaluation time. Signed envelopes (ACS-Crypto), the SessionContext audit chain via `previous_hash` and `request_hash` (ACS-Audit), and the future Policy Attestation profile are attested. An attested fact survives a compromised or replayed emitter.

## Invariants

> **The rungs do not collapse (normative).** A Guardian MUST NOT treat an asserted fact as attested. The basis of a fact is part of the fact; relying on a fact above its actual basis is an error.

> **Deterministic attachment is not a producer claim (normative).** Where ACS specifies a deterministically attached fact (a Provenance record's `origin` is the canonical case), the framework assigns it from the code path the value came through, never the producer of the data and never the LLM. Such a fact is never a content judgment and never a producer claim.

## The basis must travel

When a fact is summarized, written to memory, or passed across a boundary, its trust basis must travel with it. A derivation of asserted content is asserted; it does not become attested by being restated. This is the same rule that makes [Provenance](./provenance.md) lineage transitive, viewed from the trust side: dropping the basis at a boundary lets asserted content be treated as if it were attested, trust laundering up the spectrum.

*Example.* An agent reads an untrusted email (asserted) and writes a summary to memory. If the summary keeps the email's basis, a second agent that retrieves it still treats it as asserted. If the basis is dropped, the memory reads like trusted recall. The wire carries the basis across the store through the write's `lineage`; see [Specification §7.3](../spec/instrument/specification.md#73-memory-lineage-across-sessions-normative).

## Availability in v0.1

The spectrum is the design frame; conformance profiles declare which rungs a deployment actually provides.

| Rung | v0.1 status |
|---|---|
| Asserted | Always; the default. |
| Deterministically attached | Available; Provenance `origin`/`source_id`/`derived_from` are framework-assigned under `provenance_producer: deterministic`, required under **ACS-Provenance** (with `registration_provenance` on components). |
| Cryptographically attested | Profile-gated: **ACS-Crypto** (signatures), **ACS-Audit** (`request_hash` chain), and partly future (Policy Attestation, v0.2). |

A deployment is conformant without the top rung. The point of naming the spectrum is that policy can *require* a rung where the stakes justify it, and the Guardian can tell which rung a given fact actually has.

---

**Referenced by**

- **Instrument**, [specification](../spec/instrument/specification.md): framework-assigned Provenance fields (§7), cryptographic signatures and replay protection (§10), the SessionContext hash chain (§8); [conformance](../spec/conformance.md) for ACS-Crypto, ACS-Audit, ACS-Provenance.
- **Trace**, [events](../spec/trace/events.md): events default to the asserted rung; ACS-Crypto signing elevates them.
- **Inspect**, [AgBOM](../spec/inspect/README.md): `registration_provenance` as a deterministic attachment on each component.
- See also [Provenance](./provenance.md) (the primary input to the lower rungs) and [Intent](./intent.md) (an asserted fact until attested).
