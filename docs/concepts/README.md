# Concepts

These pages define the foundational concepts ACS uses across every pillar: agents, identity, the session lifecycle, intent, capability, skill, provenance, and trust basis. They are the single source of truth. Each pillar's specification references down into these definitions rather than restating them.

This split exists because these concepts are horizontal. Intent, for example, flows through all three pillars: Instrument fires decisions against it, Trace records it as a span attribute, and Inspect catalogs what it authorized. Defining it inside any one pillar would subordinate a concept the other two depend on.

## The altitude rule

A normative statement lives at the altitude of its scope.

- **Cross-cutting invariants** (true across pillars) are defined here and tagged **(normative)**. They belong above the pillars because that is where they are true. *e.g. "`Intent.parsed` MUST NOT be modified by the LLM or by data crossing an untrusted channel."*
- **Mechanism requirements** (true within one pillar's enforcement) stay in that pillar. *e.g. "the Guardian MUST verify approver identity," "a client declaring `provenance_producer: none` MUST be refused at handshake."*

When you add a concept, hoist the invariant and leave the mechanics. If a requirement is restated in two pillars, or buried in one but relied on by another, it is at the wrong altitude.

## Pages

| Concept | Covers |
|---|---|
| [Agents](./agents.md) | Observed Agent, Guardian Agent, Approver |
| [Identity](./identity.md) | Principal, agent identity, descriptor types |
| [Session lifecycle](./session-lifecycle.md) | Session, turn, step, subagent |
| [Intent](./intent.md) | Intent as a governance concept and its immutability invariant |
| [Provenance](./provenance.md) | Origin, source, lineage, channels |
| [Capability](./capability.md) | Capability and authorization scope |
| [Skill](./skill.md) | Skill as composed, loadable behavior and a trust boundary |
| [Trust basis](./trust.md) | The spectrum from asserted to attested |

## Convention

Every page carries the canonical definition, any cross-cutting invariants tagged **(normative)**, and a **Referenced by** footer pointing into the pillars that consume the concept. The graph is navigable in both directions.

> **Migration note.** These pages are the source of truth for the terms they define. The pillar specifications still carry some of these definitions inline. Where a pillar's inline copy disagrees with these pages, treat these pages as canonical.
