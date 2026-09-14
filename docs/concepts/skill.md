# Skill

A skill is loadable executable content that composes lower-level components into a higher-level ability. It packages instructions, helper scripts, and an action manifest that run together. Where a [capability](./capability.md) names what an action does and a tool exercises one, a skill is a reusable unit of agent behavior assembled from many tools, MCP servers, peers, and sometimes other skills.

A skill differs from an [`agent_capability`](./capability.md) in one way that governs how ACS treats it. An `agent_capability` is a passive grouping: a label over components already in the inventory. A skill carries a **definition artifact**, content that loads and runs. That artifact is a trust surface, and it is the reason skills earn lifecycle governance of their own.

## Skill and composition

A skill is defined by what it composes. Its definition references the tools, MCP servers, and peers it draws on, and the other skills it is permitted to load. This composition is the unit of analysis: a single action inside a skill can be benign while the skill as a whole is not.

This is why per-action governance is not enough. A payload split across a skill's actions is invisible to any hook that sees one action at a time. Each action is plausible alone; the behavior lives in the composition. Governing the skill means inspecting the whole definition before its actions run.

## Skill in the inventory

The Inspect pillar catalogs a skill as a `skill` component. It carries the composition references, a least-privilege capability manifest, and the definition's reference and integrity digest. The body of the definition does not enter the inventory; only the reference and digest persist, so a Guardian can detect tampering between registration and load without the wire carrying executable content.

A skill's declared capabilities are the supply-side claim of what it needs. A Guardian compares that claim against the capabilities its composed tools actually expose, and treats a gap as a signal.

## Skill as a trust boundary

A skill crosses a trust boundary twice: when it registers into the available set, and when it loads into a session. ACS governs both.

Registration is the static gate. It is the one point where a Guardian sees the whole definition before any action runs, the natural home for whole-definition analysis, signature checks, and dependency inspection.

Load is the runtime gate. It governs each activation in live context and carries the load path, the ordered list of skills that led to the current load. The path lets a Guardian contain cascades: one skill loading another that the first never declared it would.

---

**Referenced by**

- **Instrument**: the [`skillRegister`, `skillLoad`, and `skillUnload` hooks](../spec/instrument/hooks.md#skillregister).
- **Inspect**: the `skill` [AgBOM component type](../spec/inspect/README.md).
- **Trace**: the [span names and OCSF classes](../spec/trace/events.md) the three hooks emit.
- See also [Capability](./capability.md), [Provenance](./provenance.md), and [Trust basis](./trust.md).
