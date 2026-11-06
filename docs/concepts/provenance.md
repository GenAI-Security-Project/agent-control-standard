# Provenance

Provenance answers where a piece of data came from and how it got here. It is the substrate every information-flow control reads, and the thing that, if dropped at a boundary, lets trust launder silently.

A distinct but related question (*how much may I rely on this?*) is the [trust basis](./trust.md). Provenance is the primary input to the lower rungs of that spectrum; it is not the whole of it.

## What provenance records

A Provenance object carries:

- **`origin`**: the channel a piece of data crossed: `user_input`, `system`, `tool_output`, `retrieved`, `agent_generated`, `a2a_inbound`, or `external`.
- **`source_id`**: the specific source within that origin (a tool, a memory store, a user).
- **`derived_from`**: the lineage, the prior Provenance objects this data was computed from.

Argument-level provenance lets a Guardian reason about the lineage of individual tool arguments, not just the call as a whole.

## Lineage is transitive

> **Lineage spans derivation (normative).** When data is derived from other data, its `derived_from` lineage is the union of the lineage of its inputs. Summarization and compaction are derivations: the summary that comes out carries the combined lineage of everything that went in.

This is what makes compaction a controllable chokepoint rather than a laundering path. Without transitive lineage, untrusted content could enter, be summarized into new `agent_generated` text, and lose the mark of where it came from.

> **Lineage spans the session boundary (normative).** A `provenance_id` is unique only within its own session, so a read in a later session cannot cite the node that was written in an earlier one. A memory write carries a `lineage_id`, the `origin_session_id` and the writer's provenance summary; every read of that entry echoes them and cites the `lineage_id` in `derived_from`. The wire rules are in [Specification §7.3](../spec/instrument/specification.md#73-memory-lineage-across-sessions-normative).

*Example.* In session A the agent fetches a web page (`origin: tool_output`) and stores a note from it in a `user`-scoped memory. In session B the note comes back as `origin: retrieved`, but its lineage still names the `tool_output` it rests on, so a Guardian does not mistake it for recall the user wrote.

*Example.* The model summarizes a retrieved web page (`origin: retrieved`). The summary text is `agent_generated`, but its `derived_from` includes the page's Provenance, so a Guardian still sees that the summary rests on retrieved content.

## Deterministic assignment

> **Provenance is framework-assigned (normative).** The framework, not the LLM, assigns `origin`, `source_id`, and `derived_from`, based on the code path a value came through. These fields are never inferred by the model, never a content judgment, and never a producer claim.

That deterministic assignment places Provenance on the middle rung of the [trust basis](./trust.md) spectrum: stronger than a bare assertion, because the model cannot influence it, but only as trustworthy as the framework.

## How provenance is produced

Whether Provenance is populated by deterministic code outside the LLM path is declared at handshake (`provenance_producer`). LLM-authored Provenance is not a conformant producer mode. The handshake mechanics, and the requirement to refuse a session when policy needs Provenance the client cannot produce, live in the Instrument pillar.

---

**Referenced by**

- **Instrument**, [specification](../spec/instrument/specification.md): Provenance objects and framework assignment (§7), the `preCompact` laundering guard ([hooks](../spec/instrument/hooks.md)).
- **Trace**, [extend OCSF](../spec/trace/extend_ocsf.md): provenance recorded on emitted events.
- **Inspect**, [AgBOM](../spec/inspect/README.md): `registration_provenance` records how each component entered the graph.
- See also [Trust basis](./trust.md) and [Capability](./capability.md).
