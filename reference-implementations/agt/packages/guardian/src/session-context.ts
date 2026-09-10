/**
 * The Guardian's per-session state, and the hash chain that orders it.
 *
 * This module declares three types and one aggregate over them.
 * `SessionContext` holds a session's hash chain alone -- its entries and the
 * digests that link them. `Intent` holds the immutable first-message
 * baseline recorded for a session, and `SessionProvenance` holds the record
 * described below, including AGT's IFC labels. `SessionState` is what the
 * store holds for one session: the three together, with the chain held as
 * the array the store appends to rather than as a `SessionContext`, because
 * the store pushes onto that array and a reader must not be handed
 * something that grows underneath it. Keeping `SessionContext` scoped to
 * just the chain matters because `loadSessionContext` returns exactly that
 * type, and its name should promise no more than what it returns.
 *
 * This is declared in the Guardian's own package, not in `@acs/host-adapter`:
 * the adapter is what a host links against, and a host neither writes this
 * chain nor is trusted to write it. `@acs/host-adapter` already exports a
 * `Session*` cluster -- `SessionConfig`, `SessionConfigStore`,
 * `ResolvedSessionConfig` and friends -- and every one of them is about the
 * handshake. `SessionContext` is a different object with a different owner,
 * so it is never shortened to `session`, and the two names always appear
 * written out in full.
 *
 * This chain's `seq` does not inherit the audit log's duplicate-`seq`
 * hazard, and the reason is structural. The audit log's `seq` is derived by
 * a fresh host subprocess re-reading the log on each hook, so two concurrent
 * hooks can derive the same number. `seq` here is assigned by the store that
 * owns the chain, inside the Guardian's single `Bun.serve` process, and the
 * entries' order is carried by `prev_hash` rather than by the counter: two
 * entries claiming the same `seq` would still have to agree on a hash
 * covering the entry before them. `seq` is an index for readers, not the
 * chain's integrity.
 */
import { createHash } from "node:crypto";

/**
 * AGT's IFC tags: the type of the `ifc_labels` field below, and nothing wider.
 *
 * This Guardian has no separate store for labels. They are a field on a
 * session's provenance record, held alongside that session's chain and
 * intent by the one thing here called a store, `SessionContextStore`.
 *
 * ACS `Provenance` (`specification/v0.1.0/provenance.json`, which
 * defines `provenance_id`, `origin`, `source_id`, `derived_from`) carries no
 * label member. This does not widen it into a label bag; the labels ride a
 * named field on the record below.
 */
export type IfcLabels = readonly string[];

/**
 * `origin`'s seven values, as `specification/v0.1.0/provenance.json`
 * enumerates them. A union rather than `string`, so a value outside the
 * spec's enum is a compile error here rather than a schema failure wherever
 * this record is eventually read.
 */
export type ProvenanceOrigin =
  | "user_input"
  | "system"
  | "tool_output"
  | "retrieved"
  | "agent_generated"
  | "a2a_inbound"
  | "external";

/**
 * The provenance record the Guardian synthesizes per session -- ACS
 * `Provenance` as v0.1.0 defines it, plus one field carrying AGT's labels.
 *
 * `Session`-prefixed because this codebase has two provenance records that
 * never meet. The other one is on the wire: the optional `provenance` member
 * of each `{value, provenance}` argument and output an ACS payload carries,
 * typed `unknown` on the way in and stripped before any snapshot is
 * assembled. This record is synthesized here, one per session, seeded at the
 * lattice floor, and never reads that wire member. Under one bare
 * `Provenance` name, a reader of provenance.json and a reader of this type
 * would have every reason to think they were looking at the same record.
 */
export type SessionProvenance = {
  provenance_id: string;
  origin: ProvenanceOrigin;
  source_id?: string;
  derived_from?: readonly string[];
  /** AGT's labels: a field on the provenance record, not a redefinition of it. */
  ifc_labels: IfcLabels;
};

/** The session's immutable baseline: the first intent recorded for it. First one written wins. */
export type Intent = { readonly text: string; readonly recorded_at: string };

/** What a step contributes to the chain. Deliberately not the whole envelope. */
export type SessionStep = { method: string; request_id: string; tool_name: string };

export type SessionContextEntry = {
  session_id: string;
  seq: number;
  prev_hash: string;
  hash: string;
  recorded_at: string;
  method: string;
  request_id: string;
  tool_name: string;
};

/** One session's hash chain, and nothing else the session happens to own. */
export type SessionContext = {
  session_id: string;
  entries: readonly SessionContextEntry[];
};

/**
 * Everything `SessionContextStore` holds for one session: the chain, the
 * intent, and the provenance record together, named for the aggregate it is
 * rather than for any one of its three members.
 *
 * `entries` is the mutable array the store appends to, not a
 * `SessionContext`: `append` pushes one entry onto it, which is what keeps a
 * step's cost independent of how many steps came before it. `SessionContext`
 * is the reader's view, built per read over its own copy -- so these are two
 * types rather than one type twice, and which one you hold says whether you
 * are the writer or a reader.
 */
export type SessionState = {
  entries: SessionContextEntry[];
  intent: Intent | undefined;
  provenance: SessionProvenance;
};

/** The `prev_hash` of a session's first entry. */
export const GENESIS_HASH = "0".repeat(64);

/**
 * The hash covering one entry: its predecessor, its position, and its own
 * facts. Key order is fixed by the literal below rather than by
 * `JSON.stringify` of a caller's object, so the digest cannot change because
 * a field was declared somewhere else.
 */
export function hashEntry(input: Omit<SessionContextEntry, "hash">): string {
  const canonical = JSON.stringify([
    input.prev_hash,
    input.session_id,
    input.seq,
    input.recorded_at,
    input.method,
    input.request_id,
    input.tool_name,
  ]);
  return createHash("sha256").update(canonical).digest("hex");
}

/** A session with no history yet: no entries, no intent, and its labels at the lattice floor. */
export function emptySessionState(sessionId: string): SessionState {
  return {
    entries: [],
    intent: undefined,
    // `origin` names where data entered the system, and this record is one the
    // Guardian synthesizes to hold a session's labels -- so "system", with the
    // Guardian named in `source_id`, which is the member the spec gives for
    // "identifier within the origin".
    provenance: {
      provenance_id: `acs:session:${sessionId}`,
      origin: "system",
      source_id: "acs.guardian",
      // The lattice floor: the first label a session carries before any step
      // adds more. ACS v0.1.0 carries no label field itself
      // (`specification/v0.1.0/provenance.json` defines
      // provenance_id/origin/source_id/derived_from, nothing a sensitivity
      // could be read from), and AGT's gate denies a zero-label flow outright
      // rather than waving it through: `flow_allowed` in
      // `policy/lib/agt_ifc.rego` requires `count(labels) > 0`. A session with
      // no seed label is therefore a session that can do nothing at all.
      ifc_labels: ["public"],
    },
  };
}
