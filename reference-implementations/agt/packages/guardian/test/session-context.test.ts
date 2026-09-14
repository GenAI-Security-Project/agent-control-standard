import { describe, expect, it } from "bun:test";
import {
  GENESIS_HASH,
  appendContextEntry,
  createMemorySessionContextStore,
  loadSessionContext,
} from "../src/session-context-store.ts";

const at = (iso: string) => () => new Date(iso);
const step = (n: number) => ({ method: "steps/toolCallRequest", request_id: `req-${n}`, tool_name: "Bash" });

describe("SessionContext — the hash chain", () => {
  it("starts a session at the genesis hash and seq 1", () => {
    const store = createMemorySessionContextStore({ now: at("2026-08-14T00:00:00.000Z") });
    const entry = appendContextEntry(store, "sess-a", step(1));
    expect(entry.seq).toBe(1);
    expect(entry.prev_hash).toBe(GENESIS_HASH);
    expect(entry.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("chains each entry to the one before it, per session", () => {
    const store = createMemorySessionContextStore({ now: at("2026-08-14T00:00:00.000Z") });
    const first = appendContextEntry(store, "sess-a", step(1));
    const second = appendContextEntry(store, "sess-a", step(2));
    expect(second.seq).toBe(2);
    expect(second.prev_hash).toBe(first.hash);
    expect(second.hash).not.toBe(first.hash);
  });

  it("keeps two sessions on independent chains", () => {
    const store = createMemorySessionContextStore({ now: at("2026-08-14T00:00:00.000Z") });
    appendContextEntry(store, "sess-a", step(1));
    const b = appendContextEntry(store, "sess-b", step(1));
    expect(b.seq).toBe(1);
    expect(b.prev_hash).toBe(GENESIS_HASH);
    expect(loadSessionContext(store, "sess-a").entries).toHaveLength(1);
  });

  it("gives two entries at the same position different hashes when only tool_name differs", () => {
    const store = createMemorySessionContextStore({ now: at("2026-08-14T00:00:00.000Z") });
    const honest = appendContextEntry(store, "sess-a", step(1));
    const other = createMemorySessionContextStore({ now: at("2026-08-14T00:00:00.000Z") });
    const forged = appendContextEntry(other, "sess-a", { ...step(1), tool_name: "Write" });
    expect(forged.hash).not.toBe(honest.hash);
  });

  it("loads an unknown session as an empty chain rather than throwing", () => {
    const store = createMemorySessionContextStore();
    const context = loadSessionContext(store, "never-seen");
    expect(context.session_id).toBe("never-seen");
    expect(context.entries).toEqual([]);
  });

  // `loadSessionContext` returns the chain alone. Intent and provenance are
  // read through their own verbs, one record wide each -- there is no reader
  // that hands over all three at once.
  it("gives an unknown session an empty intent and the seeded labels", () => {
    const store = createMemorySessionContextStore();
    expect(store.intent("never-seen")).toBeUndefined();
    // The lattice floor, not `[]`: `emptySessionState` seeds a fresh session
    // at `["public"]`, because AGT's own IFC gate denies a zero-label flow
    // outright.
    expect(store.provenance("never-seen").ifc_labels).toEqual(["public"]);
  });
});

describe("the store is told its labels, and told nothing else", () => {
  it("replaces the labels", () => {
    const store = createMemorySessionContextStore({ now: at("2026-08-14T00:00:00.000Z") });
    store.replaceIfcLabels("sess-a", ["pii", "confidential"]);
    expect(store.sourceLabels("sess-a")).toEqual(["pii", "confidential"]);
  });

  // A verb that handed over the whole provenance record would let a caller
  // rewrite `origin` and `source_id` while meaning only to set labels. This
  // verb cannot express that mistake.
  it("leaves every other member of the provenance record alone", () => {
    const store = createMemorySessionContextStore({ now: at("2026-08-14T00:00:00.000Z") });
    store.replaceIfcLabels("sess-a", ["secret"]);
    const provenance = store.provenance("sess-a");
    expect(provenance.provenance_id).toBe("acs:session:sess-a");
    expect(provenance.origin).toBe("system");
    expect(provenance.source_id).toBe("acs.guardian");
  });
});

describe("Intent — immutable baseline per session", () => {
  it("records the first intent it is given", () => {
    const store = createMemorySessionContextStore({ now: at("2026-08-14T00:00:00.000Z") });
    store.setIntent("sess-a", "ship the redaction slice");
    expect(store.intent("sess-a")?.text).toBe("ship the redaction slice");
  });

  it("ignores every later intent, because the baseline is immutable", () => {
    const store = createMemorySessionContextStore({ now: at("2026-08-14T00:00:00.000Z") });
    store.setIntent("sess-a", "the baseline");
    store.setIntent("sess-a", "something else entirely");
    expect(store.intent("sess-a")?.text).toBe("the baseline");
  });
});

describe("the JSONL appender the Inspector tails", () => {
  it("emits one line per entry, in chain order", () => {
    const lines: string[] = [];
    const store = createMemorySessionContextStore({
      now: at("2026-08-14T00:00:00.000Z"),
      appendLine: (line) => lines.push(line),
    });
    appendContextEntry(store, "sess-a", step(1));
    appendContextEntry(store, "sess-a", step(2));
    expect(lines).toHaveLength(2);
    const parsed = lines.map((l) => JSON.parse(l) as { seq: number; prev_hash: string; hash: string });
    expect(parsed.map((p) => p.seq)).toEqual([1, 2]);
    expect(parsed[1]!.prev_hash).toBe(parsed[0]!.hash);
  });
});

/**
 * Why this suite has a section about forgetting. The store began with no cap
 * at all, which is not an untidiness: a Guardian that never forgets a session
 * grows for the life of the process, a larger Guardian answers slower, and a
 * decision that misses the host's negotiated `timeout_config.default_ms` is a
 * decision that never arrives -- which the default `proceed` posture resolves
 * by running the tool ungoverned. The cap exists so degradation cannot turn
 * itself into bypass.
 *
 * Every test here passes its own `onEvict`, both to assert the report and to
 * keep the default stderr warning out of the suite's output.
 */
describe("the store forgets whole sessions, and never quietly", () => {
  it("evicts the least recently written session when a new one passes the cap", () => {
    const evicted: string[] = [];
    const store = createMemorySessionContextStore({ maxSessions: 2, onEvict: (id) => evicted.push(id) });
    appendContextEntry(store, "sess-a", step(1));
    appendContextEntry(store, "sess-b", step(1));
    appendContextEntry(store, "sess-c", step(1));
    expect(evicted).toEqual(["sess-a"]);
    expect(loadSessionContext(store, "sess-a").entries).toEqual([]);
    expect(loadSessionContext(store, "sess-b").entries).toHaveLength(1);
    expect(loadSessionContext(store, "sess-c").entries).toHaveLength(1);
  });

  it("keeps the session still being written to, and evicts the one that went idle", () => {
    // First-seen order and write order disagree here on purpose: `sess-a` was
    // created first and is the most recently written, so the idle session is
    // `sess-b`. A cap ordered by creation would evict the busy session.
    const evicted: string[] = [];
    const store = createMemorySessionContextStore({ maxSessions: 2, onEvict: (id) => evicted.push(id) });
    appendContextEntry(store, "sess-a", step(1));
    appendContextEntry(store, "sess-b", step(1));
    appendContextEntry(store, "sess-a", step(2));
    appendContextEntry(store, "sess-c", step(1));
    expect(evicted).toEqual(["sess-b"]);
    expect(loadSessionContext(store, "sess-a").entries.map((e) => e.seq)).toEqual([1, 2]);
  });

  it("counts a label write as keeping a session alive, because that is what the request path writes", () => {
    const evicted: string[] = [];
    const store = createMemorySessionContextStore({ maxSessions: 2, onEvict: (id) => evicted.push(id) });
    appendContextEntry(store, "sess-a", step(1));
    appendContextEntry(store, "sess-b", step(1));
    store.replaceIfcLabels("sess-a", ["confidential"]);
    appendContextEntry(store, "sess-c", step(1));
    expect(evicted).toEqual(["sess-b"]);
    expect(store.sourceLabels("sess-a")).toEqual(["confidential"]);
  });

  it("does not let a read pin a session, because reading about one is not using it", () => {
    const evicted: string[] = [];
    const store = createMemorySessionContextStore({ maxSessions: 2, onEvict: (id) => evicted.push(id) });
    appendContextEntry(store, "sess-a", step(1));
    appendContextEntry(store, "sess-b", step(1));
    // Reads, not writes: `sess-a` stays the least recently WRITTEN session
    // and is still the one evicted. The request path reads a session it is
    // about to write anyway, so write recency is the whole of "idle" here.
    expect(loadSessionContext(store, "sess-a").entries).toHaveLength(1);
    expect(store.sourceLabels("sess-a")).toEqual(["public"]);
    appendContextEntry(store, "sess-c", step(1));
    expect(evicted).toEqual(["sess-a"]);
  });

  it("never shortens a chain it keeps, even at the tightest cap there is", () => {
    // The bound deliberately not taken. Dropping a session's oldest entries
    // would leave a chain whose first surviving entry links to something
    // absent, and the Inspector's check never marks a first entry -- so a
    // front-truncated chain reads exactly like a complete one. The only
    // shortening this store performs is to nothing at all.
    const store = createMemorySessionContextStore({ maxSessions: 1, onEvict: () => {} });
    for (let n = 1; n <= 5; n++) appendContextEntry(store, "sess-a", step(n));
    expect(loadSessionContext(store, "sess-a").entries.map((e) => e.seq)).toEqual([1, 2, 3, 4, 5]);
  });

  it("restarts an evicted session at genesis rather than pretending to continue it", () => {
    const store = createMemorySessionContextStore({ maxSessions: 1, onEvict: () => {} });
    const before = appendContextEntry(store, "sess-a", step(1));
    appendContextEntry(store, "sess-b", step(1));
    const after = appendContextEntry(store, "sess-a", step(2));
    // Not `seq` 2 chained to `before`: the store no longer holds `before` and
    // does not claim to. A `seq` 1 against a `session_id` the log already
    // carries entries for is what makes the eviction visible downstream --
    // asserted end to end, through the Inspector's own chain check, in
    // test/session-context-roundtrip.test.ts.
    expect(after.seq).toBe(1);
    expect(after.prev_hash).toBe(GENESIS_HASH);
    expect(after.prev_hash).not.toBe(before.hash);
  });

  it("reports every eviction, so a cap set too low is never silent", () => {
    const evicted: string[] = [];
    const store = createMemorySessionContextStore({ maxSessions: 1, onEvict: (id) => evicted.push(id) });
    appendContextEntry(store, "sess-a", step(1));
    appendContextEntry(store, "sess-b", step(1));
    appendContextEntry(store, "sess-c", step(1));
    expect(evicted).toEqual(["sess-a", "sess-b"]);
  });

  it("keeps governing when the reporter throws, because a broken reporter must not become an ungoverned call", () => {
    const store = createMemorySessionContextStore({
      maxSessions: 1,
      onEvict: () => {
        throw new Error("reporter is broken");
      },
    });
    appendContextEntry(store, "sess-a", step(1));
    // The throw is swallowed and logged rather than propagated: it would
    // otherwise surface as a Guardian-side failure on whichever unrelated
    // step happened to overflow the cap, which the default posture resolves
    // by proceeding -- the exact outcome the cap exists to prevent.
    expect(() => appendContextEntry(store, "sess-b", step(1))).not.toThrow();
    expect(loadSessionContext(store, "sess-b").entries).toHaveLength(1);
  });

  it("refuses a cap below one instead of clamping it", () => {
    // Thrown, not clamped, for the reason `ACS_ON_DECISION_FAILURE` throws on
    // a posture it does not recognise: a store that remembers nothing must
    // not be one typo away from a store that remembers everything.
    expect(() => createMemorySessionContextStore({ maxSessions: 0 })).toThrow(/positive integer/);
    expect(() => createMemorySessionContextStore({ maxSessions: -1 })).toThrow(/positive integer/);
    expect(() => createMemorySessionContextStore({ maxSessions: 2.5 })).toThrow(/positive integer/);
  });
});

describe("append pushes onto the chain rather than rebuilding it", () => {
  it("hands each reader its own array, so a chain held across a step does not grow underneath it", () => {
    const store = createMemorySessionContextStore({ now: at("2026-08-14T00:00:00.000Z") });
    appendContextEntry(store, "sess-a", step(1));
    const held = loadSessionContext(store, "sess-a").entries;
    appendContextEntry(store, "sess-a", step(2));
    // `append` pushes onto the array the store keeps, which is what makes
    // `context` copying on the way out load-bearing rather than decorative:
    // uncopied, this reader's one-entry chain would silently have two.
    expect(held).toHaveLength(1);
    expect(loadSessionContext(store, "sess-a").entries).toHaveLength(2);
  });

  /**
   * A scaling test, not a stopwatch. It compares the per-append cost at two
   * sizes measured in the same process, so machine speed cancels and no
   * absolute duration is asserted -- a slow machine slows both halves.
   *
   * The shape this guards against is the one `append` used to have:
   * `entries: [...entries, entry]` rebuilt the whole history per step, which
   * is O(n) per step and O(n^2) per session, and the module doc on
   * session-context-store.ts says what a Guardian that slow does to a
   * decision that then never arrives.
   *
   * Measured on this tree before the threshold was picked (Apple M3 Max, bun
   * 1.3.14, three runs, 2000 vs 40000 appends on one session): pushing gives
   * a per-append ratio of 1.07-1.19, rebuilding gives 8.7-9.0. The bound is
   * 3, which sits 2.5x above what pushing measured and 2.9x below what
   * rebuilding measured.
   */
  it("costs the same per step at forty thousand entries as at two thousand", () => {
    const perAppendMs = (n: number): number => {
      const store = createMemorySessionContextStore({ now: at("2026-08-14T00:00:00.000Z") });
      const started = performance.now();
      for (let i = 1; i <= n; i++) appendContextEntry(store, "sess-a", step(i));
      return (performance.now() - started) / n;
    };
    // Warmed first, so JIT compilation of `append` is not charged to the
    // small sample and read as the small sample being slow.
    perAppendMs(500);
    const small = perAppendMs(2000);
    const large = perAppendMs(40000);
    expect(large / small).toBeLessThan(3);
  });
});
