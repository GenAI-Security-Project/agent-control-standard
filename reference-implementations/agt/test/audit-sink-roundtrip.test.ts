import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, readdirSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuditSink, type AuditEntry as AdapterAuditEntry } from "host-adapter";
// Not a bare "inspector" specifier: that string is a Node/Bun built-in
// module name (`node:inspector`), which core-module resolution picks over
// any workspace package of the same name with no way for us to override it.
// test/envelope-tap-roundtrip.test.ts sidesteps the same collision for the
// same package by importing the specific submodule directly rather than
// through the barrel; this file does the same.
import { tailAuditLog, type AuditEntry as InspectorAuditEntry } from "../packages/inspector/src/tail-audit-log.ts";

/**
 * The contract test that keeps two independent AuditEntry declarations
 * honest -- the same job test/envelope-tap-roundtrip.test.ts does for
 * EnvelopeLogEntry, and the reason the Inspector's import boundary (it must
 * never import the adapter) is meaningful rather than merely inconvenient.
 * The Inspector declares its own type because it must not import the
 * adapter's; that duplication is only safe while something fails when the
 * two drift.
 *
 * This file is the only place in the tree that imports both sides.
 */
const dirs: string[] = [];
function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "acs-audit-rt-"));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  while (dirs.length > 0) {
    const dir = dirs.pop() as string;
    for (const entry of readdirSync(dir)) unlinkSync(join(dir, entry));
    rmdirSync(dir);
  }
});

/**
 * The first entry the Inspector's tailer yields, or a failure that says so.
 *
 * A bare `for await` over the tailer fails the wrong way in the exact case
 * this exists to catch: if the Inspector's shape validator tightens past
 * what the adapter writes, the line stops being yielded, the loop never
 * completes, and the test dies of a bun-test timeout -- a red suite whose
 * message is "timed out after 5000ms", pointing nowhere near the drift.
 * Bounded here instead, so the same drift fails with a sentence naming it.
 */
async function firstEntry(path: string, timeoutMs = 1000): Promise<InspectorAuditEntry> {
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), timeoutMs);
  try {
    for await (const entry of tailAuditLog({
      path,
      fromStart: true,
      pollMs: 10,
      signal: controller.signal,
      // A line the validator rejects reaches this instead of the consumer,
      // and its text is what makes the failure below diagnosable.
      onMalformedLine: (line, error) => rejected.push({ line, error }),
    })) {
      return entry;
    }
  } finally {
    clearTimeout(deadline);
    controller.abort();
  }
  const detail =
    rejected.length > 0
      ? `its shape validator rejected the line the adapter wrote: ${String(
          rejected[0]?.error instanceof Error ? rejected[0]?.error.message : rejected[0]?.error,
        )} -- ${rejected[0]?.line}`
      : "no line was rejected either, so the entry never reached the tailer at all";
  throw new Error(`the Inspector's tailer yielded no entry within ${timeoutMs}ms: ${detail}`);
}

/** Populated by `firstEntry`'s malformed-line reporter; read only when it
 * has to explain a failure. Reset per test so one test's rejection cannot
 * be reported as another's. */
let rejected: { line: string; error: unknown }[] = [];
afterEach(() => {
  rejected = [];
});

/**
 * The drift direction `toEqual` cannot see. Every assertion below compares
 * runtime values, and the tailer yields the parsed JSON object whole -- so
 * dropping a field from the Inspector's type changes nothing at runtime and
 * fails nothing, even though the two declarations have then stopped being
 * one contract. These two assignments are the check, and they are enforced
 * by `bun run typecheck` rather than by `bun test`: a field on either side
 * that the other lacks makes one of them fail to compile, in the direction
 * that names which side lost it.
 *
 * `Required<>` on both sides, not the bare types, and that is load-bearing:
 * assignability alone ignores an optional field going missing (a value that
 * lacks it is still assignable), and `session_failure` -- the newest field,
 * and the one most likely to be dropped by a future edit -- is exactly that
 * shape. `Required<>` promotes every optional field to required, so a drop
 * on either side fails in the direction that names which side lost it.
 *
 * Deliberately not `as` casts between the two, and deliberately not
 * exported -- an `as` here would silence exactly what is being checked.
 *
 * The field sets are compared, not the field types, and the one place they
 * legitimately differ is why: `failure.kind` is `StepFailureKind` on the
 * writer, because the code that builds it (`applyFailurePosture`) always
 * constructs it from that union, so the type is true by construction --
 * that is the whole point of carrying the taxonomy to the durable boundary.
 * It stays `string` on the reader, because the Inspector parses a file it
 * did not write and `isAuditEntryShape` checks only that the field is a
 * string. Narrowing the reader's type to the union would make the
 * declaration claim something its own guard does not check -- exactly the
 * mistake this test exists to catch. Validating membership instead would
 * make the Inspector drop an audit line whose kind it does not recognise,
 * and a reader that silently discards records of fail-open proceeds is
 * worse than one that renders an unfamiliar word.
 *
 * So the drift this test exists to catch -- a field added or dropped on one
 * side -- is checked by key parity in both directions, which is what `toEqual`
 * cannot see either. Assignability is still asserted in the direction that must
 * hold at runtime: everything the adapter writes must be readable as what the
 * Inspector expects.
 *
 * ARM BY ARM, because `AuditEntry` is a union and `keyof` over a union is the
 * INTERSECTION of its arms' keys: comparing the unions whole would have
 * silently stopped checking every field either arm owns alone -- `failure`,
 * `posture`, `ungoverned`, all of them -- while still compiling and still
 * reading like a check. The arms are selected by their own discriminant
 * rather than by exported names, so neither side has to widen its export
 * surface to be checked here.
 */
type SameKeys<Adapter, Inspector> = [keyof Adapter] extends [keyof Inspector]
  ? [keyof Inspector] extends [keyof Adapter]
    ? true
    : { adapterIsMissing: Exclude<keyof Inspector, keyof Adapter> }
  : { inspectorIsMissing: Exclude<keyof Adapter, keyof Inspector> };

type PostureArm<Entry> = Extract<Entry, { outcome: "proceeded" | "blocked" }>;
type UngovernedArm<Entry> = Extract<Entry, { outcome: "ungoverned" }>;

type AdapterPostureArm = Required<PostureArm<AdapterAuditEntry>>;
type InspectorPostureArm = Required<PostureArm<InspectorAuditEntry>>;

const _postureArmFieldsMatch: SameKeys<AdapterPostureArm, InspectorPostureArm> = true;
const _ungovernedArmFieldsMatch: SameKeys<
  Required<UngovernedArm<AdapterAuditEntry>>,
  Required<UngovernedArm<InspectorAuditEntry>>
> = true;
const _failureFieldsMatch: SameKeys<AdapterPostureArm["failure"], InspectorPostureArm["failure"]> = true;
const _sessionFailureFieldsMatch: SameKeys<
  AdapterPostureArm["session_failure"],
  InspectorPostureArm["session_failure"]
> = true;
const _ungovernedFieldsMatch: SameKeys<
  Required<UngovernedArm<AdapterAuditEntry>>["ungoverned"],
  Required<UngovernedArm<InspectorAuditEntry>>["ungoverned"]
> = true;
const _inspectorAcceptsWhatTheAdapterWrites: Required<InspectorAuditEntry> = {} as Required<AdapterAuditEntry>;
void _postureArmFieldsMatch;
void _ungovernedArmFieldsMatch;
void _failureFieldsMatch;
void _sessionFailureFieldsMatch;
void _ungovernedFieldsMatch;
void _inspectorAcceptsWhatTheAdapterWrites;

describe("the audit log write and the Inspector's read agree on every field", () => {
  for (const outcome of ["proceeded", "blocked"] as const) {
    it(`round-trips a ${outcome} entry`, async () => {
      const path = join(scratch(), "audit.jsonl");
      createAuditSink({ path, now: () => new Date("2026-08-10T12:00:00.000Z") }).write({
        session_id: "sess-1",
        method: "steps/toolCallRequest",
        rpc_id: outcome === "proceeded" ? "req-1" : 7,
        posture: outcome === "proceeded" ? "proceed" : "deny",
        posture_source: "negotiated",
        outcome,
        failure: { kind: "timeout", message: "no response within 5000ms" },
      });

      // toEqual, not toMatchObject: an extra field on either side is drift,
      // and drift is exactly what this test exists to catch.
      expect(await firstEntry(path)).toEqual({
        seq: 1,
        recorded_at: "2026-08-10T12:00:00.000Z",
        session_id: "sess-1",
        method: "steps/toolCallRequest",
        rpc_id: outcome === "proceeded" ? "req-1" : 7,
        posture: outcome === "proceeded" ? "proceed" : "deny",
        posture_source: "negotiated",
        outcome,
        failure: { kind: "timeout", message: "no response within 5000ms" },
      });
    });
  }

  // Both fields together: a null `method` (nothing was sent, so no ACS
  // method was ever determined) and a `session_failure` beside the step's
  // own failure. The optional field is exactly where two independent type
  // declarations drift most quietly, so it is asserted with toEqual like the
  // rest.
  it("round-trips a null method and a session_failure", async () => {
    const path = join(scratch(), "audit.jsonl");
    createAuditSink({ path, now: () => new Date("2026-08-10T12:00:00.000Z") }).write({
      session_id: "sess-1",
      method: null,
      rpc_id: null,
      posture: "proceed",
      posture_source: "default",
      outcome: "proceeded",
      failure: { kind: "host_configuration", message: "no entry for this hook" },
      session_failure: { kind: "session_config_unstored", message: "EACCES: permission denied" },
    });

    expect(await firstEntry(path)).toEqual({
      seq: 1,
      recorded_at: "2026-08-10T12:00:00.000Z",
      session_id: "sess-1",
      method: null,
      rpc_id: null,
      posture: "proceed",
      posture_source: "default",
      outcome: "proceeded",
      failure: { kind: "host_configuration", message: "no entry for this hook" },
      session_failure: { kind: "session_config_unstored", message: "EACCES: permission denied" },
    });
  });

  it("survives a null rpc_id, which an unpaired failure produces", async () => {
    const path = join(scratch(), "audit.jsonl");
    createAuditSink({ path }).write({
      session_id: "s",
      method: "steps/toolCallRequest",
      rpc_id: null,
      posture: "proceed",
      posture_source: "default",
      outcome: "proceeded",
      failure: { kind: "transport", message: "gone" },
    });
    expect((await firstEntry(path)).rpc_id).toBeNull();
  });

  // The other arm, round-tripped whole. The reader's shape guard branches on
  // `outcome`, so this is also what proves the guard admits this kind of line
  // at all: a tailer that still required `posture` and `failure` would route
  // every skip to `onMalformedLine` and drop it, which is the reader's own
  // version of the silence the entry exists to end.
  it("round-trips an ungoverned entry, with no posture and no failure on it", async () => {
    const path = join(scratch(), "audit.jsonl");
    createAuditSink({ path, now: () => new Date("2026-08-10T12:00:00.000Z") }).write({
      session_id: "sess-1",
      method: "steps/toolCallResult",
      rpc_id: null,
      outcome: "ungoverned",
      ungoverned: { tool: "read", tools: ["bash"] },
    });

    expect(await firstEntry(path)).toEqual({
      seq: 1,
      recorded_at: "2026-08-10T12:00:00.000Z",
      session_id: "sess-1",
      method: "steps/toolCallResult",
      rpc_id: null,
      outcome: "ungoverned",
      ungoverned: { tool: "read", tools: ["bash"] },
    });
    expect(rejected).toEqual([]);
  });
});
