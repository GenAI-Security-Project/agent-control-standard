import { afterEach, describe, expect, it } from "bun:test";
import { appendFileSync, mkdtempSync, readdirSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  appendContextEntry,
  createMemorySessionContextStore,
  type SessionContextEntry as GuardianSessionContextEntry,
} from "guardian";
// Not a bare "inspector" specifier: that string is a Node/Bun built-in
// module name (`node:inspector`), which core-module resolution picks over
// any workspace package of the same name with no way for us to override it.
// test/envelope-log-sink-roundtrip.test.ts and test/audit-sink-roundtrip.test.ts
// sidestep the same collision the same way, importing the specific submodule
// directly rather than through the barrel; this file does the same.
import {
  tailSessionContextLog,
  type SessionContextLogEntry as InspectorSessionContextLogEntry,
} from "../packages/inspector/src/tail-session-context.ts";
import {
  checkSessionChainLink,
  createSessionChainState,
  renderSessionChainRow,
} from "../packages/inspector/src/render.ts";

/**
 * Two claims about the seam between the store that writes the
 * session-context log and the Inspector that reads it. Both need both sides
 * in one file.
 *
 * The first is the contract test that keeps two independent
 * SessionContextLogEntry declarations honest -- the same job
 * test/audit-sink-roundtrip.test.ts and
 * test/envelope-log-sink-roundtrip.test.ts do for their own pairs, and the
 * reason the Inspector's import boundary is meaningful rather than merely
 * inconvenient. The Inspector declares its own type because it must not
 * import the Guardian's; that duplication is only safe while something fails
 * when the two drift.
 *
 * The second is what makes the store's session cap honest. The store evicts
 * whole sessions rather than truncating a session's entries, and the
 * justification is that the shortening stays visible: an evicted session that
 * comes back restarts at the genesis hash, and the Inspector reports that as
 * a CHAIN BREAK rather than as a fresh session. That is a claim about the
 * reader, so it is checked against the reader instead of being asserted in
 * the writer's own header comment.
 *
 * This file is the only place in the tree that imports both sides.
 */
const dirs: string[] = [];
function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "acs-session-context-rt-"));
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
 * The first `count` entries the Inspector's tailer yields, or a failure that
 * SAYS SO.
 *
 * Bounded rather than a bare `for await`, for the same reason
 * test/audit-sink-roundtrip.test.ts's own `firstEntry` is: if the Inspector's
 * shape validator tightens past what the store writes, the line stops being
 * yielded, the loop never completes, and the test dies of a bun-test timeout
 * whose message points nowhere near the drift. Bounded here instead, so the
 * same drift fails with a sentence naming it.
 *
 * Takes a count rather than returning the first entry alone, because the
 * chain-break claim below is about the third line's relation to the first,
 * and one entry cannot express it.
 */
async function entriesFrom(path: string, count = 1, timeoutMs = 1000): Promise<InspectorSessionContextLogEntry[]> {
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), timeoutMs);
  const collected: InspectorSessionContextLogEntry[] = [];
  try {
    for await (const entry of tailSessionContextLog({
      path,
      fromStart: true,
      pollMs: 10,
      signal: controller.signal,
      // A line the validator rejects reaches this instead of the consumer,
      // and its text is what makes the failure below diagnosable.
      onMalformedLine: (line, error) => rejected.push({ line, error }),
    })) {
      collected.push(entry);
      if (collected.length === count) return collected;
    }
  } finally {
    clearTimeout(deadline);
    controller.abort();
  }
  const detail =
    rejected.length > 0
      ? `its shape validator rejected a line the store wrote: ${String(
          rejected[0]?.error instanceof Error ? rejected[0]?.error.message : rejected[0]?.error,
        )} -- ${rejected[0]?.line}`
      : "no line was rejected either, so the entries never reached the tailer at all";
  throw new Error(
    `the Inspector's tailer yielded ${collected.length} of ${count} entries within ${timeoutMs}ms: ${detail}`,
  );
}

/** Populated by `firstEntry`'s malformed-line reporter; read only when it
 * has to explain a failure. Reset per test so one test's rejection cannot
 * be reported as another's. */
let rejected: { line: string; error: unknown }[] = [];
afterEach(() => {
  rejected = [];
});

/**
 * The drift direction `toEqual` cannot see. The assertion below compares
 * RUNTIME values, and the tailer yields the parsed JSON object whole -- so
 * dropping a field from the Inspector's TYPE changes nothing at runtime and
 * fails nothing, even though the two declarations have then stopped being
 * one contract. These two assignments are the check, and they are enforced
 * by `bun run typecheck` rather than by `bun test`: a field on either side
 * that the other lacks makes one of them fail to compile, in the direction
 * that names which side lost it.
 *
 * `Required<>` on both sides, not the bare types -- same reasoning as
 * test/audit-sink-roundtrip.test.ts's own version of this check: every field
 * on `SessionContextEntry` happens to be required today, so `Required<>` is
 * a no-op now, but it is what keeps this check meaningful the day a field
 * here becomes optional on one side and not the other.
 *
 * Deliberately not `as` casts between the two, and deliberately not
 * exported -- an `as` here would silence exactly what is being checked.
 */
type SameKeys<Writer, Reader> = [keyof Writer] extends [keyof Reader]
  ? [keyof Reader] extends [keyof Writer]
    ? true
    : { writerIsMissing: Exclude<keyof Reader, keyof Writer> }
  : { readerIsMissing: Exclude<keyof Writer, keyof Reader> };

const _entryFieldsMatch: SameKeys<Required<GuardianSessionContextEntry>, Required<InspectorSessionContextLogEntry>> =
  true;
const _inspectorAcceptsWhatTheStoreWrites: Required<InspectorSessionContextLogEntry> =
  {} as Required<GuardianSessionContextEntry>;
void _entryFieldsMatch;
void _inspectorAcceptsWhatTheStoreWrites;

describe("a write through the store and a read through the Inspector: every field survives", () => {
  it("round-trips a Guardian-written entry through the Inspector's own declaration", async () => {
    const path = join(scratch(), "session-context.jsonl");
    // `createMemorySessionContextStore`'s real `append` -- the same code
    // packages/guardian/src/server.ts wires a live Guardian to -- is what
    // builds the entry and computes its hash. Only the file-append itself is
    // supplied here, mirroring what server.ts's own (unexported)
    // `createSessionContextLogAppender` does: append the line plus one
    // newline.
    const store = createMemorySessionContextStore({
      now: () => new Date("2026-08-10T12:00:00.000Z"),
      appendLine: (line) => appendFileSync(path, `${line}\n`),
    });

    const written = appendContextEntry(store, "sess-1", {
      method: "steps/toolCallRequest",
      request_id: "req-1",
      tool_name: "run_shell",
    });

    // toEqual, not toMatchObject: an extra field on either side is drift,
    // and drift is exactly what this test exists to catch. Compared against
    // the real object the store returned, not a hand-copied literal, so the
    // comparison cannot itself drift out of step with the writer's fields.
    expect(await entriesFrom(path)).toEqual([written]);
  });
});

describe("an evicted session that comes back reads as a broken chain, not as a fresh one", () => {
  it("makes the store's forgetting visible through the Inspector's own chain check", async () => {
    const path = join(scratch(), "session-context.jsonl");
    const step = (n: number) => ({
      method: "steps/toolCallRequest",
      request_id: `req-${n}`,
      tool_name: "run_shell",
    });
    const store = createMemorySessionContextStore({
      now: () => new Date("2026-08-10T12:00:00.000Z"),
      appendLine: (line) => appendFileSync(path, `${line}\n`),
      // A cap of one, so the second session evicts the first. The default
      // `onEvict` reports to stderr and is asserted where it belongs, in
      // packages/guardian/test/session-context.test.ts; silenced here because
      // this test is about what the LOG says, which is the half a warning
      // cannot cover.
      maxSessions: 1,
      onEvict: () => {},
    });

    appendContextEntry(store, "sess-1", step(1));
    appendContextEntry(store, "sess-2", step(1));
    appendContextEntry(store, "sess-1", step(2));

    const entries = await entriesFrom(path, 3);
    // One `SessionChainState` across the whole walk, exactly as the
    // Inspector's live view keeps one for the life of the process -- the
    // check has to remember a hash for `sess-1` across `sess-2`'s
    // interleaved row for the break to be findable at all.
    const state = createSessionChainState();
    const links = entries.map((entry) => checkSessionChainLink(entry, state));

    expect(entries.map((entry) => entry.session_id)).toEqual(["sess-1", "sess-2", "sess-1"]);
    // The third line is `sess-1`'s second appearance in the log and links to
    // genesis rather than to `sess-1`'s first hash. That is the whole reason
    // the cap is allowed to evict: the shortening announces itself. Had the
    // cap truncated entries within a session instead, every surviving link
    // would still match and this row would read as unbroken.
    expect(links.map((link) => link.broken)).toEqual([false, false, true]);
    expect(renderSessionChainRow(entries[2]!, links[2]!)).toContain("CHAIN BREAK");
  });
});
