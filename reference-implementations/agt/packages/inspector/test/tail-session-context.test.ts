import { describe, expect, it } from "bun:test";
import {
  appendFileSync,
  mkdtempSync,
  rmdirSync,
  truncateSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { tailSessionContextLog, type SessionContextLogEntry } from "../src/tail-session-context.ts";
import {
  checkSessionChainLink,
  createSessionChainState,
  renderSessionChain,
  renderSessionChainRow,
} from "../src/render.ts";

const POLL_MS = 10;
const GENESIS_HASH = "0".repeat(64);

function entryLine(seq: number, overrides: Partial<SessionContextLogEntry> = {}): string {
  const entry: SessionContextLogEntry = {
    session_id: "sess-1",
    seq,
    prev_hash: GENESIS_HASH,
    hash: `hash-${seq}`,
    recorded_at: "2026-08-10T12:00:00.000Z",
    method: "steps/toolCallRequest",
    request_id: `req-${seq}`,
    tool_name: "run_shell",
    ...overrides,
  };
  return `${JSON.stringify(entry)}\n`;
}

/** Same fixture shape as `entryLine`, but the object itself -- for the
 * `renderSessionChain`/`renderSessionChainRow` tests below, which render
 * entries directly rather than tailing them from a file. */
function sessionEntry(overrides: Partial<SessionContextLogEntry> = {}): SessionContextLogEntry {
  return {
    session_id: "sess-1",
    seq: 1,
    prev_hash: GENESIS_HASH,
    hash: "hash-1",
    recorded_at: "2026-08-10T12:00:00.000Z",
    method: "steps/toolCallRequest",
    request_id: "req-1",
    tool_name: "run_shell",
    ...overrides,
  };
}

/** Collects `count` entries or rejects after `timeoutMs`, then aborts the
 * generator so the test cannot hang the suite. Mirrors
 * tail-audit-log.test.ts's own `collect`. */
async function collect(
  iterable: AsyncGenerator<SessionContextLogEntry, void, void>,
  count: number,
  controller: AbortController,
  timeoutMs = 3000,
): Promise<SessionContextLogEntry[]> {
  const out: SessionContextLogEntry[] = [];
  const deadline = setTimeout(() => controller.abort(), timeoutMs);
  try {
    for await (const entry of iterable) {
      out.push(entry);
      if (out.length >= count) {
        break;
      }
    }
  } finally {
    clearTimeout(deadline);
    controller.abort();
  }
  return out;
}

function withTempDir(run: (dir: string, path: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "acs-session-context-tail-"));
  const path = join(dir, "session-context.jsonl");
  return run(dir, path).finally(() => {
    try {
      unlinkSync(path);
    } catch {
      // some cases leave nothing behind to unlink
    }
    rmdirSync(dir);
  });
}

describe("tailSessionContextLog", () => {
  it("emits each entry already in the file, in chain order", async () => {
    await withTempDir(async (_dir, path) => {
      writeFileSync(
        path,
        entryLine(1, { prev_hash: GENESIS_HASH, hash: "hash-1" }) +
          entryLine(2, { prev_hash: "hash-1", hash: "hash-2" }) +
          entryLine(3, { prev_hash: "hash-2", hash: "hash-3" }),
      );
      const controller = new AbortController();
      const tail = tailSessionContextLog({ path, fromStart: true, pollMs: POLL_MS, signal: controller.signal });

      const entries = await collect(tail, 3, controller);
      expect(entries.map((e) => e.seq)).toEqual([1, 2, 3]);
      expect(entries.map((e) => e.hash)).toEqual(["hash-1", "hash-2", "hash-3"]);
    });
  });

  it("emits entries appended after the tail starts", async () => {
    await withTempDir(async (_dir, path) => {
      writeFileSync(path, "");
      const controller = new AbortController();
      const tail = tailSessionContextLog({ path, pollMs: POLL_MS, signal: controller.signal });

      // Calling collect() (without awaiting yet) drives the async generator
      // synchronously up to its first internal await, which is what starts
      // the (lazily-started) poll timer -- so the appends below land after
      // polling is already active, with no sleep needed to arrange that.
      const collecting = collect(tail, 2, controller);
      appendFileSync(path, entryLine(1) + entryLine(2));

      const entries = await collecting;
      expect(entries.map((e) => e.seq)).toEqual([1, 2]);
    });
  });

  it("resets when the file is truncated underneath it", async () => {
    await withTempDir(async (_dir, path) => {
      // The first entry's request_id is deliberately long, so the file's
      // byte length after truncation-and-replacement below is unambiguously
      // shorter than the offset it established -- regardless of exactly
      // when a poll happens to land relative to the truncate and the
      // append. That determinism is what lets this test wait only on the
      // tail's own emission, never on a bare duration.
      writeFileSync(path, entryLine(1, { request_id: "req-1-with-a-long-identifier-to-pad-the-offset" }));
      const controller = new AbortController();
      const tail = tailSessionContextLog({ path, fromStart: true, pollMs: POLL_MS, signal: controller.signal });

      const { value: first } = await tail.next();
      expect(first?.seq).toBe(1);

      truncateSync(path, 0);
      appendFileSync(path, entryLine(9, { request_id: "r9" }));

      const entries = await collect(tail, 1, controller);
      expect(entries.map((e) => e.seq)).toEqual([9]);
    });
  });

  it("skips a malformed line rather than stopping the tail", async () => {
    await withTempDir(async (_dir, path) => {
      const malformed: string[] = [];
      writeFileSync(path, "");
      const controller = new AbortController();
      const tail = tailSessionContextLog({
        path,
        fromStart: true,
        pollMs: POLL_MS,
        signal: controller.signal,
        onMalformedLine: (line) => malformed.push(line),
      });

      const collecting = collect(tail, 1, controller);
      // Three different malformed shapes -- each valid JSON, none a valid
      // SessionContextLogEntry -- mirroring tail-audit-log.test.ts's own
      // coverage of this branch: a partially-shaped object, a wrong-shape
      // object, and a bare array. All three are skipped, and the entry
      // appended after them still arrives.
      appendFileSync(path, '{"session_id":"sess-1"}\n{"not":"a session context entry"}\n[]\n' + entryLine(1));

      const entries = await collecting;
      expect(entries.map((e) => e.seq)).toEqual([1]);
      expect(malformed).toEqual(['{"session_id":"sess-1"}', '{"not":"a session context entry"}', "[]"]);
    });
  });
});

describe("renderSessionChain", () => {
  it("shows each entry's seq, tool, and a short hash", () => {
    const entry: SessionContextLogEntry = {
      session_id: "sess-1",
      seq: 1,
      prev_hash: GENESIS_HASH,
      hash: "abcdef0123456789fedcba9876543210",
      recorded_at: "2026-08-10T12:00:00.000Z",
      method: "steps/toolCallRequest",
      request_id: "req-1",
      tool_name: "run_shell",
    };

    const rendered = renderSessionChain([entry]);
    expect(rendered).toContain("#1");
    expect(rendered).toContain("run_shell");
    expect(rendered).toContain(entry.hash.slice(0, 12));
    // The renderer must not print the full 64-character hash on the row --
    // only an abbreviated one, which is the whole point of "short".
    expect(rendered).not.toContain(entry.hash);
  });

  it("marks a break where prev_hash does not match the entry before it", () => {
    const first: SessionContextLogEntry = {
      session_id: "sess-1",
      seq: 1,
      prev_hash: GENESIS_HASH,
      hash: "hash-1",
      recorded_at: "2026-08-10T12:00:00.000Z",
      method: "steps/toolCallRequest",
      request_id: "req-1",
      tool_name: "run_shell",
    };
    const second: SessionContextLogEntry = {
      session_id: "sess-1",
      seq: 2,
      // Does not match `first.hash` -- a break by construction.
      prev_hash: "not-hash-1",
      hash: "hash-2",
      recorded_at: "2026-08-10T12:00:01.000Z",
      method: "steps/toolCallRequest",
      request_id: "req-2",
      tool_name: "run_shell",
    };

    const rendered = renderSessionChain([first, second]);
    const lines = rendered.split("\n");
    expect(lines).toHaveLength(2);
    expect(lines[0]).not.toContain("CHAIN BREAK");
    expect(lines[1]).toContain("CHAIN BREAK");
  });

  it("renders an empty chain as an explicit empty state, not a blank panel", () => {
    // The exact text, not merely "non-blank" -- a placeholder string of any
    // shape would satisfy a non-blank check without actually being the
    // documented empty state.
    expect(renderSessionChain([])).toBe("(no session chain entries)");
  });

  it("does not falsely mark a break when two sessions' rows interleave, though naive adjacent-row comparison would", () => {
    const sessionAFirst = sessionEntry({ session_id: "sess-A", seq: 1, hash: "hash-a1", request_id: "req-a1" });
    const sessionBFirst = sessionEntry({ session_id: "sess-B", seq: 1, hash: "hash-b1", request_id: "req-b1" });
    // Correctly chains to sessionAFirst's hash -- but the row immediately
    // BEFORE this one in file order is sessionBFirst, not sessionAFirst,
    // because the two sessions interleave. A check that compared this
    // entry's prev_hash to the PREVIOUS ARRAY ELEMENT'S hash (naive
    // adjacent-row comparison -- the exact bug the per-session state in
    // checkSessionChainLink exists to prevent) would compare "hash-a1"
    // against sessionBFirst.hash ("hash-b1"), see a mismatch, and report a
    // false break. The per-session state instead compares it against
    // sessionAFirst.hash, which it correctly matches.
    const sessionASecond = sessionEntry({
      session_id: "sess-A",
      seq: 2,
      prev_hash: "hash-a1",
      hash: "hash-a2",
      request_id: "req-a2",
    });

    // File order: A1, B1, A2 -- session A's own two entries are not adjacent.
    const rendered = renderSessionChain([sessionAFirst, sessionBFirst, sessionASecond]);
    const lines = rendered.split("\n");
    expect(lines).toHaveLength(3);
    expect(lines[0]).not.toContain("CHAIN BREAK");
    expect(lines[1]).not.toContain("CHAIN BREAK");
    expect(lines[2]).not.toContain("CHAIN BREAK");
  });

  it("does not garble a row whose tool_name contains a literal newline, since each row is its own value rather than text split out of a joined string", () => {
    const state = createSessionChainState();
    const withNewline = sessionEntry({ hash: "hash-1", tool_name: "run_shell\nrm -rf /" });
    const next = sessionEntry({ seq: 2, prev_hash: "hash-1", hash: "hash-2", request_id: "req-2" });

    const firstRow = renderSessionChainRow(withNewline, checkSessionChainLink(withNewline, state));
    const secondRow = renderSessionChainRow(next, checkSessionChainLink(next, state));

    // The embedded newline reaches the row whole -- renderSessionChainRow
    // never splits or rejoins rendered text, so nothing here can misalign
    // it the way extracting a row by splitting joined output on "\n" would.
    expect(firstRow).toContain("run_shell\nrm -rf /");
    // And it did not corrupt the state carried into the next call: the
    // second row still reads its own predecessor's hash correctly.
    expect(secondRow).not.toContain("CHAIN BREAK");
  });

  // If the check and the renderer were one function, this second call would
  // read the state the first call had written -- the entry's own hash --
  // find its prev_hash no longer matching, and report a chain break that the
  // log did not contain.
  it("renders the same entry twice identically, because rendering is not the check", () => {
    const state = createSessionChainState();
    const entry = sessionEntry({ hash: "hash-1" });
    const link = checkSessionChainLink(entry, state);

    expect(renderSessionChainRow(entry, link)).toBe(renderSessionChainRow(entry, link));
    expect(renderSessionChainRow(entry, link)).not.toContain("CHAIN BREAK");
  });

  // The mirror of the test above: what the check DOES carry between calls.
  // Re-checking an entry the state has already seen is a genuine repeat, and
  // the second answer says so -- the first `hash` recorded is the one the next
  // `prev_hash` must match, and an entry never links to itself.
  it("reports a break when one entry is checked twice, because the check is the thing that remembers", () => {
    const state = createSessionChainState();
    const entry = sessionEntry({ hash: "hash-1" });

    expect(checkSessionChainLink(entry, state).broken).toBe(false);
    expect(checkSessionChainLink(entry, state).broken).toBe(true);
  });
});
