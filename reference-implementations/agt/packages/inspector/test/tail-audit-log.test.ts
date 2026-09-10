import { describe, expect, it } from "bun:test";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmdirSync,
  statSync,
  truncateSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { tailAuditLog, type AuditEntry } from "../src/tail-audit-log.ts";

const POLL_MS = 10;

/** The posture arm, which is what every line below is: this suite is about
 * the tailer's file handling -- offsets, truncation, a log that vanishes --
 * and not about which kind of entry a line holds. The `ungoverned` arm has
 * its own shape test at the bottom of this file. */
type PostureAuditEntry = Extract<AuditEntry, { outcome: "proceeded" | "blocked" }>;

function entryLine(seq: number, overrides: Partial<PostureAuditEntry> = {}): string {
  const entry: PostureAuditEntry = {
    seq,
    recorded_at: "2026-08-10T12:00:00.000Z",
    session_id: "sess-1",
    method: "steps/toolCallRequest",
    rpc_id: seq,
    posture: "proceed",
    posture_source: "negotiated",
    outcome: "proceeded",
    failure: { kind: "timeout", message: "no response within 5000ms" },
    ...overrides,
  };
  return `${JSON.stringify(entry)}\n`;
}

/** Collects `count` entries or rejects after `timeoutMs`, then aborts the
 * generator so the test cannot hang the suite. */
async function collect(
  iterable: AsyncGenerator<AuditEntry, void, void>,
  count: number,
  controller: AbortController,
  timeoutMs = 3000,
): Promise<AuditEntry[]> {
  const out: AuditEntry[] = [];
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
  const dir = mkdtempSync(join(tmpdir(), "acs-audit-tail-"));
  const path = join(dir, "audit.jsonl");
  return run(dir, path).finally(() => {
    try {
      unlinkSync(path);
    } catch {
      // some cases leave nothing behind to unlink
    }
    rmdirSync(dir);
  });
}

describe("tailAuditLog", () => {
  it("streams what arrives after the tail starts", async () => {
    await withTempDir(async (_dir, path) => {
      writeFileSync(path, "");
      const controller = new AbortController();
      const tail = tailAuditLog({ path, pollMs: POLL_MS, signal: controller.signal });
      // No poll runs during this sleep -- nobody has called .next() yet, so
      // the (lazily-started) timer has not started either. The starting
      // offset (0, since the file above was empty) was already captured
      // synchronously above, at call time. This sleep just puts real time
      // between construction and the appends below, before consumption ever
      // begins.
      await Bun.sleep(POLL_MS * 3);
      appendFileSync(path, entryLine(1) + entryLine(2));

      const entries = await collect(tail, 2, controller);
      expect(entries.map((e) => e.seq)).toEqual([1, 2]);
    });
  });

  it("fromStart replays what is already there; without it, nothing does", async () => {
    await withTempDir(async (_dir, path) => {
      writeFileSync(path, entryLine(1) + entryLine(2));
      const controller = new AbortController();
      const tail = tailAuditLog({ path, fromStart: true, pollMs: POLL_MS, signal: controller.signal });

      const entries = await collect(tail, 2, controller);
      expect(entries.map((e) => e.seq)).toEqual([1, 2]);
    });

    await withTempDir(async (_dir, path) => {
      writeFileSync(path, entryLine(1) + entryLine(2));
      const controller = new AbortController();
      const tail = tailAuditLog({ path, pollMs: POLL_MS, signal: controller.signal });

      await Bun.sleep(POLL_MS * 5);
      controller.abort();
      const entries: AuditEntry[] = [];
      for await (const entry of tail) {
        entries.push(entry);
      }
      expect(entries).toEqual([]);
    });
  });

  it("reassembles a partial line written in two chunks with a poll in between", async () => {
    await withTempDir(async (_dir, path) => {
      const line = entryLine(1);
      const split = Math.floor(line.length / 2);
      writeFileSync(path, "");
      const controller = new AbortController();
      const tail = tailAuditLog({ path, fromStart: true, pollMs: POLL_MS, signal: controller.signal });

      appendFileSync(path, line.slice(0, split));
      // Start consuming now, before the second chunk lands, so the
      // (now lazily-started) timer actually ticks against the partial line
      // at least once before the rest arrives.
      const collecting = collect(tail, 1, controller);
      await Bun.sleep(POLL_MS * 5);
      appendFileSync(path, line.slice(split));

      const entries = await collecting;
      expect(entries).toHaveLength(1);
      expect(entries[0]).toEqual(JSON.parse(line));
    });
  });

  it("routes a line that parses but is not an AuditEntry, and yields nothing", async () => {
    await withTempDir(async (_dir, path) => {
      const malformed: string[] = [];
      writeFileSync(path, "");
      const controller = new AbortController();
      const tail = tailAuditLog({
        path,
        fromStart: true,
        pollMs: POLL_MS,
        signal: controller.signal,
        onMalformedLine: (line) => malformed.push(line),
      });

      // Calling next() (without awaiting yet) runs the generator body
      // synchronously up to its first await, which is what starts the
      // timer -- so the poll below is guaranteed to run against these
      // lines rather than racing a not-yet-started one.
      const pending = tail.next();
      appendFileSync(path, '{"seq":1}\n{"not":"an entry"}\n[]\n');
      await Bun.sleep(POLL_MS * 5);
      controller.abort();

      const { value, done } = await pending;
      expect(done).toBe(true);
      expect(value).toBeUndefined();
      expect(malformed).toEqual(['{"seq":1}', '{"not":"an entry"}', "[]"]);
    });
  });

  it("resets the offset on truncation without re-delivering what was already parsed", async () => {
    await withTempDir(async (_dir, path) => {
      writeFileSync(path, entryLine(1));
      const controller = new AbortController();
      const tail = tailAuditLog({ path, fromStart: true, pollMs: POLL_MS, signal: controller.signal });

      const { value: first } = await tail.next();
      expect(first?.seq).toBe(1);

      truncateSync(path, 0);
      await Bun.sleep(POLL_MS * 3);
      appendFileSync(path, entryLine(9));

      const entries = await collect(tail, 1, controller);
      expect(entries.map((e) => e.seq)).toEqual([9]);
    });
  });

  it("reports a poll error through onPollError and keeps streaming once the file returns", async () => {
    await withTempDir(async (_dir, path) => {
      writeFileSync(path, entryLine(1));
      const pollErrors: unknown[] = [];
      const controller = new AbortController();
      const tail = tailAuditLog({
        path,
        fromStart: true,
        pollMs: POLL_MS,
        signal: controller.signal,
        onPollError: (error) => pollErrors.push(error),
      });

      const { value: first } = await tail.next();
      expect(first?.seq).toBe(1);

      unlinkSync(path);
      await Bun.sleep(POLL_MS * 5);
      expect(pollErrors.length).toBeGreaterThan(0);

      writeFileSync(path, entryLine(9));
      const entries = await collect(tail, 1, controller);
      expect(entries.map((e) => e.seq)).toEqual([9]);
    });
  });

  // Fix round: a log that has never existed is the healthy default -- a
  // session with zero fail-open bypasses never causes the sink on the other
  // side to create the file at all. Before the fix, every tick against a
  // missing path reported through onPollError regardless of whether the
  // path had ever existed, which meant this ordinary case printed a poll
  // error every `pollMs` for as long as the Inspector ran.
  it("never calls onPollError for a log that has never existed", async () => {
    await withTempDir(async (_dir, path) => {
      const pollErrors: unknown[] = [];
      const controller = new AbortController();
      const tail = tailAuditLog({
        path,
        fromStart: true,
        pollMs: POLL_MS,
        signal: controller.signal,
        onPollError: (error) => pollErrors.push(error),
      });

      // next() runs the generator body up to its first await, which is what
      // starts the (lazily-started) timer -- so the sleep below is
      // guaranteed to cover several real ticks against a path that has
      // never been created, not zero.
      const pending = tail.next();
      await Bun.sleep(POLL_MS * 5);
      controller.abort();
      await pending;

      expect(pollErrors).toEqual([]);
    });
  });

  // The third way a poll can fail, and the one the report-once discipline
  // did not reach: a log that EXISTS and cannot be read. Pointing the tail
  // at a directory makes `existsSync` true and `statSync().size` non-zero,
  // so the read is attempted and `readSync` throws EISDIR every tick --
  // deterministic, no race needed. The missing-file case was fixed to report
  // on the transition; this branch still reported once per tick, which is
  // the same wall of identical lines through a different door.
  it("reports an unreadable log once across several ticks, not once per tick", async () => {
    await withTempDir(async (dir, _path) => {
      const asDirectory = join(dir, "audit-as-dir");
      mkdirSync(asDirectory);
      // Non-zero st_size for the directory, so `size > offset` and the read
      // is actually attempted rather than skipped.
      writeFileSync(join(asDirectory, "child"), "x");
      const pollErrors: unknown[] = [];
      const controller = new AbortController();
      const tail = tailAuditLog({
        path: asDirectory,
        fromStart: true,
        pollMs: POLL_MS,
        signal: controller.signal,
        onPollError: (error) => pollErrors.push(error),
      });

      // In a `finally`, so a failing assertion does not leave the directory
      // behind for `withTempDir`'s own `rmdirSync` to trip over -- an
      // ENOTEMPTY thrown from cleanup would replace the assertion error with
      // a filesystem one and hide what actually failed.
      try {
        // next() runs the generator body to its first await, which starts the
        // lazily-started timer -- so the sleep below covers several real ticks.
        const pending = tail.next();
        await Bun.sleep(POLL_MS * 8);
        expect(pollErrors).toHaveLength(1);

        controller.abort();
        await pending;
      } finally {
        controller.abort();
        unlinkSync(join(asDirectory, "child"));
        rmdirSync(asDirectory);
      }
    });
  });

  // And the other half of "once per transition": a fault that clears and
  // returns is a new incident and is reported again. Without the reset, one
  // unreadable tick would silence every later failure for the life of the
  // process -- which is the opposite failure, and just as bad.
  it("reports again after a fault clears and returns", async () => {
    await withTempDir(async (dir, _path) => {
      const target = join(dir, "flapping.jsonl");
      const pollErrors: unknown[] = [];
      const controller = new AbortController();
      const tail = tailAuditLog({
        path: target,
        fromStart: true,
        pollMs: POLL_MS,
        signal: controller.signal,
        onPollError: (error) => pollErrors.push(error),
      });
      const pending = tail.next();

      // Same reason as the test above: cleanup in a `finally`, so a failing
      // assertion surfaces as itself rather than as an ENOTEMPTY from
      // `withTempDir`. Whichever state the path is left in -- directory or
      // file -- is removed by name.
      try {
        // Fault 1: a directory where a log should be.
        mkdirSync(target);
        writeFileSync(join(target, "child"), "x");
        await Bun.sleep(POLL_MS * 6);
        expect(pollErrors).toHaveLength(1);

        // It clears: a real, readable log at the same path.
        unlinkSync(join(target, "child"));
        rmdirSync(target);
        writeFileSync(target, entryLine(1));
        await Bun.sleep(POLL_MS * 6);
        expect(pollErrors).toHaveLength(1);

        // Fault 2, the same shape. A new incident, so it is reported again.
        unlinkSync(target);
        mkdirSync(target);
        writeFileSync(join(target, "child"), "x");
        await Bun.sleep(POLL_MS * 8);
        expect(pollErrors).toHaveLength(2);

        controller.abort();
        await pending;
      } finally {
        controller.abort();
        if (statSync(target, { throwIfNoEntry: false })?.isDirectory()) {
          if (existsSync(join(target, "child"))) {
            unlinkSync(join(target, "child"));
          }
          rmdirSync(target);
        } else if (existsSync(target)) {
          unlinkSync(target);
        }
      }
    });
  });

  // Fix round: the opposite case -- a log that existed and then vanished --
  // must still be reported, but exactly once for the whole gap, not once
  // per tick. Also confirms the offset reset that recreation depends on:
  // without it, a same-length replacement file landing at the already-
  // consumed offset would read as no growth at all.
  it("reports a vanished log exactly once across several ticks, then delivers again once it returns", async () => {
    await withTempDir(async (_dir, path) => {
      writeFileSync(path, entryLine(1));
      const pollErrors: unknown[] = [];
      const controller = new AbortController();
      const tail = tailAuditLog({
        path,
        fromStart: true,
        pollMs: POLL_MS,
        signal: controller.signal,
        onPollError: (error) => pollErrors.push(error),
      });

      const { value: first } = await tail.next();
      expect(first?.seq).toBe(1);

      unlinkSync(path);
      // Several poll intervals elapse while the log stays gone. The report
      // must land on the first tick of the gap and nowhere after.
      await Bun.sleep(POLL_MS * 8);
      expect(pollErrors).toHaveLength(1);

      writeFileSync(path, entryLine(9));
      const entries = await collect(tail, 1, controller);
      expect(entries.map((e) => e.seq)).toEqual([9]);
      // Recreation must not itself count as a second gap report.
      expect(pollErrors).toHaveLength(1);
    });
  });

  // Fix round, mirroring tail-envelope-log.test.ts's own mid-codepoint case.
  // The split below lands inside the emoji's 4-byte UTF-8 sequence, so
  // neither chunk on its own is valid UTF-8 -- exactly what a `pending` that
  // decoded each poll's bytes to a string before concatenating would
  // corrupt into a replacement character. Built as a Buffer sliced at a
  // chosen byte offset, not a JS string sliced by character index, because
  // only the former can land mid-byte-sequence on disk.
  it("reassembles a line whose split lands mid-codepoint, without corrupting the multi-byte character", async () => {
    await withTempDir(async (_dir, path) => {
      const note = "🎉café";
      const entry: AuditEntry = {
        seq: 7,
        recorded_at: "2026-08-10T12:00:00.000Z",
        session_id: note,
        method: "steps/toolCallRequest",
        rpc_id: 7,
        posture: "proceed",
        posture_source: "negotiated",
        outcome: "proceeded",
        failure: { kind: "timeout", message: "no response within 5000ms" },
      };
      const line = `${JSON.stringify(entry)}\n`;
      const bytes = Buffer.from(line, "utf8");
      const emojiStart = bytes.indexOf(Buffer.from("🎉", "utf8"));
      const splitAt = emojiStart + 2;
      writeFileSync(path, "");
      const controller = new AbortController();
      const tail = tailAuditLog({ path, fromStart: true, pollMs: POLL_MS, signal: controller.signal });

      appendFileSync(path, bytes.subarray(0, splitAt));
      const collecting = collect(tail, 1, controller);
      await Bun.sleep(POLL_MS * 5);
      appendFileSync(path, bytes.subarray(splitAt));

      const entries = await collecting;
      expect(entries).toHaveLength(1);
      expect(entries[0]?.session_id).toBe(note);
      expect(entries[0]).toEqual(entry);
    });
  });

  // The `ungoverned` arm, which the shape guard reaches by branching on
  // `outcome` rather than by making every posture field optional. Both
  // directions matter: the arm has to be admitted (a guard that still
  // required `posture` would route every skip to onMalformedLine and drop
  // it -- the reader's own version of the silence the entry exists to end),
  // and a line claiming the arm without carrying its payload has to be
  // rejected, because the renderer prints that payload unconditionally.
  it("delivers an ungoverned line, which carries no posture and no failure", async () => {
    await withTempDir(async (_dir, path) => {
      const entry: AuditEntry = {
        seq: 1,
        recorded_at: "2026-08-10T12:00:00.000Z",
        session_id: "sess-1",
        method: "steps/toolCallResult",
        rpc_id: null,
        outcome: "ungoverned",
        ungoverned: { tool: "read", tools: ["bash"] },
      };
      writeFileSync(path, `${JSON.stringify(entry)}\n`);
      const controller = new AbortController();
      const malformed: string[] = [];
      const tail = tailAuditLog({
        path,
        fromStart: true,
        pollMs: POLL_MS,
        signal: controller.signal,
        onMalformedLine: (line) => malformed.push(line),
      });

      expect(await collect(tail, 1, controller)).toEqual([entry]);
      expect(malformed).toEqual([]);
    });
  });

  it.each([
    ["no ungoverned block at all", { outcome: "ungoverned" }],
    ["a tools list holding a non-string", { outcome: "ungoverned", ungoverned: { tool: "read", tools: [7] } }],
    ["no tool name", { outcome: "ungoverned", ungoverned: { tools: ["bash"] } }],
  ])("rejects an ungoverned line with %s", async (_label, tail_fields) => {
    await withTempDir(async (_dir, path) => {
      const line = `${JSON.stringify({
        seq: 1,
        recorded_at: "2026-08-10T12:00:00.000Z",
        session_id: "sess-1",
        method: null,
        rpc_id: null,
        ...tail_fields,
      })}\n`;
      // A well-formed line after the bad one, so this asserts the bad line
      // was skipped rather than that the tailer merely produced nothing yet.
      writeFileSync(path, line + entryLine(2));
      const controller = new AbortController();
      const malformed: string[] = [];
      const tail = tailAuditLog({
        path,
        fromStart: true,
        pollMs: POLL_MS,
        signal: controller.signal,
        onMalformedLine: (bad) => malformed.push(bad),
      });

      const entries = await collect(tail, 1, controller);
      expect(entries.map((e) => e.seq)).toEqual([2]);
      expect(malformed).toHaveLength(1);
    });
  });
});
