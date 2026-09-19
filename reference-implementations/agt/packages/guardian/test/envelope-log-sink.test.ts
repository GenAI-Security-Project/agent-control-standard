import { describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createEnvelopeLogSink as createSink,
  extractRpcId,
  NULL_ENVELOPE_LOG_SINK,
  type EnvelopeLogEntry,
} from "../src/envelope-log-sink.ts";

/** A temp directory per test. Cleanup is deliberately non-recursive --
 * unlink the one file we created, then rmdir -- so a stray file makes the
 * test fail loudly instead of being silently blown away. */
async function withTempDir(
  run: (dir: string, createEnvelopeLogSink: typeof createSink) => Promise<void>,
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "acs-envelope-log-"));
  const sinks: ReturnType<typeof createSink>[] = [];
  try {
    await run(dir, (options) => {
      const sink = createSink(options);
      sinks.push(sink);
      return sink;
    });
  } finally {
    await Promise.all(sinks.map((sink) => sink.close()));
    try {
      unlinkSync(join(dir, "envelopes.jsonl"));
    } catch {
      // the test may not have produced a log at all -- that is the point of some of them
    }
    rmdirSync(dir);
  }
}

function readEntries(path: string): EnvelopeLogEntry[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line) as EnvelopeLogEntry);
}

const REQUEST = { jsonrpc: "2.0", method: "steps/toolCallRequest", id: 7, params: { acs_version: "0.1.0" } };
const RESPONSE = { jsonrpc: "2.0", id: 7, result: { decision: "deny" } };

describe("createEnvelopeLogSink -- the envelope log's JSONL format", () => {
  it("buffers a short burst instead of appending on the caller's stack", async () => {
    await withTempDir(async (dir, createEnvelopeLogSink) => {
      const path = join(dir, "envelopes.jsonl");
      const sink = createEnvelopeLogSink({ path });
      sink.write("request", REQUEST, "steps/toolCallRequest");
      sink.write("response", RESPONSE, "steps/toolCallRequest");
      expect(existsSync(path) ? readFileSync(path, "utf8") : "").toBe("");
      await sink.close();
      expect(readEntries(path).map((entry) => entry.seq)).toEqual([1, 2]);
    });
  });

  it("writes one line per call, with a monotonic seq starting at 1", async () => {
    await withTempDir(async (dir, createEnvelopeLogSink) => {
      const path = join(dir, "envelopes.jsonl");
      const sink = createEnvelopeLogSink({ path });

      sink.write("request", REQUEST, "steps/toolCallRequest");
      sink.write("response", RESPONSE, "steps/toolCallRequest");

      await sink.close();
      const entries = readEntries(path);
      expect(entries.map((e) => e.seq)).toEqual([1, 2]);
      expect(entries.map((e) => e.direction)).toEqual(["request", "response"]);
    });
  });

  // Checks that the JSON value reaches the envelope log unmodified --
  // nothing stripped, nothing reordered. This is not byte identity with the
  // wire: the sink is handed the already-parsed result of `await
  // req.json()`.
  it("records the envelope unmodified -- no reformatting or stripping", async () => {
    await withTempDir(async (dir, createEnvelopeLogSink) => {
      const path = join(dir, "envelopes.jsonl");
      const sink = createEnvelopeLogSink({ path });
      sink.write("request", REQUEST, "steps/toolCallRequest");

      await sink.close();
      expect(readEntries(path)[0]?.envelope).toEqual(REQUEST);
    });
  });

  it("carries rpc_id from both directions, so the Inspector can pair them", async () => {
    await withTempDir(async (dir, createEnvelopeLogSink) => {
      const path = join(dir, "envelopes.jsonl");
      const sink = createEnvelopeLogSink({ path });

      sink.write("request", REQUEST, "steps/toolCallRequest");
      sink.write("response", RESPONSE, "steps/toolCallRequest");

      await sink.close();
      expect(readEntries(path).map((e) => e.rpc_id)).toEqual([7, 7]);
    });
  });

  it("stamps recorded_at from the injected clock", async () => {
    await withTempDir(async (dir, createEnvelopeLogSink) => {
      const path = join(dir, "envelopes.jsonl");
      const sink = createEnvelopeLogSink({ path, now: () => new Date("2026-08-09T12:04:31.221Z") });

      sink.write("request", REQUEST, "steps/toolCallRequest");

      await sink.close();
      expect(readEntries(path)[0]?.recorded_at).toBe("2026-08-09T12:04:31.221Z");
    });
  });

  it("records method as null when the caller cannot determine one", async () => {
    await withTempDir(async (dir, createEnvelopeLogSink) => {
      const path = join(dir, "envelopes.jsonl");
      const sink = createEnvelopeLogSink({ path });
      sink.write("response", { jsonrpc: "2.0", id: null, error: { code: -32700 } }, null);

      await sink.close();
      const entry = readEntries(path)[0];
      expect(entry?.method).toBeNull();
      expect(entry?.rpc_id).toBeNull();
    });
  });

  // The whole reason the sink is a module rather than three inline
  // appendFileSync calls.
  it("never throws when the log path is unwritable, reports once, and goes quiet", async () => {
    await withTempDir(async (dir, createEnvelopeLogSink) => {
      const blocker = join(dir, "envelopes.jsonl");
      writeFileSync(blocker, "");
      // A path *through* a regular file: mkdirSync and appendFileSync both
      // fail with ENOTDIR, deterministically, on every platform.
      const path = join(blocker, "nested", "envelopes.jsonl");
      const errors: unknown[] = [];
      const sink = createEnvelopeLogSink({ path, onError: (error) => errors.push(error) });

      expect(() => sink.write("request", REQUEST, "steps/toolCallRequest")).not.toThrow();
      expect(() => sink.write("response", RESPONSE, "steps/toolCallRequest")).not.toThrow();
      expect(errors.length).toBe(1);
    });
  });

  it("never throws on an envelope JSON.stringify cannot serialize", async () => {
    await withTempDir(async (dir, createEnvelopeLogSink) => {
      const path = join(dir, "envelopes.jsonl");
      const errors: unknown[] = [];
      const sink = createEnvelopeLogSink({ path, onError: (error) => errors.push(error) });
      const circular: Record<string, unknown> = { id: 1 };
      circular.self = circular;

      expect(() => sink.write("request", circular, "steps/toolCallRequest")).not.toThrow();
      expect(errors.length).toBe(1);
    });
  });

  it("never throws when onError itself throws at construction time", async () => {
    await withTempDir(async (dir, createEnvelopeLogSink) => {
      const blocker = join(dir, "envelopes.jsonl");
      writeFileSync(blocker, "");
      const path = join(blocker, "nested", "envelopes.jsonl");

      expect(() => {
        createEnvelopeLogSink({
          path,
          onError: () => {
            throw new Error("onError threw");
          },
        });
      }).not.toThrow();
    });
  });

  it("never throws when onError itself throws at write time, and disables the sink", async () => {
    await withTempDir(async (dir, createEnvelopeLogSink) => {
      const path = join(dir, "envelopes.jsonl");
      const blocker = join(dir, "envelopes.jsonl");
      writeFileSync(blocker, "");

      const sink = createEnvelopeLogSink({
        path: join(blocker, "nested", "envelopes.jsonl"),
        onError: () => {
          throw new Error("onError threw");
        },
      });

      expect(() => sink.write("request", REQUEST, "steps/toolCallRequest")).not.toThrow();
      // The sink should be disabled, so the second write is a silent no-op
      expect(() => sink.write("response", RESPONSE, "steps/toolCallRequest")).not.toThrow();
    });
  });

  it("reports once when serialization fails while a disk failure is pending", async () => {
    await withTempDir(async (dir, createEnvelopeLogSink) => {
      const errors: unknown[] = [];
      // Opening a directory for append fails asynchronously, after write returns.
      const sink = createEnvelopeLogSink({ path: dir, onError: (error) => errors.push(error) });
      sink.write("request", REQUEST, "steps/toolCallRequest");
      const circular: Record<string, unknown> = {};
      circular.self = circular;
      sink.write("request", circular, "steps/toolCallRequest");
      await sink.close();
      expect(errors).toHaveLength(1);
      expect(errors[0]).toBeInstanceOf(TypeError);
    });
  });

  it("NULL_ENVELOPE_LOG_SINK writes nothing and never throws", () => {
    expect(() => NULL_ENVELOPE_LOG_SINK.write("request", REQUEST, "steps/toolCallRequest")).not.toThrow();
    expect(NULL_ENVELOPE_LOG_SINK.path).toBeNull();
  });
});

describe("extractRpcId", () => {
  it("reads string and number ids", () => {
    expect(extractRpcId({ id: 7 })).toBe(7);
    expect(extractRpcId({ id: "abc" })).toBe("abc");
  });

  it("returns null for a missing, null, or non-scalar id", () => {
    expect(extractRpcId({})).toBeNull();
    expect(extractRpcId({ id: null })).toBeNull();
    expect(extractRpcId({ id: { nested: true } })).toBeNull();
    expect(extractRpcId("not an object")).toBeNull();
  });
});
