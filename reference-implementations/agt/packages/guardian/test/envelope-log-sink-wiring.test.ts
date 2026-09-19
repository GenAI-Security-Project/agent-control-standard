import { describe, expect, it, spyOn } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startGuardian } from "../src/index.ts";
import type { EnvelopeLogEntry } from "../src/envelope-log-sink.ts";

function makeEnvelope(
  method: string,
  payload: Record<string, unknown>,
  overrides: { id?: number; requestId?: string } = {},
): Record<string, unknown> {
  const { id = 1, requestId = crypto.randomUUID() } = overrides;
  return {
    jsonrpc: "2.0",
    method,
    id,
    params: {
      acs_version: "0.1.0",
      request_id: requestId,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "agent-1", session_id: crypto.randomUUID() },
      payload,
    },
  };
}

function toolCallEnvelope(command: string, overrides: { id?: number } = {}) {
  return makeEnvelope(
    "steps/toolCallRequest",
    { tool: { name: "run_shell" }, arguments: { command: { value: command } } },
    overrides,
  );
}

function readEntries(path: string): EnvelopeLogEntry[] {
  if (!existsSync(path)) {
    return [];
  }
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line) as EnvelopeLogEntry);
}

/** Non-recursive cleanup, as in envelope-log-sink.test.ts. */
async function withGuardian(
  logPathFor: (dir: string) => string,
  run: (url: string, logPath: string, close: () => Promise<void>) => Promise<void>,
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "acs-envelope-log-wiring-"));
  const logPath = logPathFor(dir);
  const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml", envelopeLogPath: logPath });
  try {
    await run(guardian.url, logPath, () => guardian.close());
  } finally {
    await guardian.close();
    try {
      unlinkSync(logPath);
    } catch {
      // some tests deliberately make the path unwritable
    }
    try {
      rmdirSync(dir);
    } catch {
      // a blocker file may remain; the assertions already covered what matters
    }
  }
}

async function postRaw(url: string, body: string): Promise<unknown> {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body });
  return await res.json();
}

const logIn = (dir: string) => join(dir, "envelopes.jsonl");

describe("Guardian envelope log wiring", () => {
  it("records one request and one response per exchange, paired by rpc_id", async () => {
    await withGuardian(logIn, async (url, logPath, close) => {
      await postRaw(url, JSON.stringify(toolCallEnvelope("rm -rf /", { id: 11 })));

      await close();
      const entries = readEntries(logPath);
      expect(entries.length).toBe(2);
      expect(entries[0]?.direction).toBe("request");
      expect(entries[1]?.direction).toBe("response");
      expect(entries[0]?.rpc_id).toBe(11);
      expect(entries[1]?.rpc_id).toBe(11);
      expect(entries[0]?.method).toBe("steps/toolCallRequest");
      expect(entries[1]?.method).toBe("steps/toolCallRequest");
      expect((entries[1]?.envelope as { result?: { decision?: string } }).result?.decision).toBe("deny");
    });
  });

  it("records handshake/hello in both directions", async () => {
    await withGuardian(logIn, async (url, logPath, close) => {
      await postRaw(url, JSON.stringify(makeEnvelope("handshake/hello", {}, { id: 42 })));

      await close();
      const entries = readEntries(logPath);
      expect(entries.map((e) => e.direction)).toEqual(["request", "response"]);
      expect(entries.every((e) => e.method === "handshake/hello")).toBe(true);
    });
  });

  // The envelope that fails validation is the most useful thing an
  // ACS-first reader can see; recording it after the validator is exactly
  // what would hide it. This envelope names steps/* and carries a
  // request_id, so it is addressable -- the schema failure arrives as an
  // honoured deny decision (a JSON-RPC success), not a bare error. Still
  // recorded in both directions the same as any other response (asserted
  // below).
  it("records a schema-invalid steps/* request, then its deny decision", async () => {
    await withGuardian(logIn, async (url, logPath, close) => {
      const bad = toolCallEnvelope("rm -rf /", { id: 12 });
      delete (bad.params as Record<string, unknown>).acs_version;

      await postRaw(url, JSON.stringify(bad));

      await close();
      const entries = readEntries(logPath);
      expect(entries.length).toBe(2);
      expect(entries[0]?.direction).toBe("request");
      expect((entries[0]?.envelope as { params: Record<string, unknown> }).params.acs_version).toBeUndefined();
      expect(entries[1]?.direction).toBe("response");
      const result = (entries[1]?.envelope as { result?: { decision?: string; reason_codes?: string[]; policy_references?: unknown[] } })
        .result;
      expect(result?.decision).toBe("deny");
      expect(result?.reason_codes).toEqual(["envelope_invalid"]);
      expect(result?.policy_references).toEqual([]);
    });
  });

  it("records an unparseable body as a lone response with rpc_id null -- no request line to pair with", async () => {
    await withGuardian(logIn, async (url, logPath, close) => {
      await postRaw(url, "{not json");

      await close();
      const entries = readEntries(logPath);
      expect(entries.length).toBe(1);
      expect(entries[0]?.direction).toBe("response");
      expect(entries[0]?.rpc_id).toBeNull();
      expect(entries[0]?.method).toBeNull();
      expect((entries[0]?.envelope as { error?: { code: number } }).error?.code).toBe(-32700);
    });
  });

  // End to end: the sink is on the decision path, so this is the test that
  // says a broken sink cannot become a fail-open.
  //
  // No `onError` is passed here, so this exercises the sink's *default*
  // reporter -- a single `console.error` line -- rather than the
  // onError-captured path envelope-log-sink.test.ts's "reports once, then goes
  // quiet" test covers. Spied and silenced so a deliberately-broken sink
  // does not print real stderr into a clean `bun test` run, and asserted
  // on so "reports once" is checked at the call site instead of merely
  // claimed.
  it("still denies rm -rf / when every envelope-log write fails", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-envelope-log-broken-"));
    const blocker = join(dir, "blocker");
    writeFileSync(blocker, "");
    const errorSpy = spyOn(console, "error").mockImplementation(() => {});
    try {
      const guardian = await startGuardian({
        port: 0,
        manifestPath: "policy/manifest.yaml",
        envelopeLogPath: join(blocker, "nested", "envelopes.jsonl"),
      });
      try {
        const response = (await postRaw(guardian.url, JSON.stringify(toolCallEnvelope("rm -rf /")))) as {
          result?: { decision?: string };
          error?: unknown;
        };
        expect(response.error).toBeUndefined();
        expect(response.result?.decision).toBe("deny");
        expect(errorSpy).toHaveBeenCalledTimes(1);
      } finally {
        await guardian.close();
      }
    } finally {
      errorSpy.mockRestore();
      unlinkSync(blocker);
      rmdirSync(dir);
    }
  });

  it("writes nothing when envelopeLogPath is omitted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-envelope-log-off-"));
    const logPath = join(dir, "envelopes.jsonl");
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
    try {
      await postRaw(guardian.url, JSON.stringify(toolCallEnvelope("ls -la")));
      expect(existsSync(logPath)).toBe(false);
    } finally {
      await guardian.close();
      rmdirSync(dir);
    }
  });
});
