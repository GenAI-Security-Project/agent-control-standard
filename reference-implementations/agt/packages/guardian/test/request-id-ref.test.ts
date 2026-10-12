import { describe, expect, it, spyOn } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startGuardian, type StartGuardianOptions } from "../src/index.ts";
import { handshakeFor } from "../../../test/helpers/handshake.ts";
import type { EnvelopeLogEntry } from "../src/envelope-log-sink.ts";

// hooks.md, toolCallResult: a Guardian SHOULD resolve request_id_ref against
// the session's toolCallRequest records and MUST record a reference it cannot
// resolve. These tests drive a running Guardian and read its envelope log,
// which is the Guardian's audit record.

let rpcId = 0;

function envelope(method: string, sessionId: string, payload: Record<string, unknown>, requestId: string = crypto.randomUUID()) {
  rpcId += 1;
  return {
    jsonrpc: "2.0",
    method,
    id: rpcId,
    params: {
      acs_version: "0.1.0",
      request_id: requestId,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "agent-1", session_id: sessionId },
      payload,
    },
  };
}

function toolRequest(sessionId: string, requestId: string) {
  return envelope(
    "steps/toolCallRequest",
    sessionId,
    { tool: { name: "Bash" }, arguments: { command: { value: "ls" } } },
    requestId,
  );
}

function toolResult(sessionId: string, requestIdRef?: string) {
  const payload: Record<string, unknown> = { tool: { name: "Bash" }, exit_status: "success", outputs: [{ value: "a.txt" }] };
  if (requestIdRef !== undefined) {
    payload.request_id_ref = requestIdRef;
  }
  return envelope("steps/toolCallResult", sessionId, payload);
}

async function post(url: string, body: unknown): Promise<Record<string, unknown>> {
  await handshakeFor(url, body);
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return (await res.json()) as Record<string, unknown>;
}

function findings(path: string): EnvelopeLogEntry[] {
  if (!existsSync(path)) {
    return [];
  }
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line) as EnvelopeLogEntry)
    .filter((entry) => entry.direction === "finding");
}

async function withGuardian(
  run: (url: string, logPath: string) => Promise<void>,
  options: Partial<StartGuardianOptions> = {},
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "acs-request-id-ref-"));
  const logPath = join(dir, "envelopes.jsonl");
  const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml", envelopeLogPath: logPath, ...options });
  try {
    await run(guardian.url, logPath);
  } finally {
    await guardian.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A replay store that lets every request through. §10.3's replay check
 * refuses a repeat inside the skew window first, so the duplicate finding
 * fires only for a repeat that check missed; this stands in for one. */
const MISSED_REPLAY: Partial<StartGuardianOptions> = { replayProtectionStore: { seenOrRemember: () => "fresh" } };

describe("request_id_ref resolution", () => {
  it("records a reference the session never saw, and leaves the decision to policy", async () => {
    await withGuardian(async (url, logPath) => {
      const sessionId = crypto.randomUUID();
      const unknownRef = crypto.randomUUID();
      const result = toolResult(sessionId, unknownRef);

      const response = await post(url, result);

      expect(response.result).toBeDefined();
      const recorded = findings(logPath);
      expect(recorded).toHaveLength(1);
      const [finding] = recorded;
      expect(finding?.method).toBe("steps/toolCallResult");
      expect(finding?.rpc_id).toBe(result.id);
      expect(finding?.envelope).toEqual({
        finding: "request_id_ref_unresolved",
        session_id: sessionId,
        request_id: result.params.request_id,
        request_id_ref: unknownRef,
      });
    });
  });

  it("records nothing when the reference names this session's toolCallRequest", async () => {
    await withGuardian(async (url, logPath) => {
      const sessionId = crypto.randomUUID();
      const requestId = crypto.randomUUID();
      await post(url, toolRequest(sessionId, requestId));

      await post(url, toolResult(sessionId, requestId));

      expect(findings(logPath)).toHaveLength(0);
    });
  });

  it("records nothing when the result carries no reference", async () => {
    await withGuardian(async (url, logPath) => {
      await post(url, toolResult(crypto.randomUUID()));

      expect(findings(logPath)).toHaveLength(0);
    });
  });

  it("treats a request from another session as unresolved, because request_id is unique only within a session", async () => {
    await withGuardian(async (url, logPath) => {
      const requestId = crypto.randomUUID();
      await post(url, toolRequest(crypto.randomUUID(), requestId));

      await post(url, toolResult(crypto.randomUUID(), requestId));

      expect(findings(logPath)).toHaveLength(1);
    });
  });

  // The record is a MUST, and the envelope log is allowed to be absent or to
  // disable itself, so a finding the log did not take goes to stderr.
  async function stderrFindings(envelopeLogPath: string | undefined): Promise<unknown[]> {
    const lines: string[] = [];
    const spy = spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      lines.push(args.map(String).join(" "));
    });
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml", envelopeLogPath });
    try {
      await post(guardian.url, toolResult(crypto.randomUUID(), crypto.randomUUID()));
    } finally {
      await guardian.close();
      spy.mockRestore();
    }
    return lines.filter((line) => line.startsWith("acs-finding ")).map((line) => JSON.parse(line.slice("acs-finding ".length)));
  }

  it("writes the finding to stderr when no envelope log is configured", async () => {
    const recorded = await stderrFindings(undefined);
    expect(recorded).toHaveLength(1);
    expect(recorded[0]).toMatchObject({ finding: "request_id_ref_unresolved" });
  });

  it("writes the finding to stderr when the envelope log has disabled itself", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-request-id-ref-"));
    // A file where the log's parent directory should be, so the sink cannot
    // create the directory and disables itself before the first write.
    const blocker = join(dir, "not-a-dir");
    writeFileSync(blocker, "");
    try {
      const recorded = await stderrFindings(join(blocker, "envelopes.jsonl"));
      expect(recorded).toHaveLength(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not also write to stderr when the envelope log took the finding", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-request-id-ref-"));
    try {
      expect(await stderrFindings(join(dir, "envelopes.jsonl"))).toHaveLength(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("records a toolCallRequest whose request_id the session already holds, and still decides it", async () => {
    await withGuardian(async (url, logPath) => {
      const sessionId = crypto.randomUUID();
      const requestId = crypto.randomUUID();
      await post(url, toolRequest(sessionId, requestId));

      const repeat = await post(url, toolRequest(sessionId, requestId));

      expect(repeat.result).toBeDefined();
      const recorded = findings(logPath);
      expect(recorded).toHaveLength(1);
      expect(recorded[0]?.envelope).toEqual({ finding: "request_id_duplicate", session_id: sessionId, request_id: requestId });
    }, MISSED_REPLAY);
  });

  it("refuses a repeat inside the skew window with REPLAY_DETECTED, before any finding", async () => {
    await withGuardian(async (url, logPath) => {
      const sessionId = crypto.randomUUID();
      const requestId = crypto.randomUUID();
      await post(url, toolRequest(sessionId, requestId));

      const repeat = await post(url, toolRequest(sessionId, requestId));

      expect((repeat.error as { code: number }).code).toBe(-32005);
      expect(findings(logPath)).toHaveLength(0);
    });
  });

  it("puts the log line's fields on a stderr finding too", async () => {
    const [recorded] = await stderrFindings(undefined);
    expect(recorded).toMatchObject({ method: "steps/toolCallResult", finding: "request_id_ref_unresolved" });
    expect(recorded).toHaveProperty("recorded_at");
    expect(recorded).toHaveProperty("rpc_id");
  });

  it("records a toolCallResult that reuses an earlier request's request_id, since §10.3 covers every method", async () => {
    await withGuardian(async (url, logPath) => {
      const sessionId = crypto.randomUUID();
      const requestId = crypto.randomUUID();
      await post(url, toolRequest(sessionId, requestId));

      const reused = toolResult(sessionId, requestId);
      reused.params.request_id = requestId;
      await post(url, reused);

      const codes = findings(logPath).map((entry) => (entry.envelope as { finding: string }).finding);
      expect(codes).toEqual(["request_id_duplicate"]);
    }, MISSED_REPLAY);
  });

  it("puts the finding on the result's own chain entry, which is the Guardian's audit record", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-request-id-ref-"));
    const chainPath = join(dir, "session-context.jsonl");
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml", sessionContextLog: chainPath });
    try {
      const unknownRef = crypto.randomUUID();
      await post(guardian.url, toolResult(crypto.randomUUID(), unknownRef));
    } finally {
      await guardian.close();
    }
    try {
      const [entry] = readFileSync(chainPath, "utf8").trim().split("\n").map((line) => JSON.parse(line));
      expect(entry.findings).toEqual(["request_id_ref_unresolved"]);
      expect(entry.request_id_ref).toMatch(/^[0-9a-f-]{36}$/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

