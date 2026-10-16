import { describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startGuardian } from "../src/index.ts";
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

async function withGuardian(run: (url: string, logPath: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "acs-request-id-ref-"));
  const logPath = join(dir, "envelopes.jsonl");
  const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml", envelopeLogPath: logPath });
  try {
    await run(guardian.url, logPath);
  } finally {
    await guardian.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

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
});
