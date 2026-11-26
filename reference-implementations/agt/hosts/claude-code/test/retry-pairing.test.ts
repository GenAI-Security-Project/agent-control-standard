import { afterEach, describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, readdirSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { appliedRequestPath } from "host-adapter";

/**
 * Issue #351, end to end through two real subprocesses: the request gate
 * retries a call after REPLAY_DETECTED in one process, the result gate runs
 * in another that never saw the retry, and the result still names the
 * request this host acted on.
 *
 * A stub Guardian rather than the real one, because the shipped Guardian
 * records a duplicate `request_id` as a finding and still decides the step
 * (see its README's known limits), so it cannot produce the REPLAY_DETECTED
 * this test is about. The stub answers the first `steps/toolCallRequest`
 * with that error, the second with an allow, and keeps every envelope it was
 * sent so the assertion is about ids that actually crossed the wire.
 */
const SHIM = fileURLToPath(new URL("../acs-hook.ts", import.meta.url));
const SESSION = "retry-1";
const CALL = "toolu_retry_01";

const dirs: string[] = [];
function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "acs-retry-pairing-"));
  dirs.push(dir);
  return dir;
}

/** Removes exactly what a run can leave behind, by name, never recursively. */
function cleanupScratch(dir: string): void {
  const sessionsDir = join(dir, "sessions");
  const appliedDir = join(sessionsDir, "applied");
  for (const file of [join(dir, "audit.jsonl"), join(sessionsDir, `${SESSION}.json`)]) {
    if (existsSync(file)) {
      unlinkSync(file);
    }
  }
  if (existsSync(appliedDir)) {
    for (const entry of readdirSync(appliedDir)) {
      unlinkSync(join(appliedDir, entry));
    }
    rmdirSync(appliedDir);
  }
  if (existsSync(sessionsDir)) {
    rmdirSync(sessionsDir);
  }
  rmdirSync(dir);
}

afterEach(() => {
  while (dirs.length > 0) {
    cleanupScratch(dirs.pop() as string);
  }
});

type Envelope = { id: string | number; method: string; params: { request_id: string; payload: Record<string, unknown> } };

/** The stub described above. `seen` is every envelope, in arrival order. */
function retryingStub(): { server: ReturnType<typeof Bun.serve>; seen: Envelope[] } {
  const seen: Envelope[] = [];
  let requests = 0;
  const server = Bun.serve({
    port: 0,
    async fetch(req) {
      const body = (await req.json()) as Envelope;
      seen.push(body);
      if (body.method === "handshake/hello") {
        return Response.json({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            negotiated_version: "0.1.0",
            methods_evaluated: ["steps/toolCallRequest", "steps/toolCallResult"],
            selected_transport: "http",
            timeout_config: { default_ms: 5000 },
            on_decision_failure: "proceed",
          },
        });
      }
      if (body.method === "steps/toolCallRequest" && requests++ === 0) {
        return Response.json({ jsonrpc: "2.0", id: body.id, error: { code: -32005, message: "duplicate request_id" } });
      }
      return Response.json({ jsonrpc: "2.0", id: body.id, result: { decision: "allow", request_id: body.params.request_id } });
    },
  });
  return { server, seen };
}

async function runShim(stdin: string, env: Record<string, string>): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(["bun", "run", SHIM], {
    stdin: new TextEncoder().encode(stdin),
    env: { ...process.env, ...env },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  return { exitCode: await proc.exited, stdout, stderr };
}

const requestPayload = JSON.stringify({
  session_id: SESSION,
  hook_event_name: "PreToolUse",
  tool_name: "Bash",
  tool_use_id: CALL,
  tool_input: { command: "ls -la" },
});

const resultPayload = JSON.stringify({
  session_id: SESSION,
  hook_event_name: "PostToolUse",
  tool_name: "Bash",
  tool_use_id: CALL,
  tool_input: { command: "ls -la" },
  tool_response: { stdout: "total 0", stderr: "", interrupted: false, isImage: false, noOutputExpected: false },
});

describe("acs-hook — a result names the request this host acted on, across processes", () => {
  it("names the retry after REPLAY_DETECTED, not the derived request the Guardian refused", async () => {
    const dir = scratch();
    const { server, seen } = retryingStub();
    try {
      const env = {
        ACS_GUARDIAN_URL: `http://localhost:${server.port}/acs`,
        ACS_SESSION_DIR: join(dir, "sessions"),
        ACS_AUDIT_LOG: join(dir, "audit.jsonl"),
      };

      const request = await runShim(requestPayload, env);
      expect({ exitCode: request.exitCode, stderr: request.stderr }).toEqual({ exitCode: 0, stderr: "" });
      expect(JSON.parse(request.stdout).hookSpecificOutput.permissionDecision).toBe("allow");

      const asks = seen.filter((e) => e.method === "steps/toolCallRequest");
      expect(asks).toHaveLength(2);
      const [derived, retry] = asks.map((e) => e.params.request_id);
      expect(retry).not.toBe(derived);
      // The record the next process reads, where the README says it lives.
      expect(existsSync(appliedRequestPath(join(dir, "sessions", "applied"), derived!))).toBe(true);

      const result = await runShim(resultPayload, env);
      expect({ exitCode: result.exitCode, stderr: result.stderr }).toEqual({ exitCode: 0, stderr: "" });

      const results = seen.filter((e) => e.method === "steps/toolCallResult");
      expect(results).toHaveLength(1);
      expect(results[0]!.params.payload.request_id_ref).toBe(retry!);
      // A decision arrived both times, so nothing was audited as a failure.
      expect(existsSync(join(dir, "audit.jsonl"))).toBe(false);
    } finally {
      server.stop(true);
    }
  });

  it("names the derived request when the first ask was decided, writing no record", async () => {
    const dir = scratch();
    const { server, seen } = retryingStub();
    try {
      const env = {
        ACS_GUARDIAN_URL: `http://localhost:${server.port}/acs`,
        ACS_SESSION_DIR: join(dir, "sessions"),
        ACS_AUDIT_LOG: join(dir, "audit.jsonl"),
      };
      // Spend the stub's one REPLAY_DETECTED on another call, so this call's
      // first ask is decided outright.
      await runShim(requestPayload.replace(CALL, "toolu_other"), env);
      seen.length = 0;

      const request = await runShim(requestPayload, env);
      expect({ exitCode: request.exitCode, stderr: request.stderr }).toEqual({ exitCode: 0, stderr: "" });
      const asks = seen.filter((e) => e.method === "steps/toolCallRequest");
      expect(asks).toHaveLength(1);

      const result = await runShim(resultPayload, env);
      expect({ exitCode: result.exitCode, stderr: result.stderr }).toEqual({ exitCode: 0, stderr: "" });
      const results = seen.filter((e) => e.method === "steps/toolCallResult");
      expect(results[0]!.params.payload.request_id_ref).toBe(asks[0]!.params.request_id);
    } finally {
      server.stop(true);
    }
  });
});
