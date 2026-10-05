// SPDX-License-Identifier: Apache-2.0
import { expect, it } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startGuardian } from "../src/server.ts";

function request() {
  return {
    jsonrpc: "2.0", method: "steps/toolCallRequest", id: 1,
    params: {
      acs_version: "0.1.0", request_id: crypto.randomUUID(), timestamp: new Date().toISOString(),
      metadata: { agent_id: "test", session_id: crypto.randomUUID() },
      payload: { tool: { name: "run_shell" }, arguments: { command: { value: "ls" } } },
    },
  };
}

function readLines(path: string): Record<string, unknown>[] {
  return readFileSync(path, "utf8").trim().split("\n").map((line) => JSON.parse(line));
}

function cleanup(dir: string): void {
  for (const name of ["envelopes.jsonl", "context.jsonl"]) {
    const path = join(dir, name);
    if (existsSync(path)) unlinkSync(path);
  }
  rmdirSync(dir);
}

it("close waits for an active decision and drains its response and session record", async () => {
  const dir = mkdtempSync(join(tmpdir(), "acs-log-shutdown-"));
  const entered = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const guardian = await startGuardian({
    port: 0, manifestPath: "policy/manifest.yaml",
    envelopeLogPath: join(dir, "envelopes.jsonl"), sessionContextLog: join(dir, "context.jsonl"),
    bridge: { async evaluate() { entered.resolve(); await release.promise; return { decision: "allow" }; } },
  });
  try {
    const response = fetch(guardian.url, { method: "POST", body: JSON.stringify(request()) });
    await entered.promise;
    const closing = guardian.close();
    let closed = false;
    void closing.then(() => { closed = true; });
    await Promise.resolve();
    expect(closed).toBe(false);
    release.resolve();
    expect(((await (await response).json()) as { result: { decision: string } }).result.decision).toBe("allow");
    await closing;
    expect(guardian.close()).toBe(closing);
    expect(readLines(join(dir, "envelopes.jsonl")).map((entry) => entry.direction)).toEqual(["request", "response"]);
    expect(readLines(join(dir, "context.jsonl")).map((entry) => entry.seq)).toEqual([1]);
  } finally {
    release.resolve();
    await guardian.close();
    cleanup(dir);
  }
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  it(`the standalone Guardian drains its logs on ${signal}`, async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-log-signal-"));
    const child = Bun.spawn([process.execPath, "run", "packages/guardian/src/main.ts"], {
      env: {
        ...process.env, ACS_GUARDIAN_PORT: "0",
        ACS_ENVELOPE_LOG: join(dir, "envelopes.jsonl"), ACS_SESSION_CONTEXT_LOG: join(dir, "context.jsonl"),
      },
      stdout: "pipe", stderr: "pipe", timeout: 3000,
    });
    try {
      const reader = child.stdout.getReader();
      const decoder = new TextDecoder();
      let output = "";
      let url: string | undefined;
      try {
        while (!url) {
          const { done, value } = await reader.read();
          if (done) throw new Error(`Guardian exited before its startup banner: ${output}`);
          output += decoder.decode(value, { stream: true });
          url = /Guardian listening at (http:\/\/localhost:\d+\/acs)\n/.exec(output)?.[1];
        }
      } finally {
        reader.releaseLock();
      }
      const response = await fetch(url, { method: "POST", body: JSON.stringify(request()) });
      expect(((await response.json()) as { result: { decision: string } }).result.decision).toBe("allow");
      child.kill(signal);
      expect(await child.exited).toBe(0);
      expect(readLines(join(dir, "envelopes.jsonl")).map((entry) => entry.seq)).toEqual([1, 2]);
      expect(readLines(join(dir, "context.jsonl")).map((entry) => entry.seq)).toEqual([1]);
    } finally {
      if (child.exitCode === null) child.kill("SIGKILL");
      await child.exited;
      cleanup(dir);
    }
  });
}
