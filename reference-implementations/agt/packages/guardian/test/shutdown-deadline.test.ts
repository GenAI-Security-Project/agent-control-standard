// SPDX-License-Identifier: Apache-2.0
import { expect, it, spyOn } from "bun:test";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { NULL_OTEL_TRACE_EXPORTER } from "../src/otel-trace-exporter.ts";
import { buildServerHello } from "../src/handshake.ts";
import { startGuardian } from "../src/server.ts";

const timeoutMs = buildServerHello().timeout_config.default_ms;

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

it("closes within the negotiated deadline when a decision never finishes, without trace export", async () => {
  const entered = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const guardian = await startGuardian({
    port: 0, manifestPath: "policy/manifest.yaml",
    bridge: { async evaluate() { entered.resolve(); await release.promise; return { decision: "allow" }; } },
  });
  const response = fetch(guardian.url, { method: "POST", body: JSON.stringify(request()) });
  try {
    await entered.promise;
    const closing = guardian.close();
    expect(guardian.close()).toBe(closing);
    let closed = false;
    void closing.then(() => { closed = true; });
    await Bun.sleep(timeoutMs + 500);
    expect(closed).toBe(true);
  } finally {
    release.resolve();
    await response;
    await guardian.close();
  }
}, timeoutMs + 5000);

it("bounds both log drains by one deadline before shutting down the trace exporter", async () => {
  const dir = fs.mkdtempSync(join(tmpdir(), "acs-log-deadline-"));
  const releases: (() => void)[] = [];
  const streams: Writable[] = [];
  const create = spyOn(fs, "createWriteStream").mockImplementation(() => {
    const stream = new Writable({ write(_chunk, _encoding, done) { releases.push(done); } });
    streams.push(stream);
    return stream as fs.WriteStream;
  });
  let shutdowns = 0;
  const guardian = await startGuardian({
    port: 0, manifestPath: "policy/manifest.yaml",
    envelopeLogPath: join(dir, "envelopes.jsonl"), sessionContextLog: join(dir, "context.jsonl"),
    traceExporter: { ...NULL_OTEL_TRACE_EXPORTER, async shutdown() { shutdowns += 1; } },
    bridge: { async evaluate() { return { decision: "allow" }; } },
  });
  try {
    const response = await fetch(guardian.url, { method: "POST", body: JSON.stringify(request()) });
    expect(response.ok).toBe(true);
    await response.arrayBuffer();
    const closing = guardian.close();
    let closed = false;
    void closing.then(() => { closed = true; });
    await Bun.sleep(10);
    expect(closed).toBe(false);
    expect(shutdowns).toBe(0);
    await Bun.sleep(timeoutMs + 500);
    expect(streams).toHaveLength(2);
    expect(streams.every((stream) => stream.writableEnded && !stream.writableFinished)).toBe(true);
    expect(closed).toBe(true);
    expect(shutdowns).toBe(1);
    expect(guardian.close()).toBe(closing);
  } finally {
    create.mockRestore();
    for (const stream of streams) stream.destroy();
    for (const release of releases) release();
    await guardian.close();
    fs.rmdirSync(dir);
  }
}, timeoutMs + 5000);
