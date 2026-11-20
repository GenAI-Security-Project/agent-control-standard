/**
 * main.ts is the composition root, so it is the one place that reads the
 * proxy variables and applies the loopback exemption (Ariel's review on
 * PR #286). These tests run it as the operator does, as a process, because
 * the wiring under test is the entrypoint itself.
 */
import { afterEach, describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, rmdirSync, unlinkSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { toolCallEnvelope } from "./helpers/envelopes.ts";

const GUARDIAN = fileURLToPath(new URL("../src/main.ts", import.meta.url));
/** Absolute, because the process runs from a scratch cwd rather than from
 * the repo root, the same reason test/readme-captures.test.ts gives. */
const MANIFEST = fileURLToPath(new URL("../../../policy/manifest.yaml", import.meta.url));

const dirs: string[] = [];
function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "acs-main-"));
  dirs.push(dir);
  return dir;
}

/** What a run can leave in its scratch cwd: the `.acs/` directory the
 * Guardian makes at startup, and the two default logs once an envelope
 * arrives. Each is removed by name, never recursively, so rmdirSync fails
 * loudly on anything else. */
const LEFT_BEHIND = [".acs/envelopes.jsonl", ".acs/session-context.jsonl"];
afterEach(() => {
  for (const dir of dirs.splice(0)) {
    for (const file of LEFT_BEHIND) {
      if (existsSync(join(dir, file))) {
        unlinkSync(join(dir, file));
      }
    }
    const acs = join(dir, ".acs");
    if (existsSync(acs)) {
      rmdirSync(acs);
    }
    rmdirSync(dir);
  }
});

/** A port nothing listens on once this returns. No span is sent in these
 * tests, so the endpoint only has to be a well-formed loopback URL. */
async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as { port: number };
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

describe("main.ts applies the loopback proxy exemption", () => {
  it("warns on stderr at startup when a proxy is set and loopback is not exempt", async () => {
    const endpoint = `http://127.0.0.1:${await freePort()}/v1/traces`;
    // process.execPath, not "bun" off PATH, so the entrypoint runs on the
    // same Bun version as the suite. The environment is built up rather than
    // inherited, so a NO_PROXY in the developer's shell cannot hide the
    // warning. `timeout` is the runtime's own watchdog, shorter than bun
    // test's five-second cap, so a missing warning fails on the assertion.
    const proc = Bun.spawn([process.execPath, GUARDIAN], {
      cwd: scratch(),
      env: {
        PATH: process.env.PATH ?? "",
        HOME: process.env.HOME ?? "",
        NO_COLOR: "1",
        ACS_GUARDIAN_PORT: "0",
        ACS_MANIFEST_PATH: MANIFEST,
        ACS_OTEL_ENDPOINT: endpoint,
        HTTP_PROXY: "http://127.0.0.1:9/",
      },
      stdout: "ignore",
      stderr: "pipe",
      timeout: 3_000,
    });
    const decoder = new TextDecoder();
    let stderr = "";
    for await (const chunk of proc.stderr) {
      stderr += decoder.decode(chunk, { stream: true });
      if (stderr.includes("did not exempt 127.0.0.1")) {
        proc.kill();
      }
    }
    proc.kill();
    await proc.exited;
    expect(stderr).toContain(
      `otel trace export to ${endpoint}: an HTTP proxy is set and NO_PROXY/no_proxy did not exempt 127.0.0.1, ` +
        "so on some Bun versions these spans go through the proxy. Start the Guardian with 127.0.0.1 in both NO_PROXY and no_proxy.",
    );
  });

  // The warning above proves main.ts reads the variables. This proves it
  // edits them: spans reach the collector and not the proxy. Gated to Bun
  // 1.3.14 and later, because 1.3.11 reads the proxy variables only at
  // startup and ignores the edit.
  it.skipIf(!Bun.semver.satisfies(Bun.version, ">=1.3.14"))(
    "sends spans to a loopback collector directly when NO_PROXY holds only the user's own entries",
    async () => {
      // A proxy that only counts connections and never answers.
      let proxyConnections = 0;
      const proxy = createServer((socket) => {
        proxyConnections += 1;
        socket.destroy();
      });
      await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
      const proxyUrl = `http://127.0.0.1:${(proxy.address() as { port: number }).port}`;
      let exports = 0;
      const collector = Bun.serve({
        port: 0,
        hostname: "127.0.0.1",
        fetch() {
          exports += 1;
          return new Response("{}", { headers: { "content-type": "application/json" } });
        },
      });
      // Async spawn, not spawnSync: the proxy and the collector run on this
      // process's event loop and could not answer the child while blocked.
      // `timeout` kills a Guardian that never exits, so the test fails on
      // the assertions rather than hanging.
      const proc = Bun.spawn([process.execPath, GUARDIAN], {
        cwd: scratch(),
        env: {
          PATH: process.env.PATH ?? "",
          HOME: process.env.HOME ?? "",
          NO_COLOR: "1",
          ACS_GUARDIAN_PORT: "0",
          ACS_MANIFEST_PATH: MANIFEST,
          ACS_OTEL_ENDPOINT: `http://127.0.0.1:${collector.port}/v1/traces`,
          HTTP_PROXY: proxyUrl,
          http_proxy: proxyUrl,
          // A user's own exemption, which the edit must keep. no_proxy is
          // left unset, so the edit goes to NO_PROXY alone.
          NO_PROXY: "corp.internal",
        },
        stdout: "pipe",
        stderr: "ignore",
        timeout: 12_000,
      });
      try {
        // main.ts prints "OTel traces:" in the same turn that installs its
        // SIGTERM handler, so once that line is in, a SIGTERM flushes.
        const reader = proc.stdout.getReader();
        const decoder = new TextDecoder();
        let stdout = "";
        while (!stdout.includes("OTel traces:")) {
          const { value, done } = await reader.read();
          if (done) {
            break;
          }
          stdout += decoder.decode(value, { stream: true });
        }
        reader.releaseLock();
        const url = /Guardian listening at (\S+)/.exec(stdout)?.[1];
        expect(url).toBeDefined();
        const response = await fetch(url!, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(toolCallEnvelope("ls -la")),
        });
        expect(response.ok).toBe(true);
        await response.json();
        proc.kill("SIGTERM");
        await proc.exited;
        expect({ proxyConnections, exportsReceived: exports > 0 }).toEqual({ proxyConnections: 0, exportsReceived: true });
      } finally {
        proc.kill();
        await proc.exited;
        collector.stop(true);
        proxy.close();
      }
    },
    15_000,
  );
});

// Issue #283: plain http to a host that is not loopback needs an explicit
// opt-in, and main.ts is the one place that reads it. No step is posted in
// these tests, so the Guardian has no span to send and nothing reaches
// 10.0.0.1.
describe("main.ts reads the plain http opt-in", () => {
  const ENDPOINT = "http://10.0.0.1:4318/v1/traces";

  /** Starts the Guardian against ENDPOINT and returns its stderr, read until
   * `expected` shows up or the runtime's watchdog ends the process. */
  async function stderrUntil(expected: string, env: Record<string, string>): Promise<string> {
    const proc = Bun.spawn([process.execPath, GUARDIAN], {
      cwd: scratch(),
      env: {
        PATH: process.env.PATH ?? "",
        HOME: process.env.HOME ?? "",
        NO_COLOR: "1",
        ACS_GUARDIAN_PORT: "0",
        ACS_MANIFEST_PATH: MANIFEST,
        ACS_OTEL_ENDPOINT: ENDPOINT,
        ...env,
      },
      stdout: "ignore",
      stderr: "pipe",
      timeout: 3_000,
    });
    const decoder = new TextDecoder();
    let stderr = "";
    for await (const chunk of proc.stderr) {
      stderr += decoder.decode(chunk, { stream: true });
      if (stderr.includes(expected)) {
        proc.kill();
      }
    }
    proc.kill();
    await proc.exited;
    return stderr;
  }

  it("refuses the endpoint on stderr when ACS_OTEL_ALLOW_PLAINTEXT_ENDPOINT is unset", async () => {
    const refused =
      `otel trace export to ${ENDPOINT} disabled after failure: refusing plain http to 10.0.0.1, which is not a loopback host: ` +
      "spans would cross the network unencrypted. Use an https endpoint, or set ACS_OTEL_ALLOW_PLAINTEXT_ENDPOINT=1 to send them anyway.";
    expect(await stderrUntil(refused, {})).toContain(refused);
  });

  it("warns on stderr instead when ACS_OTEL_ALLOW_PLAINTEXT_ENDPOINT is 1", async () => {
    const warning =
      `otel trace export to ${ENDPOINT}: ACS_OTEL_ALLOW_PLAINTEXT_ENDPOINT=1 is set, so spans go to 10.0.0.1 over plain http, unencrypted. ` +
      "Use an https endpoint unless every hop to that host is trusted.";
    const stderr = await stderrUntil(warning, { ACS_OTEL_ALLOW_PLAINTEXT_ENDPOINT: "1" });
    expect(stderr).toContain(warning);
    expect(stderr).not.toContain("refusing plain http");
  });

  it("takes only the value 1 as the opt-in", async () => {
    expect(await stderrUntil("refusing plain http to 10.0.0.1", { ACS_OTEL_ALLOW_PLAINTEXT_ENDPOINT: "true" })).toContain(
      "refusing plain http to 10.0.0.1, which is not a loopback host",
    );
  });
});
