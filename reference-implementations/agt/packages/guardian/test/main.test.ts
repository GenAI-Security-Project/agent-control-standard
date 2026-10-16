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
