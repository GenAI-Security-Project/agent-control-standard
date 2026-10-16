/**
 * main.ts is the composition root, so it is the one place that reads the
 * proxy variables and applies the loopback exemption (Ariel's review on
 * PR #286). These tests run it as the operator does, as a process, because
 * the wiring under test is the entrypoint itself.
 */
import { afterEach, describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, rmdirSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

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

/** The Guardian mkdirs `.acs/` at startup and writes nothing into it until
 * an envelope arrives. Nothing posts here, so an empty `.acs/` is the only
 * thing a run can leave, and rmdirSync fails loudly on anything else. */
afterEach(() => {
  for (const dir of dirs.splice(0)) {
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
});
