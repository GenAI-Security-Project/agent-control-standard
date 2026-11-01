import { describe, expect, it } from "bun:test";
import { mkdtempSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createBridge } from "../src/index.ts";
import { publishOpaPath } from "../src/opa-path.ts";

/**
 * The claim opa-path.ts makes, tested from the outside: a bridge built in a
 * process whose real environment names no `opa` anywhere still evaluates
 * policy. That is exactly the process CI is -- a fresh runner with the
 * repository's own dependencies and nothing else -- and it was the process
 * in which every evaluation denied on runtime_error:policy_invocation_failed
 * before this file's subject existed.
 *
 * A child process rather than this one, because this one cannot be made to
 * forget: by the time any test here runs, another suite may already have
 * published the binary into this process's environment, and an assertion
 * made here would be measuring that rather than the fresh case. `Bun.spawn`
 * with an explicit `env` hands the child exactly that environment and
 * nothing inherited -- so PATH is one empty directory, there is no
 * ACS_OPA_PATH, and the only way the child can reach opa is the one under
 * test.
 */
const REPO_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const BRIDGE_INDEX = fileURLToPath(new URL("../src/index.ts", import.meta.url));
const MANIFEST = join(REPO_ROOT, "policy", "manifest.yaml");

const SNAPSHOT = {
  envelope: { budgets: { tool_call_count: 0, token_count: 0, elapsed_seconds: 0, cost_usd: 0 } },
  tool_call: { name: "run_shell", args: { command: "ls -la", acs_policy_target: "ls -la" }, raw_command: "ls -la", id: "t1" },
  input: { ifc: { source_labels: ["public"] } },
};

describe("publishOpaPath -- the opa AGT's native core spawns, made reachable from a Bun process", () => {
  it("a bridge built in a process whose environment names no opa at all still evaluates policy", () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-opa-path-"));
    const emptyPath = join(dir, "empty-path");
    const script = join(dir, "evaluate.ts");
    try {
      // `mkdtempSync` again rather than `mkdirSync`, so the directory on
      // PATH is one nothing else could have populated.
      const onlyDirOnPath = mkdtempSync(emptyPath);
      writeFileSync(
        script,
        [
          `import { createBridge } from ${JSON.stringify(BRIDGE_INDEX)};`,
          `const bridge = createBridge(${JSON.stringify(MANIFEST)}, { annotator: () => ({}) });`,
          `const verdict = await bridge.evaluate("pre_tool_call", ${JSON.stringify(SNAPSHOT)});`,
          `console.log(JSON.stringify(verdict));`,
          "",
        ].join("\n"),
      );

      const child = Bun.spawnSync([process.execPath, "run", script], {
        cwd: REPO_ROOT,
        // Exactly this, nothing inherited. HOME is the one thing Bun itself
        // wants at startup; PATH holds a directory with nothing in it.
        env: { PATH: onlyDirOnPath, HOME: process.env.HOME ?? dir },
        stdout: "pipe",
        stderr: "pipe",
      });

      const stderr = child.stderr.toString();
      expect({ exitCode: child.exitCode, stderr }).toEqual({ exitCode: 0, stderr: "" });
      // The decision AND the absence of the runtime error: the fixture is a
      // benign command under the shipped manifest, so anything but a clean
      // allow means a rule never ran.
      expect(JSON.parse(child.stdout.toString())).toMatchObject({ decision: "allow" });

      rmdirSync(onlyDirOnPath);
    } finally {
      try {
        unlinkSync(script);
      } catch {
        // Never written: the failure above already names why.
      }
      rmdirSync(dir);
    }
  });

  // Linux and macOS can reach the Windows branch only with a stubbed platform.
  // The stub shows the branch's own logic: the path lands in `process.env` and
  // the C library is never touched. It shows nothing about Windows itself.
  it.skipIf(process.platform === "win32")("on win32 publishes through process.env and leaves the C library alone", async () => {
    const opa = publishOpaPath();
    const source = fileURLToPath(new URL("../src/opa-path.ts", import.meta.url));
    const script = `
      import { dlopen, FFIType } from "bun:ffi";
      Object.defineProperty(process, "platform", { value: "win32" });
      const { publishOpaPath } = await import(${JSON.stringify(source)});
      const returned = publishOpaPath();
      const js = process.env.ACS_OPA_PATH;
      let real = "";
      for (const name of ["libc.so.6", "libSystem.B.dylib"]) {
        try {
          const lib = dlopen(name, { getenv: { args: [FFIType.cstring], returns: FFIType.cstring } });
          real = lib.symbols.getenv(Buffer.from("ACS_OPA_PATH\\0"))?.toString() ?? "";
          break;
        } catch {}
      }
      console.log(JSON.stringify({ returned, js, real }));
    `;
    // A directory hint, so the real environment and `process.env` both hold
    // something other than the resolved file until a write reaches them.
    const hint = opa.slice(0, opa.lastIndexOf("/"));
    // The stubbed platform names a bundled opa package this machine does not
    // have, so a digest stands in for any comparison with the bundled binary.
    const digest = new Bun.CryptoHasher("sha256").update(await Bun.file(opa).arrayBuffer()).digest("hex");
    const child = Bun.spawnSync([process.execPath, "--no-install", "-e", script], {
      env: { PATH: "/nonexistent", ACS_OPA_PATH: hint, ACS_OPA_SHA256: digest },
      stdout: "pipe",
      stderr: "pipe",
    });
    expect({ exitCode: child.exitCode, stderr: child.stderr.toString() }).toEqual({ exitCode: 0, stderr: "" });
    expect(JSON.parse(child.stdout.toString())).toEqual({ returned: opa, js: opa, real: hint });
  });

  it("answers the path of an opa that actually runs", () => {
    const opa = publishOpaPath();
    const child = Bun.spawnSync([opa, "version"], { stdout: "pipe", stderr: "pipe" });
    expect({ exitCode: child.exitCode, stdout: child.stdout.toString() }).toMatchObject({
      exitCode: 0,
      stdout: expect.stringContaining("Version:"),
    });
  });

  /**
   * The fail-loud half. An explicit hint that names nothing must stop
   * construction, not produce a bridge that denies everything with a
   * policy-shaped reason -- that is the failure this file's subject exists
   * to make impossible, and the SDK's own contract ("a bad explicit path
   * fails closed instead of falling back to another opa on PATH") is the
   * one being relied on. Restored in `finally` so the suites after this one
   * see the environment they expect.
   */
  it("refuses to build a bridge when an explicit ACS_OPA_PATH names nothing, rather than one that denies every step", () => {
    const before = process.env.ACS_OPA_PATH;
    process.env.ACS_OPA_PATH = join(tmpdir(), "acs-opa-path-no-such-binary");
    try {
      expect(() => createBridge(MANIFEST, { annotator: () => ({}) })).toThrow(/opa not found at the path provided/);
    } finally {
      if (before === undefined) delete process.env.ACS_OPA_PATH;
      else process.env.ACS_OPA_PATH = before;
    }
  });
});
