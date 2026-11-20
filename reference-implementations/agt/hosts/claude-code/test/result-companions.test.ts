import { afterAll, afterEach, beforeAll, describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
// Test-only import, the precedent post-tool-use.test.ts and posture.test.ts set.
import { startGuardian, type StartedGuardian } from "guardian";

/**
 * Bash returns two text fields, `stdout` and `stderr`, and the model reads both.
 * The policy evaluates `stdout`. A withholding at the result gate has to replace
 * `stderr` as well, or a deny delivers whatever the command wrote there.
 *
 * Each test runs the real shim as a subprocess, the way Claude Code does, and
 * asserts on what the shim writes and how it exits.
 */
const SHIM_PATH = fileURLToPath(new URL("../acs-hook.ts", import.meta.url));
const MANIFEST = "policy/manifest.yaml";
const SESSION = "companions-1";
const SECRET = "ghp_ABCDEF123456";
const WITHHELD = "[OUTPUT WITHHELD BY POLICY]";

const dirs: string[] = [];
function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "acs-result-companions-"));
  dirs.push(dir);
  return dir;
}

/** Removes exactly what a run can leave behind, by name, never recursively. */
function cleanupScratch(dir: string): void {
  const sessionsDir = join(dir, "sessions");
  for (const file of [join(dir, "audit.jsonl"), join(sessionsDir, `${SESSION}.json`)]) {
    if (existsSync(file)) {
      unlinkSync(file);
    }
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

type ShimRun = { stdout: string; stderr: string; exitCode: number };

function payload(fields: Record<string, unknown>): Record<string, unknown> {
  return {
    session_id: SESSION,
    transcript_path: "/path/to/transcript.jsonl",
    cwd: "/current/dir",
    hook_event_name: "PostToolUse",
    tool_name: "Bash",
    tool_input: { command: "cat .env" },
    tool_response: toolResponse(fields),
  };
}

/** Bash's real `tool_response` shape, with the given fields overriding the empty defaults. */
function toolResponse(fields: Record<string, unknown>): Record<string, unknown> {
  return { stdout: "", stderr: "", interrupted: false, isImage: false, noOutputExpected: false, ...fields };
}

async function runShim(body: Record<string, unknown>, dir: string, guardianUrl: string): Promise<ShimRun> {
  const proc = Bun.spawn({
    cmd: ["bun", "run", SHIM_PATH],
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
    env: {
      ...process.env,
      ACS_GUARDIAN_URL: guardianUrl,
      ACS_SESSION_DIR: join(dir, "sessions"),
      ACS_AUDIT_LOG: join(dir, "audit.jsonl"),
    },
  });
  proc.stdin.write(JSON.stringify(body));
  proc.stdin.end();
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { stdout, stderr, exitCode };
}

function hookOutput(out: ShimRun): Record<string, unknown> {
  expect({ exitCode: out.exitCode, stderr: out.stderr }).toEqual({ exitCode: 0, stderr: "" });
  return JSON.parse(out.stdout).hookSpecificOutput as Record<string, unknown>;
}

function auditOf(dir: string): Record<string, unknown>[] {
  return readFileSync(join(dir, "audit.jsonl"), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
}

/** A stub Guardian that negotiates a session and answers the step call with `decision`. */
async function answering<T>(decision: Record<string, unknown>, body: (url: string) => Promise<T>): Promise<T> {
  const stub = Bun.serve({
    port: 0,
    async fetch(req) {
      const rpc = (await req.json()) as { id: string | number; method: string };
      if (rpc.method === "handshake/hello") {
        return Response.json({
          jsonrpc: "2.0",
          id: rpc.id,
          result: {
            negotiated_version: "0.1.0",
            methods_evaluated: ["steps/toolCallResult"],
            selected_transport: "http",
            timeout_config: { default_ms: 5000 },
            on_decision_failure: "proceed",
          },
        });
      }
      return Response.json({ jsonrpc: "2.0", id: rpc.id, result: decision });
    },
  });
  try {
    return await body(`http://localhost:${stub.port}/acs`);
  } finally {
    stub.stop(true);
  }
}

let guardian: StartedGuardian;

beforeAll(async () => {
  guardian = await startGuardian({ port: 0, manifestPath: MANIFEST });
});

afterAll(async () => {
  await guardian.close();
});

describe("the result gate withholds stderr with stdout", () => {
  it("on a policy deny, replaces both", async () => {
    const dir = scratch();
    const out = await answering({ decision: "deny", reasoning: "no" }, (url) =>
      runShim(payload({ stdout: `TOKEN=${SECRET}`, stderr: `warn ${SECRET}` }), dir, url),
    );

    expect(hookOutput(out).updatedToolOutput).toEqual(
      toolResponse({ stdout: WITHHELD, stderr: WITHHELD }),
    );
    expect(out.stdout).not.toContain(SECRET);
  });

  it("on a deny, leaves an empty stderr empty", async () => {
    const dir = scratch();
    const out = await answering({ decision: "deny", reasoning: "no" }, (url) =>
      runShim(payload({ stdout: `TOKEN=${SECRET}` }), dir, url),
    );

    expect(hookOutput(out).updatedToolOutput).toEqual(toolResponse({ stdout: WITHHELD }));
  });

  it("on a deny with nothing in stdout, still replaces a stderr that holds text", async () => {
    const dir = scratch();
    const out = await answering({ decision: "deny", reasoning: "no" }, (url) =>
      runShim(payload({ stdout: "", stderr: `fatal ${SECRET}` }), dir, url),
    );

    expect(hookOutput(out).updatedToolOutput).toEqual(toolResponse({ stdout: WITHHELD, stderr: WITHHELD }));
    expect(out.stdout).not.toContain(SECRET);
  });

  it("when the Guardian is gone under the deny posture, replaces both", async () => {
    const dir = scratch();
    const live = await startGuardian({ port: 0, manifestPath: MANIFEST, onDecisionFailure: "deny" });
    try {
      // Hook 1 negotiates while the Guardian is alive, with nothing to hide.
      await runShim(payload({ stdout: "ok" }), dir, live.url);
    } finally {
      await live.close();
    }

    const out = await runShim(payload({ stdout: `TOKEN=${SECRET}`, stderr: `warn ${SECRET}` }), dir, live.url);

    expect(hookOutput(out).updatedToolOutput).toEqual(toolResponse({ stdout: WITHHELD, stderr: WITHHELD }));
    expect(out.stdout).not.toContain(SECRET);
    expect(auditOf(dir)[0]).toMatchObject({ posture: "deny", outcome: "blocked" });
  });

  it("under the deny posture, withholds stderr from a result that carries no stdout", async () => {
    const dir = scratch();
    const live = await startGuardian({ port: 0, manifestPath: MANIFEST, onDecisionFailure: "deny" });
    try {
      await runShim(payload({ stdout: "ok" }), dir, live.url);
    } finally {
      await live.close();
    }

    const { stdout: _stdout, ...noStdout } = toolResponse({ stderr: `fatal ${SECRET}` });
    const out = await runShim({ ...payload({}), tool_response: noStdout }, dir, live.url);

    // Before, this was exit 2 with empty stdout, and Claude Code showed the
    // model the stderr text. Now the shim answers, and adds no field the tool
    // did not produce.
    const updated = hookOutput(out).updatedToolOutput as Record<string, unknown>;
    expect(updated.stderr).toBe(WITHHELD);
    expect("stdout" in updated).toBe(false);
    expect(out.stdout).not.toContain(SECRET);
    expect(auditOf(dir)[0]).toMatchObject({ posture: "deny", outcome: "blocked" });
  });
});

describe("the result gate leaves stderr alone when nothing is withheld", () => {
  it("on an allow", async () => {
    const dir = scratch();
    const out = await answering({ decision: "allow" }, (url) =>
      runShim(payload({ stdout: "fine", stderr: "a warning" }), dir, url),
    );

    expect("updatedToolOutput" in hookOutput(out)).toBe(false);
  });

  it("on a redaction, because the policy evaluates stdout alone", async () => {
    const dir = scratch();
    const out = await runShim(
      payload({ stdout: `TOKEN=${SECRET}`, stderr: "a warning" }),
      dir,
      guardian.url,
    );

    expect(hookOutput(out).updatedToolOutput).toEqual(
      toolResponse({ stdout: "TOKEN=[REDACTED]", stderr: "a warning" }),
    );
  });
});
