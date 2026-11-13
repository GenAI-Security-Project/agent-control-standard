import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
// Test-only import: stands up a real Guardian so this test proves the wire
// contract for real, not against a hand-copied shape -- same precedent as
// packages/host-adapter/test/client.test.ts. `host-adapter` here
// is used the same way the shim itself uses it, so this test also proves
// what a subprocess sees is what the adapter would have produced directly.
import { startGuardian, type StartedGuardian } from "guardian";
import {
  buildEnvelope,
  createGuardianClient,
  createMemorySessionConfigStore,
  DEFAULT_TIMEOUT_MS,
  governStep,
  loadHookmap,
  NULL_AUDIT_SINK,
  renderDecision,
  resolveSessionConfig,
  toSessionUuid,
  type Hookmap,
} from "host-adapter";

const SHIM_PATH = fileURLToPath(new URL("../acs-hook.ts", import.meta.url));
const HOOKMAP_PATH = fileURLToPath(new URL("../claude-code.hookmap.yaml", import.meta.url));

// The shim negotiates a session, persisting it to the session config store,
// and can audit a fail-open to the audit log; both default to `.acs/...`
// under the process cwd when unset -- which would otherwise scatter real
// files into the repo's working tree on every run of this suite. Every test
// below shares one session id ("abc123"), so the only path any of them can
// create is `sessions/abc123.json` under this scratch dir; no audit file is
// expected, since every test exercises a decision that actually arrives.
const SCRATCH_DIR = mkdtempSync(join(tmpdir(), "acs-hook-test-"));
const SESSION_DIR = join(SCRATCH_DIR, "sessions");
const AUDIT_LOG = join(SCRATCH_DIR, "audit.jsonl");

/** The real PreToolUse payload shape Claude Code delivers on stdin, with
 * `tool_name: "Bash"` -- what Claude Code actually sends, and what
 * `policy/manifest.yaml` registers. */
function preToolUsePayload(command: string): Record<string, unknown> {
  return {
    session_id: "abc123",
    transcript_path: "/path/to/transcript.jsonl",
    cwd: "/current/dir",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command },
  };
}

/** The real PostToolUse payload shape Claude Code 2.1.227 delivers, captured
 * from a live run: `tool_response` is a structured object and `stdout` is
 * the leaf the shipped hookmap puts on the wire. */
function postToolUsePayload(stdout: string): Record<string, unknown> {
  return {
    session_id: "abc123",
    transcript_path: "/path/to/transcript.jsonl",
    cwd: "/current/dir",
    hook_event_name: "PostToolUse",
    tool_name: "Bash",
    tool_input: { command: "ls -la" },
    tool_response: { stdout, stderr: "", interrupted: false, isImage: false, noOutputExpected: false },
  };
}

/** Spawns the real shim as a subprocess -- exactly how Claude Code invokes
 * it -- feeds it `payload` on stdin, and returns what it wrote once it has
 * run to completion. */
async function runHook(
  payload: Record<string, unknown>,
  guardianUrl: string,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const proc = Bun.spawn({
    cmd: ["bun", "run", SHIM_PATH],
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, ACS_GUARDIAN_URL: guardianUrl, ACS_SESSION_DIR: SESSION_DIR, ACS_AUDIT_LOG: AUDIT_LOG },
  });
  proc.stdin.write(JSON.stringify(payload));
  proc.stdin.end();
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { stdout, stderr, exitCode };
}

let guardian: StartedGuardian;

beforeAll(async () => {
  guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
});

afterAll(async () => {
  await guardian.close();
  // Named cleanup, not recursive: the only path any test above can create is
  // enumerated in the SCRATCH_DIR comment. Removing anything
  // unexpected is not this cleanup's job -- an unknown leftover should fail
  // `rmdirSync` loudly rather than be swept away silently.
  const sessionFile = join(SESSION_DIR, "abc123.json");
  if (existsSync(sessionFile)) {
    unlinkSync(sessionFile);
  }
  if (existsSync(SESSION_DIR)) {
    rmdirSync(SESSION_DIR);
  }
  if (existsSync(AUDIT_LOG)) {
    unlinkSync(AUDIT_LOG);
  }
  rmdirSync(SCRATCH_DIR);
});

describe("acs-hook.ts -- the Claude Code hook shim, run as a real subprocess", () => {
  it("denies a real rm -rf / tool call: exit 0, clean JSON on stdout, and the policy's own reasoning in permissionDecisionReason", async () => {
    const payload = preToolUsePayload("rm -rf /");

    const { stdout, stderr, exitCode } = await runHook(payload, guardian.url);

    expect(exitCode).toBe(0);
    expect(() => JSON.parse(stdout)).not.toThrow();
    const parsed = JSON.parse(stdout) as { hookSpecificOutput: Record<string, unknown> };

    expect(parsed.hookSpecificOutput.hookEventName).toBe("PreToolUse");
    expect(parsed.hookSpecificOutput.permissionDecision).toBe("deny");
    const reason = parsed.hookSpecificOutput.permissionDecisionReason;
    expect(typeof reason).toBe("string");
    expect((reason as string).length).toBeGreaterThan(0);

    // Cross-check against the real Guardian's own decision for the
    // identical tool call, obtained independently of the subprocess (the
    // exact composition the shim itself performs, called directly rather
    // than through stdin/stdout) -- proves the shim relays the policy's
    // actual text rather than a hardcoded placeholder, which a suite that
    // only checked "reason is a non-empty string" would miss. This is the
    // demo's entire payoff: what a human reads in the transcript.
    const hookmap: Hookmap = loadHookmap(HOOKMAP_PATH);
    const envelope = buildEnvelope("PreToolUse", payload, hookmap);
    const response = await createGuardianClient(guardian.url).post(envelope);
    expect(response.error).toBeUndefined();
    const expected = renderDecision(
      "PreToolUse",
      response.result as { decision: string } & Record<string, unknown>,
      hookmap,
    ) as { hookSpecificOutput: Record<string, unknown> };

    expect(reason).toBe(expected.hookSpecificOutput.permissionDecisionReason);
    expect(stderr).toBe("");
  });

  it("allows a real ls -la tool call: exit 0, and clean JSON on stdout with a plain allow", async () => {
    const payload = preToolUsePayload("ls -la");

    const { stdout, stderr, exitCode } = await runHook(payload, guardian.url);

    expect(exitCode).toBe(0);
    expect(() => JSON.parse(stdout)).not.toThrow();
    const parsed = JSON.parse(stdout) as { hookSpecificOutput: Record<string, unknown> };

    expect(parsed.hookSpecificOutput).toEqual({
      hookEventName: "PreToolUse",
      permissionDecision: "allow",
    });
    expect(stderr).toBe("");
  });

  // This wrapper refusal is hook-aware. At PreToolUse an output Claude Code
  // reads no decision from lets the tool call proceed, so this shim refuses
  // to write one -- and that same refusal, applied to the result gate, would
  // exit 2 on every clean tool call. The tool has already run here:
  // "nothing to change, deliver it as the tool produced it" is the honest
  // answer, and it is what a clean allow renders, because the only field
  // PostToolUse's `allow` declares is conditional on a `reasoning` a genuine
  // allow does not carry.
  //
  // Through the real shim and the real Guardian rather than a stub, because the
  // claim is about the bytes a Claude Code process reads back for a clean
  // result, and the empty wrapper is exactly the shape that looks like a bug.
  it("answers a clean tool result with an empty wrapper: exit 0, nothing to change, delivered unchanged", async () => {
    const { stdout, stderr, exitCode } = await runHook(postToolUsePayload("total 0\n"), guardian.url);

    expect({ exitCode, stderr }).toEqual({ exitCode: 0, stderr: "" });
    // The whole object, as a literal: no permissionDecision (there is no
    // permission to grant once the step has run), no `decision: block`, and no
    // replacement -- an empty wrapper and nothing else.
    expect(JSON.parse(stdout)).toEqual({ hookSpecificOutput: { hookEventName: "PostToolUse" } });
  });
});

/**
 * `governStep` accepts an optional `scopedTool` -- the tool a caller has
 * already scoped on. When a gate's hookmap entry declares a `tools` list,
 * governStep refuses a caller that names none. This shim declares no
 * `tools` at either gate (each has its own settings.json matcher already
 * scoping it -- `^(Bash|WebFetch)$` at the request gate, `^Bash$` at the
 * result gate) and passes no `scopedTool`. `scripts/verify-zero-diff.sh`
 * pinned `hosts/claude-code/*.ts` and `*.yaml`, which is why this comment
 * used to say the shim's one `governStep` call could not be updated even if
 * the field became required.
 *
 * That is past tense now. The script diffs against `slice/v4`, this host's
 * hookmap has since changed under the frozen pattern, `bun run
 * verify:zero-diff` exits 1 from this HEAD naming it, and no workflow runs
 * the script. So it proved the file unchanged at the commit it was written
 * against and proves nothing from here -- and it never could prove the call
 * still works, which was always this suite's job: the two subprocess tests
 * above prove that end to end for the request gate. Pinned
 * separately, and at the adapter seam rather than through stdin/stdout,
 * because the property is specifically that an untold scope is a complete
 * call at both gates: a refusal that fired on an absent `tools` key rather
 * than a declared one would break this host everywhere at once, and the
 * failure that reported it should name the field rather than an exit code.
 *
 * Tested against the shipped hookmap, not a fixture, because the thing
 * under test is that this deployment's own entries declare no list.
 */
describe("this shim tells governStep no scoped tool, and that is a complete call at both gates", () => {
  const SESSION_ID = "abc123";

  it.each([
    ["PreToolUse", () => preToolUsePayload("ls -la")],
    ["PostToolUse", () => postToolUsePayload("total 0\n")],
  ] as const)("governs a %s step with no scopedTool passed", async (hookEventName, buildPayload) => {
    const hookmap: Hookmap = loadHookmap(HOOKMAP_PATH);

    // Why untold is legal here, stated as an assertion rather than as a
    // comment: this entry declares no `tools`, so there is no list for a
    // caller to be scoped against and nothing for it to tell. If a future
    // edit adds one, this row fails before the call below does, and it names
    // the reason.
    expect(hookmap.hooks[hookEventName]?.tools).toBeUndefined();

    const guardianClient = createGuardianClient(guardian.url);
    const session = await resolveSessionConfig(
      {
        guardian: guardianClient,
        agentId: hookmap.host,
        sessionId: toSessionUuid(SESSION_ID),
        timeoutMs: DEFAULT_TIMEOUT_MS,
      },
      createMemorySessionConfigStore(),
    );

    // Exactly acs-hook.ts's own call: every field it passes, and no
    // `scopedTool`.
    const governed = await governStep({
      hookEventName,
      payload: buildPayload(),
      hookmap,
      guardian: guardianClient,
      session,
      sessionId: SESSION_ID,
      audit: NULL_AUDIT_SINK,
    });

    // Governed by a decision that really arrived -- not refused, and not
    // skipped as a tool this gate does not govern.
    expect(governed.stage).toBe("honoured");
  });
});
