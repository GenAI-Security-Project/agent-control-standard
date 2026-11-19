/**
 * The shipped `settings.json` is what Claude Code reads, and the shim never
 * gets a vote when that file's command fails before `main`.
 *
 * Claude Code's hooks reference (https://code.claude.com/docs/en/hooks),
 * under "Exit code output" and "Block the action when a hook fails": on most
 * events a command hook that cannot start, exits with a code other than 0 or
 * 2, prints JSON that does not parse, or times out does not block the action
 * unless the hook sets `onFailure` to `"block"`. The field requires Claude
 * Code v2.1.295 or later. Unset, the tool call proceeds. Exit 2 blocks on
 * its own; this file is about every failure that is not exit 2.
 *
 * `bun run` on a missing file exits 1. Measured here on Bun 1.3.11, the
 * version `.github/workflows/reference-implementation.yml` installs, and
 * reported for Bun 1.3.14 in issue #376. Exit 1 is the non-blocking code.
 * Nothing in the command string turns it into 0. The shim's `main().catch`
 * exits 2, and that path is unreachable when bun cannot load the file, bun
 * is not on `PATH`, or the script throws while loading. The negotiated
 * `on_decision_failure` posture never runs either.
 *
 * `preToolUseToolCall` is that reference's rule for this one event, not a
 * second policy. Each failure below is a real `sh -c` of the shipped
 * command. Shell form is how Claude Code runs a command hook that sets no
 * `args`. The assertion is that the shipped `onFailure` denies the tool
 * call. The same run with the field removed proceeds, which is the fail-open
 * this file used to ship, so a classifier that denied every run would fail
 * that half rather than pass as a fix.
 *
 * `PostToolUse` is asserted unset. Exit 2 there shows stderr to Claude, and
 * the tool has already run, so `onFailure` cannot withhold the output and
 * does not replace the result gate.
 */
import { afterEach, describe, expect, it } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const SETTINGS_PATH = fileURLToPath(new URL("../settings.json", import.meta.url));

type CommandHook = { type: "command"; command: string; onFailure?: string };

type CompletedRun = { kind: "completed"; exitCode: number; stdout: string };

type HookRun = CompletedRun | { kind: "timeout" };

type ToolCall = "denied" | "proceeds";

type StdoutClass = "valid-object" | "invalid-json" | "plain";

const PERMISSION_DECISIONS = ["allow", "deny", "ask", "defer"] as const;
type PermissionDecision = (typeof PERMISSION_DECISIONS)[number];

const dirs: string[] = [];

function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "acs-hook-failure-"));
  dirs.push(dir);
  return dir;
}

/** The only file a case here writes is `hosts/claude-code/acs-hook.ts`.
 * Removed by name, never recursively, so a stray file fails `rmdirSync`
 * instead of disappearing. The missing-script case creates none of these. */
function cleanup(dir: string): void {
  const hookDir = join(dir, "hosts", "claude-code");
  const hostsDir = join(dir, "hosts");
  const file = join(hookDir, "acs-hook.ts");
  if (existsSync(file)) unlinkSync(file);
  if (existsSync(hookDir)) rmdirSync(hookDir);
  if (existsSync(hostsDir)) rmdirSync(hostsDir);
  rmdirSync(dir);
}

afterEach(() => {
  while (dirs.length > 0) {
    cleanup(dirs.pop() as string);
  }
});

function commandHooks(event: string): CommandHook[] {
  const settings = JSON.parse(readFileSync(SETTINGS_PATH, "utf8")) as {
    hooks?: Record<string, Array<{ hooks?: Array<Record<string, unknown>> }> | undefined>;
  };
  const found: CommandHook[] = [];
  for (const group of settings.hooks?.[event] ?? []) {
    for (const hook of group.hooks ?? []) {
      if (hook.type !== "command" || typeof hook.command !== "string") continue;
      if (hook.onFailure !== undefined && typeof hook.onFailure !== "string") {
        throw new Error(`${event} command hook onFailure is ${JSON.stringify(hook.onFailure)}`);
      }
      found.push({
        type: "command",
        command: hook.command,
        ...(typeof hook.onFailure === "string" ? { onFailure: hook.onFailure } : {}),
      });
    }
  }
  return found;
}

function shippedPreToolUse(): CommandHook {
  const hooks = commandHooks("PreToolUse");
  expect(hooks).toHaveLength(1);
  const hook = hooks[0];
  if (hook === undefined) {
    throw new Error("settings.json registers no PreToolUse command hook");
  }
  expect(hook.onFailure).toBe("block");
  return hook;
}

/**
 * Claude Code's single-object stdout rule. Plain text, including output that
 * starts with `{` but does not end with `}`, is not a failure. Output that
 * starts with `{`, ends with `}`, and is not a JSON object is a parse
 * failure, which is a failure. The multi-line rule in the reference does not
 * apply to the one-object runs this file produces.
 */
function classifyStdout(stdout: string): StdoutClass {
  const trimmed = stdout.trim();
  if (trimmed === "" || !trimmed.startsWith("{") || !trimmed.endsWith("}")) {
    return "plain";
  }
  try {
    const value: unknown = JSON.parse(trimmed);
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      return "valid-object";
    }
    return "invalid-json";
  } catch {
    return "invalid-json";
  }
}

function honouredDecision(stdout: string): PermissionDecision | undefined {
  const value: unknown = JSON.parse(stdout.trim());
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const wrapper = (value as Record<string, unknown>).hookSpecificOutput;
  if (typeof wrapper !== "object" || wrapper === null || Array.isArray(wrapper)) return undefined;
  const decision = (wrapper as Record<string, unknown>).permissionDecision;
  return PERMISSION_DECISIONS.find((candidate) => candidate === decision);
}

/**
 * Whether the tool call runs, for one PreToolUse command hook.
 *
 * A failure denies the call only when `onFailure` is `"block"`. That failure
 * is: the hook did not start, it timed out, it exited with a code other than
 * 0 or 2 (even if stdout is a JSON allow), or stdout is JSON that does not
 * parse. Exit 0 with plain text or with a JSON object is a success, and the
 * object decides. Exit 2 denies the call either way, and a JSON allow cannot
 * override it.
 */
function preToolUseToolCall(onFailure: string | undefined, run: HookRun): ToolCall {
  const blocksOnFailure = onFailure === "block";
  if (run.kind === "timeout") {
    return blocksOnFailure ? "denied" : "proceeds";
  }
  if (run.exitCode === 2) {
    return "denied";
  }

  const stdoutClass = classifyStdout(run.stdout);
  // Exit 0 with plain text, or with a JSON object, is a success. The object
  // decides. Unparseable JSON on exit 0 is a failure, handled below.
  if (run.exitCode === 0 && stdoutClass !== "invalid-json") {
    if (stdoutClass === "valid-object" && honouredDecision(run.stdout) === "deny") {
      return "denied";
    }
    return "proceeds";
  }
  // Any other exit code ignores a JSON allow when the hook blocks on
  // failure, and honours that JSON when it does not. A deny in the JSON
  // still denies.
  if (stdoutClass === "valid-object" && !blocksOnFailure) {
    return honouredDecision(run.stdout) === "deny" ? "denied" : "proceeds";
  }
  return blocksOnFailure ? "denied" : "proceeds";
}

function assertFailClosed(run: HookRun): void {
  const hook = shippedPreToolUse();
  expect(preToolUseToolCall(hook.onFailure, run)).toBe("denied");
  // The same outcome with the field absent, which is how this file shipped.
  // Claude Code then carries out the tool call.
  expect(preToolUseToolCall(undefined, run)).toBe("proceeds");
}

/** Shell form, the way Claude Code runs the shipped command: no `args`. */
async function runShippedCommand(
  env: Record<string, string>,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(["sh", "-c", shippedPreToolUse().command], {
    env: { ...process.env, ...env },
    stdin: new TextEncoder().encode(""),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { stdout, stderr, exitCode };
}

function writeStandIn(dir: string, source: string): void {
  const hookDir = join(dir, "hosts", "claude-code");
  mkdirSync(hookDir, { recursive: true });
  writeFileSync(join(hookDir, "acs-hook.ts"), source);
}

describe("shipped PreToolUse settings: a failure of the hook itself denies the tool call", () => {
  it("denies when bun cannot find the script", async () => {
    const project = scratch();
    const run = await runShippedCommand({ CLAUDE_PROJECT_DIR: project });

    // Empty stdout, exit 1. A non-blocking error when onFailure is unset.
    expect(run.exitCode).toBe(1);
    expect(run.stdout).toBe("");
    expect(run.stderr).toContain("Module not found");
    assertFailClosed({ kind: "completed", exitCode: run.exitCode, stdout: run.stdout });
  });

  it("denies when bun itself is missing", async () => {
    const project = scratch();
    const run = await runShippedCommand({ CLAUDE_PROJECT_DIR: project, PATH: "/usr/bin:/bin" });

    expect(run.exitCode).toBe(127);
    expect(run.stdout).toBe("");
    expect(run.stderr).toContain("not found");
    assertFailClosed({ kind: "completed", exitCode: run.exitCode, stdout: run.stdout });
  });

  it("denies when the script crashes before the shim can exit 2", async () => {
    const project = scratch();
    writeStandIn(project, 'throw new Error("acs-hook crashed before main");\n');
    const run = await runShippedCommand({ CLAUDE_PROJECT_DIR: project });

    expect(run.exitCode).toBe(1);
    expect(run.stdout).toBe("");
    expect(run.stderr).toContain("acs-hook crashed before main");
    assertFailClosed({ kind: "completed", exitCode: run.exitCode, stdout: run.stdout });
  });

  it("denies when stdout is JSON Claude Code cannot parse", async () => {
    const project = scratch();
    // Starts with `{` and ends with `}`, so Claude Code tries to parse it.
    // It is not JSON. Exit 0 with that stdout is a non-blocking error unless
    // onFailure blocks. `{not json` would be plain text, and plain text on
    // exit 0 is a success.
    writeStandIn(project, 'process.stdout.write(\'{"hookSpecificOutput":}\');\nprocess.exit(0);\n');
    const run = await runShippedCommand({ CLAUDE_PROJECT_DIR: project });

    expect(run.exitCode).toBe(0);
    expect(run.stdout).toBe('{"hookSpecificOutput":}');
    expect(classifyStdout(run.stdout)).toBe("invalid-json");
    assertFailClosed({ kind: "completed", exitCode: run.exitCode, stdout: run.stdout });
  });

  it("denies an unexpected exit even when stdout carries an allow", async () => {
    const project = scratch();
    writeStandIn(
      project,
      'process.stdout.write(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"allow"}}));\nprocess.exit(1);\n',
    );
    const run = await runShippedCommand({ CLAUDE_PROJECT_DIR: project });

    expect(run.exitCode).toBe(1);
    expect(classifyStdout(run.stdout)).toBe("valid-object");
    expect(honouredDecision(run.stdout)).toBe("allow");
    assertFailClosed({ kind: "completed", exitCode: run.exitCode, stdout: run.stdout });
  });

  it("denies a timeout", () => {
    // The default command-hook timeout is 600 seconds, and Claude Code
    // discards the hook's output when it fires. This classifies that
    // outcome instead of waiting one out. The reference lists a timeout as
    // a failure, and a PreToolUse timeout does not block the tool call
    // unless the hook's failure blocks the action.
    assertFailClosed({ kind: "timeout" });
  });

  it("does not deny a clean exit 0 whose JSON allows the tool", async () => {
    const project = scratch();
    writeStandIn(
      project,
      'process.stdout.write(JSON.stringify({hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"allow"}}));\n',
    );
    const run = await runShippedCommand({ CLAUDE_PROJECT_DIR: project });
    const completed: CompletedRun = { kind: "completed", exitCode: run.exitCode, stdout: run.stdout };

    expect(run.exitCode).toBe(0);
    expect(honouredDecision(run.stdout)).toBe("allow");
    const hook = shippedPreToolUse();
    expect(preToolUseToolCall(hook.onFailure, completed)).toBe("proceeds");
    expect(preToolUseToolCall(undefined, completed)).toBe("proceeds");
  });

  it("does not deny a clean exit 0 that prints no decision", async () => {
    const project = scratch();
    writeStandIn(project, "process.exit(0);\n");
    const run = await runShippedCommand({ CLAUDE_PROJECT_DIR: project });
    const completed: CompletedRun = { kind: "completed", exitCode: run.exitCode, stdout: run.stdout };

    expect(run.exitCode).toBe(0);
    expect(run.stdout).toBe("");
    const hook = shippedPreToolUse();
    expect(preToolUseToolCall(hook.onFailure, completed)).toBe("proceeds");
    expect(preToolUseToolCall(undefined, completed)).toBe("proceeds");
  });

  it("still denies on exit 2 when onFailure is unset", () => {
    const run: CompletedRun = { kind: "completed", exitCode: 2, stdout: "" };
    expect(preToolUseToolCall(undefined, run)).toBe("denied");
    expect(preToolUseToolCall("block", run)).toBe("denied");
  });
});

describe("PostToolUse leaves onFailure unset", () => {
  it("does not pretend a hook failure can undo a tool that already ran", () => {
    const hooks = commandHooks("PostToolUse");
    expect(hooks.length).toBeGreaterThan(0);
    for (const hook of hooks) {
      expect(hook.onFailure).toBeUndefined();
    }
  });
});
