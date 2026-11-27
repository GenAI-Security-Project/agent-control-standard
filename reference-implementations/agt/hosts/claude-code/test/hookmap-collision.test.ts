import { afterEach, describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * A hookmap whose `modify` entry declares `updatedInput` and
 * `updatedInput.command` cannot render a `modify`. Before `loadHookmap` checked
 * for it, that hookmap loaded clean. When a Guardian answered `modify`, the
 * render threw, the delivery posture answered, and under `proceed` the shim
 * wrote `allow` with no rewrite: the command ran as originally requested.
 * Measured through this shim against a stub Guardian that answered `modify`.
 *
 * Now the shim stops at load, the way it does for any hookmap it cannot trust:
 * exit 2, nothing on stdout, the reason on stderr, nothing written.
 */
const SHIM_PATH = fileURLToPath(new URL("../acs-hook.ts", import.meta.url));

const dirs: string[] = [];
const files: string[] = [];
afterEach(() => {
  while (files.length > 0) {
    unlinkSync(files.pop() as string);
  }
  while (dirs.length > 0) {
    rmdirSync(dirs.pop() as string);
  }
});

const HOOKMAP =
  "host: claude-code\n" +
  "hooks:\n" +
  "  PreToolUse:\n" +
  "    acs_method: steps/toolCallRequest\n" +
  "    tool_name: $.tool_name\n" +
  "    arguments: $.tool_input\n" +
  "    decisions:\n" +
  "      allow: { output: { hookSpecificOutput.permissionDecision: { value: allow } } }\n" +
  "      deny: { output: { hookSpecificOutput.permissionDecision: { value: deny } } }\n" +
  "      modify:\n" +
  "        output:\n" +
  "          hookSpecificOutput.permissionDecision: { value: allow }\n" +
  "          hookSpecificOutput.updatedInput: { from: applied_input }\n" +
  "          hookSpecificOutput.updatedInput.command: { value: echo x }\n";

describe("the Claude Code shim with a hookmap whose output paths collide", () => {
  it("exits 2 with the collision on stderr, and writes nothing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-hookmap-collision-"));
    dirs.push(dir);
    const hookmapPath = join(dir, "colliding.yaml");
    writeFileSync(hookmapPath, HOOKMAP);
    files.push(hookmapPath);

    const proc = Bun.spawn({
      cmd: ["bun", "run", SHIM_PATH],
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
      env: {
        ...process.env,
        ACS_HOOKMAP_PATH: hookmapPath,
        ACS_GUARDIAN_URL: "http://127.0.0.1:1/acs",
        ACS_SESSION_DIR: join(dir, "sessions"),
        ACS_AUDIT_LOG: join(dir, "audit.jsonl"),
      },
    });
    proc.stdin.write(
      JSON.stringify({
        session_id: "collision-1",
        hook_event_name: "PreToolUse",
        tool_name: "Bash",
        tool_input: { command: "rm -rf /tmp/x" },
      }),
    );
    proc.stdin.end();
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);

    expect(exitCode).toBe(2);
    expect(stdout).toBe("");
    expect(stderr).toContain("hooks.PreToolUse.decisions.modify");
    expect(stderr).toContain("hookSpecificOutput.updatedInput");
    expect(stderr).toContain("collide");
    expect(existsSync(join(dir, "sessions"))).toBe(false);
    expect(existsSync(join(dir, "audit.jsonl"))).toBe(false);
  });
});
