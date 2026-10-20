import { describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
// Test-only import, the same precedent as hook.test.ts: a real Guardian, so
// this proves the pairing on the wire rather than against a copied shape.
import { startGuardian } from "guardian";
import {
  createGuardianClient,
  createMemorySessionConfigStore,
  DEFAULT_TIMEOUT_MS,
  governStep,
  loadHookmap,
  NULL_AUDIT_SINK,
  resolveSessionConfig,
  toSessionUuid,
} from "host-adapter";

const HOOKMAP_PATH = fileURLToPath(new URL("../claude-code.hookmap.yaml", import.meta.url));

// The shipped hookmap names `tool_use_id` as the call id. Claude Code's hooks
// reference shows the field on both PreToolUse and PostToolUse; a transcript
// check found the same value on both hooks of one call.
function findingLines(path: string): unknown[] {
  if (!existsSync(path)) {
    return [];
  }
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line) as { direction: string; envelope: unknown })
    .filter((entry) => entry.direction === "finding")
    .map((entry) => entry.envelope);
}

async function runCall(sessionId: string, beforeId: string, afterId: string): Promise<unknown[]> {
  const dir = mkdtempSync(join(tmpdir(), "acs-pairing-"));
  const logPath = join(dir, "envelopes.jsonl");
  const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml", envelopeLogPath: logPath });
  try {
    const hookmap = loadHookmap(HOOKMAP_PATH);
    const client = createGuardianClient(guardian.url);
    const session = await resolveSessionConfig(
      { guardian: client, agentId: hookmap.host, sessionId: toSessionUuid(sessionId), timeoutMs: DEFAULT_TIMEOUT_MS },
      createMemorySessionConfigStore(),
    );
    const common = { session_id: sessionId, tool_name: "Bash", tool_input: { command: "ls" } };
    for (const [hookEventName, payload] of [
      ["PreToolUse", { ...common, hook_event_name: "PreToolUse", tool_use_id: beforeId }],
      ["PostToolUse", { ...common, hook_event_name: "PostToolUse", tool_use_id: afterId, tool_response: { stdout: "a.txt" } }],
    ] as const) {
      await governStep({ hookEventName, payload, hookmap, guardian: client, session, sessionId, audit: NULL_AUDIT_SINK });
    }
    return findingLines(logPath);
  } finally {
    await guardian.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("Claude Code: a result names the request it answers", () => {
  it("records no finding when PostToolUse carries the same tool_use_id as PreToolUse", async () => {
    expect(await runCall("sess-raw-not-a-uuid", "toolu_01", "toolu_01")).toHaveLength(0);
  });

  it("records an unresolved reference when the result's call never reached the Guardian", async () => {
    const findings = await runCall("sess-raw-not-a-uuid", "toolu_01", "toolu_02");
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ finding: "request_id_ref_unresolved" });
  });
});
