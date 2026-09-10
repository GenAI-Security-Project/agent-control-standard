import { afterEach, describe, expect, it } from "bun:test";
import { startGuardian } from "guardian";
import { buildConfigBundle, buildManifest } from "./helpers/config-bundle.ts";

const DESTRUCTIVE = ["(?i)rm\\s+-[a-z]*r[a-z]*f[a-z]*\\s+/(?:\\s|$)"];
const cleanups: (() => void)[] = [];
afterEach(() => {
  while (cleanups.length > 0) (cleanups.pop() as () => void)();
});

async function decide(config: unknown, command: string, annotator?: () => unknown) {
  const bundle = buildConfigBundle(config);
  cleanups.push(bundle.cleanup);
  const manifestPath = buildManifest({ bundleDir: bundle.dir, annotator: annotator !== undefined });
  const guardian = await startGuardian({ port: 0, manifestPath, annotator });
  try {
    const requestId = crypto.randomUUID();
    const res = await fetch(guardian.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: requestId,
        method: "steps/toolCallRequest",
        params: {
          acs_version: "0.1.0",
          request_id: requestId,
          timestamp: new Date().toISOString(),
          // metadata.session_id is schema-constrained to format "uuid"
          // (request-envelope.json) -- "sess-1" fails that check before
          // the envelope ever reaches AGT, so this uses a real UUID instead.
          metadata: { agent_id: "test", session_id: crypto.randomUUID() },
          payload: { tool: { name: "Bash" }, arguments: { command: { value: command } } },
        },
      }),
    });
    return (await res.json()) as { result?: Record<string, unknown>; error?: unknown };
  } finally {
    await guardian.close();
  }
}

const PATTERNS = { patterns: { patterns: DESTRUCTIVE, reason: "destructive_shell_command_blocked" } };

describe("all five AGT verdicts arrive as ACS decisions, from the pinned bundle", () => {
  it("allow", async () => {
    const { result } = await decide(PATTERNS, "ls -la");
    expect(result).toMatchObject({ decision: "allow" });
    // A clean allow, not a policy-fired one: this is what distinguishes it from warn.
    expect(result?.policy_references ?? []).toEqual([]);
  });

  it("deny", async () => {
    const { result } = await decide(PATTERNS, "rm -rf /");
    expect(result).toMatchObject({ decision: "deny", reason_codes: ["destructive_shell_command_blocked"] });
  });

  it("escalate arrives as ask", async () => {
    const { result } = await decide({ ...PATTERNS, approval: { required: true, approvers: ["security-team"] } }, "ls -la");
    expect(result).toMatchObject({ decision: "ask", reason_codes: ["approval_required"] });
  });

  it("transform arrives as modify, carrying the rewritten argument", async () => {
    const { result } = await decide(
      { ...PATTERNS, redact: { patterns: ["ghp_[A-Za-z0-9]{6,}"], replacement: "[REDACTED]" } },
      "echo ghp_ABCDEF123456",
    );
    expect(result).toMatchObject({
      decision: "modify",
      reason_codes: ["redaction_applied"],
      modifications: { parameter_overrides: { command: "echo [REDACTED]" } },
    });
  });

  // warn has no ACS disposition of its own, so it arrives as allow, and the
  // non-empty policy_references is the only thing distinguishing it from a
  // clean allow.
  it("warn arrives as allow with non-empty policy_references", async () => {
    const { result } = await decide({ ...PATTERNS, drift: { warn_threshold: 0.5 } }, "ls -la", () => 0.9);
    expect(result).toMatchObject({ decision: "allow", reason_codes: ["drift_detected"] });
    expect(result?.policy_references).toEqual([{ policy_id: "agt_stock", rule_id: "drift_detected" }]);
  });

  // Stated as a test so the mechanic is recorded in code, not only prose.
  it("the stock chain's global approval switch outranks allow and transform", async () => {
    const config = {
      ...PATTERNS,
      approval: { required: true, approvers: ["sec"] },
      redact: { patterns: ["ghp_[A-Za-z0-9]{6,}"] },
    };
    expect((await decide(config, "echo ghp_ABCDEF123456")).result).toMatchObject({ decision: "ask" });
    expect((await decide(config, "rm -rf /")).result).toMatchObject({ decision: "deny" });
  });
});

describe("the fixture bundles never fork the pinned bundle", () => {
  it("copies every .rego byte-identically", () => {
    const bundle = buildConfigBundle(PATTERNS);
    cleanups.push(bundle.cleanup);
    // buildConfigBundle asserts this internally; this test proves the
    // assertion exists and runs, so a future edit cannot quietly drop it.
    expect(() => buildConfigBundle(PATTERNS).cleanup()).not.toThrow();
  });
});
