/**
 * The result gate, end to end: `AcsPlugin`'s `"tool.execute.after"` hook,
 * against a live Guardian -- the same precedent request-gate.test.ts sets for
 * this host's other gate, and hosts/claude-code/test/post-tool-use.test.ts
 * sets for the Claude Code host's own result gate. `applyOpenCodeOutput` in
 * isolation, the shipped hookmap's static shape, and `AcsPlugin`'s own
 * load-time gate already have their own suites (apply-opencode-output.test.ts,
 * hookmap.test.ts, acs-plugin.test.ts); this is the first one that calls this
 * hook the way OpenCode itself would.
 *
 * The mirror is the point. `opencode.hookmap.yaml`'s result gate declares
 * `outputs.mirrors: [$.result.metadata.output]` -- `metadata` carries its own
 * copy of the tool's output, and a redaction that patched only the leaf would
 * leave the plaintext sitting in OpenCode's own session record while the
 * model correctly saw the redaction. Proving that mirror lands, end to end,
 * through the unmodified adapter, on a second host, is the whole point of
 * this suite.
 */
import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
// Test-only import: stands up a real Guardian, same precedent as
// request-gate.test.ts and hosts/claude-code/test/post-tool-use.test.ts.
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
  withResultOutput,
  type AcsDecision,
  type Hookmap,
} from "host-adapter";
import { AcsPlugin } from "../acs-plugin.ts";
import { applyOpenCodeOutput } from "../apply-opencode-output.ts";

const HOOKMAP_PATH = fileURLToPath(new URL("../opencode.hookmap.yaml", import.meta.url));

// "bash" (lowercase) -- OpenCode's own real tool name, measured on 1.18.15
// and what opencode.hookmap.yaml's result gate scopes `tools:` to (its own
// comment: `metadata` is per-tool, and only `bash`'s carries `exit`/`output`).
const TOOL = "bash";

// The live object shape OpenCode hands "tool.execute.after" for a `bash`
// call, measured on 1.18.15 (opencode.hookmap.yaml's own header):
// `{title, output, metadata: {output, exit, truncated}, attachments}`.
// `attachments` is present at runtime and absent from the published 1.18.15
// type (@opencode-ai/plugin's own `tool.execute.after` signature) -- this
// suite still carries it, the same way a real invocation would, to prove it
// survives a redaction untouched.
function liveResult(output: string): {
  title: string;
  output: string;
  metadata: { output: string; exit: number; truncated: boolean };
  attachments: unknown[];
} {
  return {
    title: "cat .env",
    output,
    metadata: { output, exit: 0, truncated: false },
    attachments: [{ type: "file", path: "/tmp/note.txt" }],
  };
}

// The same shape, with `metadata.exit` absent -- not a hand-waved "missing
// field". Real OpenCode never sends this for a `bash` call (see the "posture
// -proceeds" test below for the two measurements that pin that), but the
// gate's own behaviour for it is still real and still worth pinning.
function liveResultMissingExit(output: string): {
  title: string;
  output: string;
  metadata: { output: string; truncated: boolean };
  attachments: unknown[];
} {
  return {
    title: "cat .env",
    output,
    metadata: { output, truncated: false },
    attachments: [{ type: "file", path: "/tmp/note.txt" }],
  };
}

// Matching hosts/claude-code/test/post-tool-use.test.ts and this host's own
// request-gate.test.ts: redirected regardless of whether
// today's tests reach the fail-open path, because a handshake failure
// mid-run would otherwise append a real secret to the developer's own
// `.acs/audit.jsonl`.
const SCRATCH_DIR = mkdtempSync(join(tmpdir(), "acs-result-gate-test-"));
const AUDIT_LOG = join(SCRATCH_DIR, "audit.jsonl");

/**
 * A scratch audit path unique to one call, so an assertion about whether
 * that call wrote an audit entry does not depend on this file's own test
 * order, or on what an earlier test happened to write to the shared
 * `AUDIT_LOG`.
 */
function freshAuditLogPath(): string {
  return join(SCRATCH_DIR, `audit-${crypto.randomUUID()}.jsonl`);
}

/**
 * Runs `body` with `ACS_AUDIT_LOG` pointed at `path` for its duration, then
 * restores whatever was there before. `AcsPlugin` reads `ACS_AUDIT_LOG` at
 * its own construction (this file's own header note, and acs-plugin.ts's),
 * so the override has to be in place before `AcsPlugin({})` runs, not merely
 * before the hook fires -- every caller below constructs its own `hooks`
 * from inside `body` for exactly that reason.
 */
async function withAuditLog<T>(path: string, body: () => Promise<T>): Promise<T> {
  const previous = process.env.ACS_AUDIT_LOG;
  process.env.ACS_AUDIT_LOG = path;
  try {
    return await body();
  } finally {
    if (previous === undefined) {
      delete process.env.ACS_AUDIT_LOG;
    } else {
      process.env.ACS_AUDIT_LOG = previous;
    }
  }
}

let guardian: StartedGuardian;

beforeAll(async () => {
  guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
  // Read at AcsPlugin's own construction -- has to be set before AcsPlugin
  // runs, not merely before the hook fires. Same precedent as
  // request-gate.test.ts.
  process.env.ACS_GUARDIAN_URL = guardian.url;
  process.env.ACS_AUDIT_LOG = AUDIT_LOG;
});

afterAll(async () => {
  await guardian.close();
  delete process.env.ACS_GUARDIAN_URL;
  delete process.env.ACS_AUDIT_LOG;
  rmSync(SCRATCH_DIR, { recursive: true, force: true });
});

describe('AcsPlugin\'s "tool.execute.after" hook -- the result gate, against a live Guardian', () => {
  it("redacts the leaf AND its metadata mirror, leaving every other sibling untouched", async () => {
    const hooks = await AcsPlugin({} as never);
    const result = liveResult("TOKEN=ghp_SECRET123456");
    // Captured before the hook runs, so the `toBe` checks below the
    // assertions are identity checks, not value checks -- the request gate's
    // own `originalArgs` pin (request-gate.test.ts) is meaningful because the
    // applier could replace that reference; this is its result-gate
    // counterpart, for the two fields the deep in-place merge (mergeInPlace,
    // acs-plugin.ts) exists to spare.
    const originalMetadata = result.metadata;
    const originalAttachments = result.attachments;

    await expect(
      hooks["tool.execute.after"]!(
        { tool: TOOL, sessionID: "ses-result-gate-redact", callID: "c1", args: {} },
        result,
      ),
    ).resolves.toBeUndefined();

    // The leaf.
    expect(result.output).toBe("TOKEN=[REDACTED]");
    expect(result.output).not.toContain("ghp_SECRET123456");
    // The mirror -- the whole reason a second host exists to prove the
    // shared adapter still works. A redaction that patched only
    // `result.output` and left this plaintext would be a clean-looking leak:
    // the model sees the redaction, OpenCode's own session record does not.
    expect(result.metadata.output).toBe("TOKEN=[REDACTED]");
    expect(result.metadata.output).not.toContain("ghp_SECRET123456");

    // Every sibling this decision does not name, untouched -- the clone
    // discipline that is right for every field that is not a mirror.
    expect(result.title).toBe("cat .env");
    expect(result.metadata.exit).toBe(0);
    expect(result.metadata.truncated).toBe(false);
    expect(result.attachments).toEqual([{ type: "file", path: "/tmp/note.txt" }]);

    // Object identity survives the merge, not merely equal content:
    // `result.metadata` is the same object mergeInPlace recursed into and
    // mutated in place (this applier's own contract with OpenCode -- "mutate
    // what you were handed"), and `result.attachments` is the same array
    // `patchedClone` (result-output.ts) never touched, because it sits
    // outside the path to both the leaf and the mirror. A shallow
    // `Object.assign`-based merge would have replaced `result.metadata` with
    // a new object and failed this.
    expect(result.metadata).toBe(originalMetadata);
    expect(result.attachments).toBe(originalAttachments);
  });

  it("passes a clean result through untouched, on the same live object", async () => {
    const auditPath = freshAuditLogPath();
    const result = liveResult("hello world");

    await withAuditLog(auditPath, async () => {
      const hooks = await AcsPlugin({} as never);
      await expect(
        hooks["tool.execute.after"]!(
          { tool: TOOL, sessionID: "ses-result-gate-allow", callID: "c1", args: {} },
          result,
        ),
      ).resolves.toBeUndefined();
    });

    // A clean allow renders no `result` field at all (only the
    // declared-inert `reason.text`), so applyOpenCodeOutput's pass 3 merges
    // nothing -- the tool's own output survives exactly as produced.
    expect(result).toEqual(liveResult("hello world"));
    // No audit entry either: a decision arrived, so no fail-open posture was
    // ever consulted. Its own scratch path, not the shared `AUDIT_LOG` --
    // this assertion does not depend on this test running before any test
    // that does write one.
    expect(existsSync(auditPath)).toBe(false);
  });

  it("withholds a denied result by replacing rather than throwing", async () => {
    // "rm -rf /" -- the same destructive-command pattern policy/manifest.yaml
    // configures for the request gate, matched here against the result
    // payload's own text (post_tool_call's policy_target,
    // "$.tool_result.outputs[0].value") -- confirmed genuinely policy-
    // produced, below, not assumed from the withheld marker alone.
    const auditPath = freshAuditLogPath();
    const sessionID = "ses-result-gate-deny";
    const result = liveResult("rm -rf /");

    // Resolves, does not throw -- opencode.hookmap.yaml's own header states
    // the measurement this pins: OpenCode discards the plugin's mutations on
    // a throw out of "tool.execute.after" and rebuilds `metadata` from its
    // own pre-hook copy, so a secret scrubbed by a throw would not stay
    // scrubbed on disk. The result gate's own deny withholds by replacing
    // `result` instead.
    await withAuditLog(auditPath, async () => {
      const hooks = await AcsPlugin({} as never);
      await expect(
        hooks["tool.execute.after"]!({ tool: TOOL, sessionID, callID: "c1", args: {} }, result),
      ).resolves.toBeUndefined();
    });

    // The withheld marker, on the leaf AND its mirror -- the same pairing the
    // redaction test above pins, now for a deny.
    expect(result.output).toBe("[OUTPUT WITHHELD BY POLICY]");
    expect(result.metadata.output).toBe("[OUTPUT WITHHELD BY POLICY]");
    expect(result.output).not.toContain("rm -rf /");
    expect(result.metadata.output).not.toContain("rm -rf /");

    // Every sibling this decision does not name, still untouched.
    expect(result.title).toBe("cat .env");
    expect(result.metadata.exit).toBe(0);
    expect(result.metadata.truncated).toBe(false);
    expect(result.attachments).toEqual([{ type: "file", path: "/tmp/note.txt" }]);

    // Genuinely policy-produced, not a posture deny -- the withheld marker
    // alone cannot tell the two apart, since a fail-closed posture would
    // render byte-identically. Two independent checks close that:
    //
    //   1. No audit entry: a posture is only ever consulted, and only ever
    //      audited, when a decision failed to arrive -- a real decision
    //      arriving is not that.
    expect(existsSync(auditPath)).toBe(false);
    //   2. A cross-check against the real Guardian's own decision for the
    //      identical result payload, obtained independently of the hook (the
    //      same composition acs-plugin.ts's own "tool.execute.after"
    //      performs, called directly rather than through the hook) -- the
    //      same precedent request-gate.test.ts sets for its own deny test.
    const hookmap: Hookmap = loadHookmap(HOOKMAP_PATH);
    const crossCheckPayload = {
      tool: TOOL,
      session_id: sessionID,
      callID: "c1",
      args: {},
      result: liveResult("rm -rf /"),
    };
    const envelope = buildEnvelope("tool.execute.after", crossCheckPayload, hookmap);
    const response = await createGuardianClient(guardian.url).post(envelope);
    expect(response.error).toBeUndefined();
    expect(response.result?.decision).toBe("deny");
    // The stock pattern rule's own reason code -- proves this is the
    // destructive-command rule, not a differently-shaped deny that happens
    // to render the same withheld marker.
    expect(response.result?.reason_codes).toEqual(["destructive_shell_command_blocked"]);
  });

  it("skips a tool outside this gate's own tools list: no throw, result untouched, no Guardian request -- and one line saying so", async () => {
    // "read" -- one of the real tool names measured alongside "bash" that
    // opencode.hookmap.yaml's result gate does not list (its own comment:
    // `metadata` is per-tool -- "read"'s carries {display, loaded, preview,
    // truncated}, no `exit`). This gate is never asked to resolve
    // `$.result.metadata.exit` for it at all, so the shape below does not
    // matter to the assertion, only that nothing here touches it.
    const auditPath = freshAuditLogPath();
    const result = liveResult("some file preview text");

    const fetchSpy = spyOn(globalThis, "fetch");
    try {
      await withAuditLog(auditPath, async () => {
        const hooks = await AcsPlugin({} as never);
        await expect(
          hooks["tool.execute.after"]!(
            { tool: "read", sessionID: "ses-result-gate-unlisted", callID: "c1", args: {} },
            result,
          ),
        ).resolves.toBeUndefined();
      });

      expect(result).toEqual(liveResult("some file preview text"));
      expect(fetchSpy).not.toHaveBeenCalled();

      // And one audit line, which is the half that stops this from being
      // indistinguishable from a session where the hook never fired. OpenCode
      // fires this gate for EVERY tool, so on this host that silence was the
      // ordinary case rather than a corner: every `read`, `grep` and `edit`
      // call reached exactly this skip and left nothing behind. The entry
      // names the tool that arrived and the list that declined it, which is
      // what makes a `tools` list drifting away from OpenCode's own tool
      // names readable rather than invisible.
      expect(existsSync(auditPath)).toBe(true);
      const entries = readFileSync(auditPath, "utf8")
        .split("\n")
        .filter((line) => line.length > 0)
        .map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(entries).toEqual([
        {
          seq: 1,
          recorded_at: expect.any(String),
          session_id: "ses-result-gate-unlisted",
          method: "steps/toolCallResult",
          rpc_id: null,
          outcome: "ungoverned",
          ungoverned: { tool: "read", tools: ["bash"] },
        },
      ]);
      // Not a failure, and the negative half is asserted rather than implied:
      // nothing failed here, no posture was consulted, and an entry carrying
      // either would describe an incident that did not happen.
      expect(entries[0]).not.toHaveProperty("failure");
      expect(entries[0]).not.toHaveProperty("posture");
    } finally {
      fetchSpy.mockRestore();
    }
  });

  // See acs-plugin.ts's own "tool.execute.after" doc comment for the two
  // measurements pinning this as unreachable through `bash`, the only tool
  // this gate governs -- real in principle, and correctly left to the
  // posture rather than closed here.
  it("posture-proceeds, audited, when metadata.exit is missing -- real in principle, not reachable through bash", async () => {
    const auditPath = freshAuditLogPath();
    const result = liveResultMissingExit("TOKEN=ghp_SECRET123456");

    await withAuditLog(auditPath, async () => {
      const hooks = await AcsPlugin({} as never);
      await expect(
        hooks["tool.execute.after"]!(
          { tool: TOOL, sessionID: "ses-result-gate-missing-exit", callID: "c1", args: {} },
          result,
        ),
      ).resolves.toBeUndefined();
    });

    // A host_configuration failure at stage "request" -- exitStatusOf's own
    // throw, caught by governStep before the Guardian is ever asked -- is
    // answered by this deployment's negotiated posture, which defaults to
    // "proceed" (handshake.ts's own spec default). A posture "allow" renders
    // no `result` field, so applyOpenCodeOutput merges nothing: the tool's
    // own output -- secret included -- is delivered exactly as produced, in
    // both the leaf and the mirror. Correct because the fault is
    // payload-dependent, so `resolveByPosture` is the right seam, and pinned
    // here so the behaviour is a recorded decision, not an accident.
    expect(result.output).toBe("TOKEN=ghp_SECRET123456");
    expect(result.metadata.output).toBe("TOKEN=ghp_SECRET123456");

    // Audited -- this is the whole point of a posture-routed proceed: it is
    // visible, not silent (§6.4).
    expect(existsSync(auditPath)).toBe(true);
    const entries = readFileSync(auditPath, "utf8")
      .split("\n")
      .filter((line) => line.trim() !== "")
      .map((line) => JSON.parse(line) as { outcome: string; failure: { kind: string } });
    expect(
      entries.some((entry) => entry.outcome === "proceeded" && entry.failure.kind === "host_configuration"),
    ).toBe(true);
  });

  it("throws before asking the Guardian anything when sessionID is missing or empty -- a broken deployment, not a policy question", async () => {
    const hooks = await AcsPlugin({} as never);
    const result = liveResult("hello world");

    const fetchSpy = spyOn(globalThis, "fetch");
    try {
      await expect(
        hooks["tool.execute.after"]!({ tool: TOOL, sessionID: "", callID: "c1", args: {} }, result),
      ).rejects.toThrow(/sessionID/);
      // Nothing half-applied: a broken deployment refuses before any live
      // object could have been touched.
      expect(result).toEqual(liveResult("hello world"));
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("throws before asking the Guardian anything when `tool` is missing or not a string -- the same broken-deployment refusal `sessionID` gets, not a silent skip", async () => {
    const hooks = await AcsPlugin({} as never);
    const result = liveResult("hello world");

    const fetchSpy = spyOn(globalThis, "fetch");
    try {
      await expect(
        hooks["tool.execute.after"]!(
          { tool: undefined as unknown as string, sessionID: "ses-result-gate-bad-tool", callID: "c1", args: {} },
          result,
        ),
      ).rejects.toThrow(/tool/i);
      expect(result).toEqual(liveResult("hello world"));
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });
});

/**
 * The fault `assertHostAcceptsEveryDecision` (acs-plugin.ts) exists to
 * refuse, measured rather than assumed.
 *
 * These three tests are deliberately not written through `AcsPlugin`, and
 * that is the point rather than a convenience: this class of hookmap loads
 * cleanly on its own, and the fix is a load-time refusal in `AcsPlugin`.
 * Driving these through `AcsPlugin` would prove only that the refusal fires,
 * which `acs-plugin.test.ts` already pins -- it would say nothing about what
 * the refused hookmap actually does if it ever reaches a live decision,
 * which is the claim the gate rests on. So these call the same collaborators
 * `"tool.execute.after"` above calls (`loadHookmap`, `resolveSessionConfig`
 * -> `governStep`, `applyOpenCodeOutput`), against the same live Guardian and
 * the same real decisions, with the plugin factory -- and therefore the gate
 * -- out of the path. They keep measuring the hazard the gate exists to
 * prevent.
 *
 * Every fixture below is a few lines different from the shipped
 * `opencode.hookmap.yaml`'s result gate, and every one of them loads clean
 * through `loadHookmap`: `assertRenderableDecisions` (build-envelope.ts)
 * requires only a non-empty `output` block whose every field names a `value`
 * or a `from`, and `reason.text: { from: reasoning }` satisfies that exactly.
 */
describe("a result-gate decision the hookmap gives no way to withhold with -- the measured fail-open", () => {
  /** Writes one fixture hookmap into this file's scratch dir and returns its path. */
  function fixture(name: string, yaml: string): string {
    const path = join(SCRATCH_DIR, name);
    writeFileSync(path, yaml);
    return path;
  }

  /**
   * Runs the real chain for one hookmap and reports what the applier did to
   * the live object, with the plugin factory out of the path -- see this
   * describe block's own comment for why that is deliberate.
   *
   * `expectedDecision` is asserted here rather than returned, because it is
   * this helper's own precondition: every caller below is claiming something
   * about a decision that genuinely arrived, and a test whose Guardian
   * answered something else would be measuring nothing.
   *
   * What this helper cannot assert, and how the callers cover it instead: the
   * decision message's own `applied_output` -- `withResultOutput`'s guarantee
   * -- is not reachable from here. `governStep` attaches it inside its own
   * render step and returns the pre-attachment decision on
   * `GovernedStep.decision` (govern-step.ts, `renderDecision(hookEventName,
   * withResultOutput(decision, ...), hookmap)`). So each caller pins the
   * guarantee the way it is actually observable -- by running the identical
   * payload through the shipped hookmap and showing the withholding lands
   * there. Same Guardian, same decision, same live shape; the hookmap is the
   * only thing that differs, which is exactly the claim.
   */
  async function governAndApply(options: {
    hookmapPath: string;
    sessionID: string;
    toolOutput: string;
    expectedDecision: string;
  }): Promise<{ output: Record<string, unknown>; result: ReturnType<typeof liveResult>; threw: unknown }> {
    // Loads clean for every fixture below -- the finding's first half. Nothing
    // in the adapter's own load-time checks has an opinion about which key a
    // result-gate `deny`/`modify` renders into.
    const hookmap: Hookmap = loadHookmap(options.hookmapPath);

    const result = liveResult(options.toolOutput);
    const client = createGuardianClient(guardian.url);
    const session = await resolveSessionConfig(
      {
        guardian: client,
        agentId: hookmap.host,
        sessionId: toSessionUuid(options.sessionID),
        timeoutMs: DEFAULT_TIMEOUT_MS,
      },
      createMemorySessionConfigStore(),
    );
    const governed = await governStep({
      hookEventName: "tool.execute.after",
      payload: { tool: TOOL, session_id: options.sessionID, callID: "c1", args: {}, result },
      hookmap,
      guardian: client,
      session,
      sessionId: options.sessionID,
      // A posture is only ever consulted -- and only ever audited -- when a
      // decision failed to arrive, and every caller below asserts a real one
      // did. Nothing here writes an audit line, so nothing here needs a path.
      audit: NULL_AUDIT_SINK,
      // What `runExchange` passes: the tool this exchange already scoped on.
      // Every fixture below declares `tools: [bash]`, and a gate that
      // declares a list refuses a caller that names no tool.
      scopedTool: TOOL,
    });

    // A real policy decision, not a posture-resolved one: `stage: "honoured"`
    // is reachable only through the route that rendered a decision that
    // actually arrived (govern-step.ts's own `GovernedStep` doc comment).
    expect(governed.stage).toBe("honoured");
    expect(governed.decision?.decision).toBe(options.expectedDecision);

    let threw: unknown;
    try {
      applyOpenCodeOutput(governed.output, { gate: "result", result: result as unknown as Record<string, unknown> });
    } catch (error) {
      threw = error;
    }
    return { output: governed.output as Record<string, unknown>, result, threw };
  }

  // The result gate exactly as shipped, except that `deny` and `modify`
  // declare only `reason.text` -- the `result: { from: applied_output }` sink
  // removed from both. Every other line, `outputs.mirrors` included, is the
  // shipped file's.
  const NO_SINK_AT_ALL =
    "host: opencode\n" +
    "hooks:\n" +
    "  tool.execute.after:\n" +
    "    acs_method: steps/toolCallResult\n" +
    "    tool_name: $.tool\n" +
    "    tools: [bash]\n" +
    "    outputs:\n" +
    "      from: $.result.output\n" +
    "      within: $.result\n" +
    "      mirrors:\n" +
    "        - $.result.metadata.output\n" +
    "    exit_status: { from: $.result.metadata.exit }\n" +
    "    decisions:\n" +
    "      allow:\n" +
    "        output:\n" +
    "          reason.text: { from: reasoning, type: string }\n" +
    "      deny:\n" +
    "        output:\n" +
    "          reason.text: { from: reasoning, type: string }\n" +
    "      modify:\n" +
    "        output:\n" +
    "          reason.text: { from: reasoning, type: string }\n";

  it("deny: applies nothing and throws nothing, where the shipped hookmap withholds from the identical decision", async () => {
    // "rm -rf /" -- the same destructive-command payload the shipped-hookmap
    // deny test above uses, so the Guardian's answer here is the identical
    // `destructive_shell_command_blocked` deny, differing only in the hookmap
    // it is rendered through.
    const TOOL_OUTPUT = "rm -rf /";

    // The control, first: the shipped hookmap, whose result-gate `deny`
    // declares `result: { from: applied_output }`. The withholding lands on
    // the leaf and the mirror -- so `withResultOutput` did put one on the
    // decision message for this exact payload.
    const shipped = await governAndApply({
      hookmapPath: HOOKMAP_PATH,
      sessionID: "ses-result-gate-sink-control",
      toolOutput: TOOL_OUTPUT,
      expectedDecision: "deny",
    });
    expect(shipped.threw).toBeUndefined();
    expect(shipped.result.output).toBe("[OUTPUT WITHHELD BY POLICY]");
    expect(shipped.result.metadata.output).toBe("[OUTPUT WITHHELD BY POLICY]");

    // The fault: the same decision, the same payload, one hookmap block
    // different.
    const { output, result, threw } = await governAndApply({
      hookmapPath: fixture("result-deny-without-a-sink.yaml", NO_SINK_AT_ALL),
      sessionID: "ses-result-gate-no-sink-deny",
      toolOutput: TOOL_OUTPUT,
      expectedDecision: "deny",
    });

    // The render carries the declared-inert `reason` and nothing else --
    // `applyOpenCodeOutput`'s pass 1 skips `reason`, pass 2a finds no
    // `refuse`, pass 2b writes at most an `ACS_DEBUG` stderr line, and pass 3
    // has no `result` to merge.
    expect(Object.keys(output)).toEqual(["reason"]);
    expect(threw).toBeUndefined();

    // Nothing applied. The tool's own output survives in both places --
    // indistinguishable, on this live object, from a clean allow (compare
    // "passes a clean result through untouched", above).
    expect(result.output).toBe(TOOL_OUTPUT);
    expect(result.metadata.output).toBe(TOOL_OUTPUT);
    expect(result).toEqual(liveResult(TOOL_OUTPUT));
  });

  it("modify: the same, for a redaction -- and the render is literally {}", async () => {
    // The `modify` half of the same rule, measured rather than extrapolated
    // from the `deny` half: this deployment's own policy answers a secret in a
    // tool result with a redacting `modify`, which the shipped hookmap lands
    // through the same `result: { from: applied_output }` sink `deny` uses.
    const TOOL_OUTPUT = "TOKEN=ghp_SECRET123456";

    const shipped = await governAndApply({
      hookmapPath: HOOKMAP_PATH,
      sessionID: "ses-result-gate-sink-control-modify",
      toolOutput: TOOL_OUTPUT,
      expectedDecision: "modify",
    });
    expect(shipped.threw).toBeUndefined();
    expect(shipped.result.output).toBe("TOKEN=[REDACTED]");
    expect(shipped.result.metadata.output).toBe("TOKEN=[REDACTED]");

    const { output, result, threw } = await governAndApply({
      hookmapPath: fixture("result-modify-without-a-sink.yaml", NO_SINK_AT_ALL),
      sessionID: "ses-result-gate-no-sink-modify",
      toolOutput: TOOL_OUTPUT,
      expectedDecision: "modify",
    });

    // A reason, and nothing else. `reason.text: { from: reasoning }` renders
    // now -- the Guardian composes a sentence for a redaction out of the rule
    // that decided it, where AGT's own transform verdict carries no message --
    // but no sink is declared, so nothing here carries the redacted output and
    // the secret is delivered whole below. An explanation beside an unapplied
    // redaction is the shape this pins.
    expect(output).toEqual({
      reason: {
        text:
          "Secrets in this output were replaced before the model saw them. " +
          "Policy: redaction_applied, from AGT's stock bundle (agt_stock).",
      },
    });
    expect(threw).toBeUndefined();
    expect(result.output).toBe(TOOL_OUTPUT);
    expect(result.metadata.output).toBe(TOOL_OUTPUT);
  });

  // The second shape this gate refuses, and the reason its rule is the exact
  // key `result` rather than "any path whose leading segment is `result`".
  // Naming the leaf renders `{result: {output: <the whole patched container>}}`,
  // which `applyOpenCodeOutput` merges without complaint: `live.result.output`
  // becomes an object where OpenCode expects the tool's own output string, and
  // `live.result.metadata.output` -- the mirror, the entire reason a second
  // host exists to prove the shared adapter still works -- is never written
  // at all. opencode.hookmap.yaml's own `deny` comment already names this
  // shape as wrong ("burying the mirror's own patched copy one level too deep
  // for OpenCode to ever apply") and hookmap.test.ts already asserts the
  // shipped file does not use it; this load-time gate is what refuses it.
  const DENY_NAMING_THE_LEAF = NO_SINK_AT_ALL.replace(
    "      deny:\n" + "        output:\n" + "          reason.text: { from: reasoning, type: string }\n",
    "      deny:\n" +
      "        output:\n" +
      "          result.output: { from: applied_output }\n" +
      "          reason.text: { from: reasoning, type: string }\n",
  );

  it("deny naming the leaf (result.output) instead of the container leaves the mirror unwritten", async () => {
    const { result, threw } = await governAndApply({
      hookmapPath: fixture("result-deny-naming-the-leaf.yaml", DENY_NAMING_THE_LEAF),
      sessionID: "ses-result-gate-leaf-sink",
      toolOutput: "rm -rf /",
      expectedDecision: "deny",
    });

    expect(threw).toBeUndefined();
    // The mirror keeps what the tool produced -- a clean-looking leak, exactly
    // the one `outputs.mirrors` exists to prevent.
    expect(result.metadata.output).toBe("rm -rf /");
    // And the leaf did not receive the withheld string either: it received the
    // whole patched container object, one level too deep for OpenCode to read
    // an output from.
    expect(typeof result.output).toBe("object");
    expect((result.output as unknown as Record<string, unknown>).output).toBe("[OUTPUT WITHHELD BY POLICY]");
  });

  // The third member of the class. A gate that checks only whether the key
  // `result` is present, never what it is sourced from, would load this
  // fixture clean: `result: { from: applied_input }` declares the right key
  // against the wrong field. A result-gate decision carries `applied_output`,
  // never `applied_input`, and a `from:` field renders nothing when its
  // source is absent (render-decision.ts) -- exactly the reasoning the
  // request gate's own rule is written around ("`refuse.reason` alone is a
  // `from:` field that renders nothing...").
  //
  // Not a contrived shape: `args: { from: applied_input }` is what the request
  // gate's own `modify` declares, one copy-paste away in the same file.
  const DENY_SOURCING_THE_WRONG_FIELD = NO_SINK_AT_ALL.replace(
    "      deny:\n" + "        output:\n" + "          reason.text: { from: reasoning, type: string }\n",
    "      deny:\n" +
      "        output:\n" +
      "          result: { from: applied_input }\n" +
      "          reason.text: { from: reasoning, type: string }\n",
  );

  it("deny declaring result sourced from applied_input renders nothing at all -- the right key, the wrong field", async () => {
    const { output, result, threw } = await governAndApply({
      hookmapPath: fixture("result-deny-wrong-source.yaml", DENY_SOURCING_THE_WRONG_FIELD),
      sessionID: "ses-result-gate-wrong-source",
      toolOutput: "rm -rf /",
      expectedDecision: "deny",
    });

    // No `result` key at all: `applied_input` is absent on a result-gate
    // decision, so the field the hookmap declared resolved to nothing and
    // `renderDecision` emitted no key for it. What is left is the
    // declared-inert `reason` -- exactly the render the no-sink-at-all deny
    // above produces, from a hookmap that looks like it declares a sink.
    expect(Object.keys(output)).toEqual(["reason"]);
    expect(Object.hasOwn(output, "result")).toBe(false);
    expect(threw).toBeUndefined();
    expect(result.output).toBe("rm -rf /");
    expect(result.metadata.output).toBe("rm -rf /");
    expect(result).toEqual(liveResult("rm -rf /"));
  });

  // `declaresSinkFrom` checks what the sink is named, not whether the field
  // can actually render, so both shapes below declare
  // `result: { ... from: applied_output ... }` and still deliver.
  //
  // Shape 1: `type: string` beside the right `from`. `renderDecision` drops a
  // `from:` field whose carried value fails `typeof carried === field.type`
  // (render-decision.ts) -- and `applied_output` is an object, so `type: string`
  // drops it every time. More plausible than the wrong-`from` shape above, not
  // less: every other `from:` field in the shipped hookmap carries
  // `type: string` (`reason.text: { from: reasoning, type: string }`), so an
  // author following the house style writes exactly this.
  const DENY_WITH_A_TYPE_THAT_NEVER_MATCHES = NO_SINK_AT_ALL.replace(
    "      deny:\n" + "        output:\n" + "          reason.text: { from: reasoning, type: string }\n",
    "      deny:\n" +
      "        output:\n" +
      "          result: { from: applied_output, type: string }\n" +
      "          reason.text: { from: reasoning, type: string }\n",
  );

  it("deny declaring result with type: string renders no result key -- applied_output is an object, so the type filter drops it", async () => {
    const { output, result, threw } = await governAndApply({
      hookmapPath: fixture("result-deny-type-string.yaml", DENY_WITH_A_TYPE_THAT_NEVER_MATCHES),
      sessionID: "ses-result-gate-type-string",
      toolOutput: "rm -rf /",
      expectedDecision: "deny",
    });

    expect(Object.hasOwn(output, "result")).toBe(false);
    expect(threw).toBeUndefined();
    expect(result.output).toBe("rm -rf /");
    expect(result.metadata.output).toBe("rm -rf /");
    expect(result).toEqual(liveResult("rm -rf /"));
  });

  it("modify declaring result with type: string renders literally {} -- the secret delivered in leaf and mirror", async () => {
    // The same shape on the decision that carries no `reasoning`, so nothing
    // renders at all: byte-identical to a clean `allow`.
    const yaml = NO_SINK_AT_ALL.replace(
      "      modify:\n" + "        output:\n" + "          reason.text: { from: reasoning, type: string }\n",
      "      modify:\n" +
        "        output:\n" +
        "          result: { from: applied_output, type: string }\n" +
        "          reason.text: { from: reasoning, type: string }\n",
    );
    const { output, result, threw } = await governAndApply({
      hookmapPath: fixture("result-modify-type-string.yaml", yaml),
      sessionID: "ses-result-gate-type-string-modify",
      toolOutput: "TOKEN=ghp_SECRET123456",
      expectedDecision: "modify",
    });

    // `result` is dropped by the type filter -- applied_output is an object --
    // so the composed reason is all that renders, and nothing carries the
    // redaction.
    expect(output).toEqual({
      reason: {
        text:
          "Secrets in this output were replaced before the model saw them. " +
          "Policy: redaction_applied, from AGT's stock bundle (agt_stock).",
      },
    });
    expect(threw).toBeUndefined();
    expect(result.output).toBe("TOKEN=ghp_SECRET123456");
    expect(result.metadata.output).toBe("TOKEN=ghp_SECRET123456");
  });

  // Shape 2: a `value:` sitting beside the right `from:`. `renderDecision`
  // checks `hasOwnProperty(field, "value")` first and `continue`s -- it never
  // reads `from` at all. So this renders the literal, and an empty literal
  // renders `{"result":{}}`: a key the applier happily merges, merging nothing.
  const DENY_WITH_A_LITERAL_BESIDE_THE_SOURCE = NO_SINK_AT_ALL.replace(
    "      deny:\n" + "        output:\n" + "          reason.text: { from: reasoning, type: string }\n",
    "      deny:\n" + "        output:\n" + "          result: { value: {}, from: applied_output }\n",
  );

  it("deny declaring result as a literal BESIDE the right from: renders {result:{}} and merges nothing", async () => {
    const { output, result, threw } = await governAndApply({
      hookmapPath: fixture("result-deny-value-beside-from.yaml", DENY_WITH_A_LITERAL_BESIDE_THE_SOURCE),
      sessionID: "ses-result-gate-value-beside-from",
      toolOutput: "rm -rf /",
      expectedDecision: "deny",
    });

    // The key is rendered -- so a gate checking only for the key's presence
    // sees a well-formed sink -- and it is empty, so the merge is a no-op.
    expect(output).toEqual({ result: {} });
    expect(threw).toBeUndefined();
    expect(result).toEqual(liveResult("rm -rf /"));
  });

  // Covers `ask`/`defer` declared at this gate, even though the shipped
  // hookmap declares neither.
  //
  // Direction is what makes it a fault rather than a gap. Not declaring `ask`
  // is the safe state: `renderDecision` throws on a decision the hookmap has
  // no entry for, `governStep` catches it, and the deployment's posture
  // answers it -- audited either way. Declaring it without a sink is the
  // silent one, and that is what this measures.
  //
  // The decision is constructed, not Guardian-produced, and deliberately so:
  // what is at issue is what this hookmap renders for an arriving `ask`, not
  // which Guardian produces one. `renderDecision` is the exact seam the fault
  // lives at, and it is the same function `governStep` calls -- so this
  // drives the real adapter and the real applier, with only the decision's
  // origin differing from the tests above.
  const ASK_AND_DEFER_WITHOUT_A_SINK =
    NO_SINK_AT_ALL.replace(
      "      deny:\n" + "        output:\n" + "          reason.text: { from: reasoning, type: string }\n",
      "      deny:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n" +
        "          reason.text: { from: reasoning, type: string }\n",
    ).replace(
      "      modify:\n" + "        output:\n" + "          reason.text: { from: reasoning, type: string }\n",
      "      modify:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n" +
        "          reason.text: { from: reasoning, type: string }\n" +
        "      ask:\n" +
        "        output:\n" +
        "          reason.text: { from: reasoning, type: string }\n" +
        "      defer:\n" +
        "        output:\n" +
        "          reason.text: { from: reasoning, type: string }\n",
    );

  it.each(["ask", "defer"] as const)(
    "%s declared at the result gate with no sink renders a reason and withholds nothing",
    (decisionName) => {
      const hookmap = loadHookmap(
        fixture("result-ask-defer-without-a-sink.yaml", ASK_AND_DEFER_WITHOUT_A_SINK),
      );
      const result = liveResult("TOKEN=ghp_SECRET123456");

      const rendered = renderDecision("tool.execute.after", {
        decision: decisionName,
        reasoning: "held for review",
      } as unknown as AcsDecision, hookmap);

      // Only the declared-inert `reason` -- nothing this applier can land.
      expect(Object.keys(rendered)).toEqual(["reason"]);
      expect(() =>
        applyOpenCodeOutput(rendered, { gate: "result", result: result as unknown as Record<string, unknown> }),
      ).not.toThrow();
      // The secret is delivered, in both places, on a decision that asked for
      // the output to be held.
      expect(result).toEqual(liveResult("TOKEN=ghp_SECRET123456"));
    },
  );

  // The other direction, and the reason this gate's rule is "land it or
  // refuse it" rather than "land it".
  //
  // A result-gate decision mapped to `refuse.denied: { value: true }` is not
  // a silent no-op: the applier throws, measured below. That is a weaker
  // withholding than replacing -- opencode.hookmap.yaml's own header records
  // the measurement that OpenCode discards this plugin's mutations on a throw
  // out of "tool.execute.after" and rebuilds `metadata` from its own pre-hook
  // copy, so the plaintext survives in OpenCode's session record -- but it is
  // an honest one: the model never sees the output, and the author chose it.
  //
  // Refusing such a hookmap at load would be strictly worse on this host, and
  // that is measured too, elsewhere: OpenCode catches a throwing plugin
  // factory and continues with the plugin unloaded
  // (measured while the second host was built), so every tool call for the
  // rest of the session runs completely ungoverned -- the secret delivered to
  // the model and left on disk. Over-refusal is not a free direction to err
  // in here.
  it.each(["deny", "ask", "defer", "modify"] as const)(
    "a result-gate %s mapped to an unconditional refusal throws -- an honest outcome, not a no-op",
    (decisionName) => {
      const yaml =
        NO_SINK_AT_ALL.replace(
          "      deny:\n" + "        output:\n" + "          reason.text: { from: reasoning, type: string }\n",
          "      deny:\n" + "        output:\n" + "          refuse.denied: { value: true }\n",
        ).replace(
          "      modify:\n" + "        output:\n" + "          reason.text: { from: reasoning, type: string }\n",
          "      modify:\n" +
            "        output:\n" +
            "          refuse.denied: { value: true }\n" +
            "      ask:\n" +
            "        output:\n" +
            "          refuse.denied: { value: true }\n" +
            "      defer:\n" +
            "        output:\n" +
            "          refuse.denied: { value: true }\n",
        );
      const hookmap = loadHookmap(fixture("result-refusal-mapping.yaml", yaml));
      const result = liveResult("TOKEN=ghp_SECRET123456");

      const rendered = renderDecision("tool.execute.after", {
        decision: decisionName,
        reasoning: "held for review",
      } as unknown as AcsDecision, hookmap);

      expect(rendered).toEqual({ refuse: { denied: true } });
      // Throws -- the model never sees the tool's output. Nothing half-applied
      // either: pass 2a fires before any assignment.
      expect(() =>
        applyOpenCodeOutput(rendered, { gate: "result", result: result as unknown as Record<string, unknown> }),
      ).toThrow();
      expect(result).toEqual(liveResult("TOKEN=ghp_SECRET123456"));
    },
  );

  // The sixth member of the class, and the one that is no longer a member.
  //
  // This pair used to measure the fail-open: the result gate's rule required
  // a sink on `deny`/`modify`/`ask`/`defer`, and the sink it demanded could
  // never be filled for two of them, because `withResultOutput` attached
  // `applied_output` for `deny` alone and returned `ask`/`defer` untouched.
  // A result-gate `ask` or `defer` declaring `result: { from: applied_output }`
  // -- the exact declaration the gate required -- rendered no `result` key at
  // all and delivered the secret in the leaf and its mirror both.
  //
  // `withholdsAtResultGate` (result-output.ts) closed it: every disposition
  // but `allow` and `modify` now carries `applied_output` at a result gate,
  // on the reasoning that a step which has already run leaves nothing to ask
  // about and nothing to hold pending. So the mandated declaration is now the
  // one that works, and this asserts the withholding rather than the leak.
  //
  // Composed the way `governStep` composes it -- `renderDecision(hook,
  // withResultOutput(decision, outputLocation), hookmap)`, its own `render()`
  // (govern-step.ts) -- against the real adapter and the real applier. The
  // decision is constructed rather than Guardian-produced for the same reason
  // stated on the `ask`/`defer` no-sink case above.
  it.each(["ask", "defer"] as const)(
    "a result-gate %s declaring the mandated result sink withholds the output -- withResultOutput fills it",
    (decisionName) => {
      const yaml = NO_SINK_AT_ALL.replace(
        "      modify:\n" + "        output:\n" + "          reason.text: { from: reasoning, type: string }\n",
        "      modify:\n" +
          "        output:\n" +
          "          result: { from: applied_output }\n" +
          `      ${decisionName}:\n` +
          "        output:\n" +
          "          result: { from: applied_output }\n" +
          "          reason.text: { from: reasoning, type: string }\n",
      ).replace(
        "      deny:\n" + "        output:\n" + "          reason.text: { from: reasoning, type: string }\n",
        "      deny:\n" + "        output:\n" + "          result: { from: applied_output }\n",
      );
      const hookmap: Hookmap = loadHookmap(fixture(`result-${decisionName}-mandated-sink.yaml`, yaml));
      const result = liveResult("TOKEN=ghp_SECRET123456");

      // The location `governStep` would build for this entry -- an `outputs`
      // block is declared, so this is the well-formed case; nothing here is
      // degenerate.
      const outputs = hookmap.hooks["tool.execute.after"]!.outputs!;
      const projected = withResultOutput(
        { decision: decisionName, reasoning: "held for human review" } as unknown as AcsDecision,
        { payload: { result }, outputs },
      );

      // Attached: the field the hookmap points at now exists on the decision.
      expect(Object.hasOwn(projected, "applied_output")).toBe(true);

      const rendered = renderDecision("tool.execute.after", projected, hookmap);
      expect(Object.hasOwn(rendered, "result")).toBe(true);

      expect(() =>
        applyOpenCodeOutput(rendered, { gate: "result", result: result as unknown as Record<string, unknown> }),
      ).not.toThrow();

      // The secret withheld, in the leaf and the mirror both, from the same
      // hookmap that used to satisfy the gate's requirement and leak anyway.
      expect(result.output).toBe("[OUTPUT WITHHELD BY POLICY]");
      expect(result.metadata.output).toBe("[OUTPUT WITHHELD BY POLICY]");
      expect(result.output).not.toContain("ghp_SECRET123456");
      expect(result.metadata.output).not.toContain("ghp_SECRET123456");

      // Every sibling this decision does not name, still untouched.
      expect(result.title).toBe("cat .env");
      expect(result.metadata.exit).toBe(0);
      expect(result.attachments).toEqual([{ type: "file", path: "/tmp/note.txt" }]);
    },
  );

  // The same unsatisfiable-by-construction fault reached from the entry
  // rather than the decision, and this one hits `deny`.
  //
  // `withResultOutput` no-ops for every decision when its `location` is
  // undefined, and `governStep` builds that location from the entry's own
  // `outputs` block (`outputs === undefined ? undefined : {...}`). An entry at
  // `tool.execute.after` declaring `arguments:` instead of `outputs:` is a
  // legal `HookmapRequestHookEntry` as far as the adapter is concerned -- the
  // adapter keys off the entry's shape and never off the event name, on
  // purpose -- so it loads clean, and this host's gate (which does key by
  // hook name) demanded `result: { from: applied_output }` and got it.
  //
  // Guardian-produced end to end: this face hits `deny`, which this
  // deployment really does answer for `rm -rf /`.
  const RESULT_HOOK_WITH_NO_OUTPUTS =
    "host: opencode\n" +
    "hooks:\n" +
    "  tool.execute.after:\n" +
    "    acs_method: steps/toolCallRequest\n" +
    "    tool_name: $.tool\n" +
    "    arguments: $.args\n" +
    "    tools: [bash]\n" +
    "    decisions:\n" +
    "      allow:\n" +
    "        output:\n" +
    "          reason.text: { from: reasoning, type: string }\n" +
    "      deny:\n" +
    "        output:\n" +
    "          result: { from: applied_output }\n" +
    "          reason.text: { from: reasoning, type: string }\n";

  // `outputs.within` names the container a decision's `applied_output` is a
  // patched clone of, and nothing checks that it is the object this shim
  // actually hands the applier. The shim passes `result: output` (the live
  // `{title, output, metadata, attachments}`), and its payload puts that at
  // `$.result` -- so `$.result` is the only path that names it. Any other
  // container satisfies the sink rule and lands the clone somewhere else.
  const RESULT_WITHIN = (from: string, within: string) =>
    "host: opencode\n" +
    "hooks:\n" +
    "  tool.execute.after:\n" +
    "    acs_method: steps/toolCallResult\n" +
    "    tool_name: $.tool\n" +
    "    tools: [bash]\n" +
    "    outputs:\n" +
    `      from: ${from}\n` +
    `      within: ${within}\n` +
    "    exit_status: { from: $.result.metadata.exit }\n" +
    "    decisions:\n" +
    "      allow:\n" +
    "        output:\n" +
    "          reason.text: { from: reasoning, type: string }\n" +
    "      deny:\n" +
    "        output:\n" +
    "          result: { from: applied_output }\n" +
    "      modify:\n" +
    "        output:\n" +
    "          result: { from: applied_output }\n";

  it("within: $ makes the withheld clone land one level too deep -- leaf AND mirror keep the plaintext", async () => {
    const { output, result, threw } = await governAndApply({
      hookmapPath: fixture("result-within-root.yaml", RESULT_WITHIN("$.result.output", "$")),
      sessionID: "ses-result-within-root",
      toolOutput: "rm -rf /",
      expectedDecision: "deny",
    });

    // The sink rule is satisfied -- a `result` key is rendered and is merged.
    expect(Object.hasOwn(output, "result")).toBe(true);
    expect(threw).toBeUndefined();
    // And it withheld nothing: the clone is of the whole payload, so its own
    // `result` field is what carries the withholding, one level below where
    // the live object lives.
    expect(result.output).toBe("rm -rf /");
    expect(result.metadata.output).toBe("rm -rf /");
    // Worse: the payload's other top-level fields are merged onto OpenCode's
    // own live result object as junk keys.
    const asRecord = result as unknown as Record<string, unknown>;
    expect(Object.hasOwn(asRecord, "tool")).toBe(true);
    expect(Object.hasOwn(asRecord, "session_id")).toBe(true);
    expect(Object.hasOwn(asRecord, "callID")).toBe(true);
  });

  it("within: $.result.metadata leaves the mirror plaintext -- the exact leak outputs.mirrors exists to close", async () => {
    // `from`/`within` nest correctly here (`replacingOutput` refuses a pair
    // that does not), so nothing upstream complains: this names `metadata` as
    // the container and `metadata.output` as its leaf. Both are real paths in
    // the payload. What is wrong is only that `metadata` is not the object the
    // shim hands the applier.
    const { result, threw } = await governAndApply({
      hookmapPath: fixture(
        "result-within-metadata.yaml",
        RESULT_WITHIN("$.result.metadata.output", "$.result.metadata"),
      ),
      sessionID: "ses-result-within-metadata",
      toolOutput: "rm -rf /",
      expectedDecision: "deny",
    });

    expect(threw).toBeUndefined();
    // The mirror keeps the plaintext -- the leak `outputs.mirrors` exists to
    // close, reached from the container rather than from a missing mirror.
    expect(result.metadata.output).toBe("rm -rf /");
    // And `metadata`'s own siblings land on the live result object as junk,
    // because the patched clone of `metadata` was merged one level too high.
    const asRecord = result as unknown as Record<string, unknown>;
    expect(asRecord.exit).toBe(0);
    expect(asRecord.truncated).toBe(false);
  });

  // `outputs.from` is not only the leaf a withholding replaces. It is the
  // leaf that goes on the wire as the ACS result payload's
  // `outputs[0].value` -- the value the policy runtime is asked about. Point
  // it at a different field and the Guardian is not asked the wrong question
  // about the output; it is asked about a different value entirely, answers
  // it correctly, and the step is audited as a clean allow.
  it("outputs.from naming another leaf puts the WRONG VALUE on the wire, and the deny never happens", async () => {
    const yaml = RESULT_WITHIN("$.result.title", "$.result");
    const hookmapPath = fixture("result-from-title.yaml", yaml);

    // First, the wire: this is what the policy runtime is actually asked
    // about.
    const hookmap: Hookmap = loadHookmap(hookmapPath);
    const envelope = buildEnvelope("tool.execute.after", {
      tool: TOOL,
      session_id: "ses-envelope-probe",
      callID: "c1",
      args: {},
      result: liveResult("rm -rf /"),
    }, hookmap);
    // "cat .env" -- `liveResult`'s own `title` -- where the shipped hookmap
    // puts the tool's output. (`bash` is `tool.name`, a different field.)
    expect(envelope.params.payload).toEqual({
      tool: { name: "bash" },
      exit_status: "success",
      outputs: [{ value: "cat .env" }],
    });

    // Then the consequence, end to end against the live Guardian.
    const { output, result, threw } = await governAndApply({
      hookmapPath,
      sessionID: "ses-result-from-title",
      toolOutput: "rm -rf /",
      // Allow -- not a deny that failed to land, a deny that never happened.
      // The policy never saw `rm -rf /` at all.
      expectedDecision: "allow",
    });

    expect(output).toEqual({});
    expect(threw).toBeUndefined();
    expect(result.output).toBe("rm -rf /");
    expect(result.metadata.output).toBe("rm -rf /");
    expect(result).toEqual(liveResult("rm -rf /"));
  });

  it("a result hook declaring no outputs block renders no result key for a real deny -- the sink is unfillable by construction", async () => {
    const { output, result, threw } = await governAndApply({
      hookmapPath: fixture("result-hook-without-outputs.yaml", RESULT_HOOK_WITH_NO_OUTPUTS),
      sessionID: "ses-result-gate-no-outputs-block",
      toolOutput: "rm -rf /",
      expectedDecision: "deny",
    });

    expect(Object.hasOwn(output, "result")).toBe(false);
    expect(threw).toBeUndefined();
    expect(result.output).toBe("rm -rf /");
    expect(result.metadata.output).toBe("rm -rf /");
    expect(result).toEqual(liveResult("rm -rf /"));
  });
});
