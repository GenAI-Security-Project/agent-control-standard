/**
 * The request gate, end to end: `AcsPlugin`'s `"tool.execute.before"` hook,
 * against a live Guardian -- exactly as hosts/claude-code/test/hook.test.ts
 * proves the wire contract for the Claude Code host, not against a
 * hand-copied shape. Everything below the plugin factory itself --
 * `applyOpenCodeOutput` in isolation, the shipped hookmap's static shape,
 * `AcsPlugin`'s own load-time gate -- already has its own suite
 * (apply-opencode-output.test.ts, hookmap.test.ts, acs-plugin.test.ts); this
 * is the first one that calls the hook OpenCode itself would call.
 */
import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
// Test-only import: stands up a real Guardian, the same arrangement
// hosts/claude-code/test/hook.test.ts uses, and the same one
// apply-opencode-output.test.ts uses to render through the real adapter.
import { startGuardian, type StartedGuardian } from "guardian";
import {
  buildEnvelope,
  createGuardianClient,
  governsTool,
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
import { AcsPlugin } from "../acs-plugin.ts";
import { applyOpenCodeOutput } from "../apply-opencode-output.ts";

const HOOKMAP_PATH = fileURLToPath(new URL("../opencode.hookmap.yaml", import.meta.url));

// "bash" (lowercase) -- OpenCode's own real tool name, measured on 1.18.15
// and what opencode.hookmap.yaml's request gate scopes `tools:` to.
// policy/manifest.yaml's fixed policy_target denies every tool it has not
// registered, unconditionally, before any authored rule runs; it registers
// both "bash" and "Bash" (Claude Code's own capitalised name), additive, so
// this suite exercises the name the host actually sends.
const TOOL = "bash";

// Matching hosts/claude-code/test/hook.test.ts's own ACS_AUDIT_LOG redirect:
// nearly every test below expects a real decision to arrive, so nearly
// nothing here writes an entry -- the one exception is the `tools` skip,
// which files an ungoverned line and therefore points at its own path rather
// than this shared one, so "no entry" stays a claim about the test making it.
// The redirect is unconditional regardless, because a handshake failure
// mid-run would append raw tool arguments (a destructive command, in this
// suite) to the developer's own `.acs/audit.jsonl`, whether or not today's
// tests reach that path.
const SCRATCH_DIR = mkdtempSync(join(tmpdir(), "acs-request-gate-test-"));
const AUDIT_LOG = join(SCRATCH_DIR, "audit.jsonl");

let guardian: StartedGuardian;

beforeAll(async () => {
  guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
  // Read at AcsPlugin's own construction, per hosts/opencode/acs-plugin.ts's
  // own header ("the plugin reads ACS_GUARDIAN_URL when it is constructed") --
  // so this has to be set before AcsPlugin runs, not merely before the hook
  // fires. hosts/claude-code/test/hook.test.ts sets it the same way.
  process.env.ACS_GUARDIAN_URL = guardian.url;
  process.env.ACS_AUDIT_LOG = AUDIT_LOG;
});

afterAll(async () => {
  await guardian.close();
  delete process.env.ACS_GUARDIAN_URL;
  delete process.env.ACS_AUDIT_LOG;
  rmSync(SCRATCH_DIR, { recursive: true, force: true });
});

describe('AcsPlugin\'s "tool.execute.before" hook -- the request gate, against a live Guardian', () => {
  it("allows a clean command: no throw, and args untouched", async () => {
    const hooks = await AcsPlugin({} as never);
    const output = { args: { command: "ls -la" } };

    await expect(
      hooks["tool.execute.before"]!({ tool: TOOL, sessionID: "ses-request-gate-allow", callID: "c1" }, output),
    ).resolves.toBeUndefined();

    // A clean allow renders no `args` field at all (only the declared-inert
    // `reason.text`), so applyOpenCodeOutput's pass 3 merges nothing -- the
    // live object is the same reference, untouched.
    expect(output.args).toEqual({ command: "ls -la" });
    // No audit entry either: a decision arrived, so no fail-open posture was
    // ever consulted.
    expect(existsSync(AUDIT_LOG)).toBe(false);
  });

  it("denies a destructive command by throwing, with the Guardian's own reason, and applies nothing first", async () => {
    const sessionID = "ses-request-gate-deny";
    const command = "rm -rf /";

    const hooks = await AcsPlugin({} as never);
    const output = { args: { command } };

    let thrown: unknown;
    try {
      await hooks["tool.execute.before"]!({ tool: TOOL, sessionID, callID: "c1" }, output);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Error);
    // Nothing half-applied: the live object this call was handed is
    // untouched, the same all-or-nothing guarantee apply-opencode-output.test.ts
    // pins in isolation, now proven through governStep and a real deny.
    expect(output.args.command).toBe(command);

    // Cross-check against the real Guardian's own decision for the identical
    // tool call, obtained independently of the hook (the same composition
    // acs-plugin.ts's own "tool.execute.before" performs, called directly
    // rather than through the hook) -- proves the thrown message is the
    // policy's actual text, not a hardcoded placeholder. Same precedent as
    // hosts/claude-code/test/hook.test.ts's own cross-check.
    const hookmap: Hookmap = loadHookmap(HOOKMAP_PATH);
    const envelope = buildEnvelope(
      "tool.execute.before",
      { tool: TOOL, session_id: sessionID, callID: "c1", args: { command } },
      hookmap,
    );
    const response = await createGuardianClient(guardian.url).post(envelope);
    expect(response.error).toBeUndefined();
    const expected = renderDecision(
      "tool.execute.before",
      response.result as { decision: string } & Record<string, unknown>,
      hookmap,
    ) as { refuse?: { denied?: unknown; reason?: unknown } };

    expect(expected.refuse?.denied).toBe(true);
    expect(typeof expected.refuse?.reason).toBe("string");
    expect((thrown as Error).message).toBe(expected.refuse!.reason as string);
  });

  it("applies a rewrite to the live args in place, for a command a redaction rewrites", async () => {
    const hooks = await AcsPlugin({} as never);
    const output = { args: { command: "echo ghp_ABCDEF123456" } };
    const originalArgs = output.args;

    await expect(
      hooks["tool.execute.before"]!(
        { tool: TOOL, sessionID: "ses-request-gate-modify", callID: "c1" },
        output,
      ),
    ).resolves.toBeUndefined();

    // Mutated in place -- applyOpenCodeOutput's own contract -- not replaced with
    // a new object.
    expect(output.args).toBe(originalArgs);
    expect(output.args.command).toBe("echo [REDACTED]");
  });

  it("throws before asking the Guardian anything when sessionID is missing or empty -- a broken deployment, not a policy question", async () => {
    const hooks = await AcsPlugin({} as never);
    const output = { args: { command: "ls -la" } };

    await expect(
      hooks["tool.execute.before"]!({ tool: TOOL, sessionID: "", callID: "c1" }, output),
    ).rejects.toThrow(/sessionID/);
    // Nothing half-applied here either: a broken deployment refuses before
    // any live object could have been touched.
    expect(output.args.command).toBe("ls -la");
  });

  it("skips a tool outside this gate's own tools list: no throw, args untouched, no Guardian request -- and one line saying so", async () => {
    // "read" -- one of the real tool names measured alongside "bash" that
    // opencode.hookmap.yaml's request gate does not list. Args shaped the
    // way OpenCode's own "read" tool call actually is (the coordinator's own
    // measurement): {filePath}, not {command} -- this gate is never asked to
    // resolve `$.args` for it at all, so the shape does not matter to the
    // assertion, only that nothing here touches it.
    //
    // Its own audit path, not this file's shared one: this is the one test
    // here that writes an entry, and the shared log is what every other test
    // asserts is absent.
    const auditPath = join(SCRATCH_DIR, `audit-${crypto.randomUUID()}.jsonl`);
    const previousAuditLog = process.env.ACS_AUDIT_LOG;
    const output = { args: { filePath: "/etc/passwd" } };

    // If the skip did not run before any envelope was built, a request would
    // go out over `fetch` (createGuardianClient's own wire primitive) --
    // spied here, not mocked, so a call that does happen still reaches the
    // real Guardian rather than hanging; the assertion below is on whether
    // it was called at all, not on what it returned.
    const fetchSpy = spyOn(globalThis, "fetch");
    try {
      // Set before AcsPlugin runs, not merely before the hook fires: the
      // sink is built in the plugin factory (acs-plugin.ts's own note).
      process.env.ACS_AUDIT_LOG = auditPath;
      const hooks = await AcsPlugin({} as never);
      await expect(
        hooks["tool.execute.before"]!({ tool: "read", sessionID: "ses-request-gate-unlisted", callID: "c1" }, output),
      ).resolves.toBeUndefined();

      expect(output.args).toEqual({ filePath: "/etc/passwd" });
      expect(fetchSpy).not.toHaveBeenCalled();

      // Ungoverned, and recorded as exactly that: this gate declined to ask,
      // so there is no failure to file and no posture that answered. What
      // the line has to carry is the tool that arrived beside the list that
      // declined it, since a `tools` list drifting away from the names
      // OpenCode actually sends is otherwise invisible.
      expect(existsSync(auditPath)).toBe(true);
      const entries = readFileSync(auditPath, "utf8")
        .split("\n")
        .filter((line) => line.length > 0)
        .map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(entries).toEqual([
        {
          seq: 1,
          recorded_at: expect.any(String),
          session_id: "ses-request-gate-unlisted",
          method: "steps/toolCallRequest",
          rpc_id: null,
          outcome: "ungoverned",
          // Both tools this gate governs since V9, not just `bash`: the list
          // is the half of the entry that makes a drifting `tools` decl
          // visible, so it has to be the shipped one.
          ungoverned: { tool: "read", tools: ["bash", "webfetch"] },
        },
      ]);
    } finally {
      fetchSpy.mockRestore();
      if (previousAuditLog === undefined) {
        delete process.env.ACS_AUDIT_LOG;
      } else {
        process.env.ACS_AUDIT_LOG = previousAuditLog;
      }
    }
  });

  it("does not crash on a bare `tools:` key (YAML null) -- read as \"every tool\", not a TypeError", async () => {
    // `tools:` with nothing after it parses to YAML null -- present and
    // unusable, not absent. `loadHookmap` normalises it to a hookmap with the
    // key omitted (`normalizeTools`), and `governsTool` is what reads the
    // result. What this test pins is the behaviour that normalisation has to
    // preserve -- a bare `tools:` means "every tool".
    const hookmapPath = join(SCRATCH_DIR, "bare-tools.hookmap.yaml");
    writeFileSync(
      hookmapPath,
      "host: opencode\n" +
        "hooks:\n" +
        "  tool.execute.before:\n" +
        "    acs_method: steps/toolCallRequest\n" +
        "    tool_name: $.tool\n" +
        "    arguments: $.args\n" +
        "    tools:\n" +
        "    decisions:\n" +
        "      allow:\n" +
        "        output:\n" +
        "          reason.text: { from: reasoning, type: string }\n" +
        "      deny:\n" +
        "        output:\n" +
        "          refuse.denied: { value: true }\n" +
        "          refuse.reason: { from: reasoning, type: string }\n",
    );

    const previousHookmapPath = process.env.ACS_HOOKMAP_PATH;
    process.env.ACS_HOOKMAP_PATH = hookmapPath;
    try {
      const hooks = await AcsPlugin({} as never);
      const output = { args: { command: "ls -la" } };
      await expect(
        hooks["tool.execute.before"]!({ tool: TOOL, sessionID: "ses-request-gate-bare-tools", callID: "c1" }, output),
      ).resolves.toBeUndefined();
      // Governed, not skipped: a bare `tools:` means "every tool", the same
      // as an undeclared one -- a clean allow, so args is untouched.
      expect(output.args).toEqual({ command: "ls -la" });
    } finally {
      if (previousHookmapPath === undefined) {
        delete process.env.ACS_HOOKMAP_PATH;
      } else {
        process.env.ACS_HOOKMAP_PATH = previousHookmapPath;
      }
    }
  });

  it("throws before asking the Guardian anything when `tool` is missing or not a string -- the same broken-deployment refusal `sessionID` gets, not a silent skip", async () => {
    // A `tools.includes(undefined)` check alone would read as `false` --
    // "not in this gate's tools list" -- and return cleanly: no throw, no
    // fetch, no audit line. This asserts an ungoverned-but-loud stop instead
    // -- no fetch at all, the same "broken deployment" shape `sessionID`'s
    // own missing-value test already gets, rather than letting a malformed
    // `tool` reach `buildEnvelope` (which throws, caught by `governStep`'s
    // stage-"request" catch and answered by the negotiated posture, audited
    // regardless of which way the posture resolves).
    const hooks = await AcsPlugin({} as never);
    const output = { args: { command: "ls -la" } };

    const fetchSpy = spyOn(globalThis, "fetch");
    try {
      await expect(
        hooks["tool.execute.before"]!(
          { tool: undefined as unknown as string, sessionID: "ses-request-gate-bad-tool", callID: "c1" },
          output,
        ),
      ).rejects.toThrow(/tool/i);
      // Nothing half-applied, and nothing asked: the same discipline the
      // sessionID refusal already gets.
      expect(output.args.command).toBe("ls -la");
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });
});

/**
 * The request gate's own member of the class closed at the result gate -- a
 * `modify` the hookmap gives nowhere to land.
 *
 * This measures it, and it is worse than a silent skip: the step is not
 * merely ungoverned, it is recorded as governed. `governStep` returns
 * `stage: "honoured"` -- a decision arrived and was honoured -- while the
 * rewrite it carried landed nowhere.
 *
 * Routed around `AcsPlugin` for the same reason the result gate's own
 * fail-open block is (result-gate.test.ts): the fix is a load-time refusal,
 * so a test driven through the factory would stop measuring the hazard the
 * moment the gate lands. This calls `loadHookmap` -> `resolveSessionConfig`
 * -> `governStep` -> `applyOpenCodeOutput`, exactly what the hook calls, with
 * the factory out of the path.
 */
describe("a request-gate modify the hookmap gives no way to land -- the measured fail-open", () => {
  // The shipped request gate up to (but not including) its `modify` block --
  // every line the shipped file's. Each test below appends one `modify` block,
  // so the shapes are compared on exactly one variable.
  const REQUEST_GATE_HEAD_FOR_FAILOPEN =
    "host: opencode\n" +
    "hooks:\n" +
    "  tool.execute.before:\n" +
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
    "          refuse.denied: { value: true }\n" +
    "          refuse.reason: { from: reasoning, type: string }\n";

  const MODIFY_WITHOUT_A_SINK =
    REQUEST_GATE_HEAD_FOR_FAILOPEN +
    "      modify:\n" +
    "        output:\n" +
    "          reason.text: { from: reasoning, type: string }\n";

  it("renders nothing, applies nothing, and is audited as honoured while the secret survives in live.args", async () => {
    const hookmapPath = join(SCRATCH_DIR, "request-modify-without-a-sink.yaml");
    writeFileSync(hookmapPath, MODIFY_WITHOUT_A_SINK);
    // Loads clean: `assertRenderableDecisions` requires only a non-empty
    // `output` block whose every field names a `value` or a `from`.
    const hookmap: Hookmap = loadHookmap(hookmapPath);

    const sessionID = "ses-request-gate-modify-no-sink";
    // The same command the shipped-hookmap `modify` test above rewrites to
    // "echo [REDACTED]" -- so the Guardian's answer here is that identical
    // decision, carrying that identical `applied_input`.
    const SECRET_COMMAND = "echo ghp_ABCDEF123456";
    const args = { command: SECRET_COMMAND };

    const client = createGuardianClient(guardian.url);
    const session = await resolveSessionConfig(
      { guardian: client, agentId: hookmap.host, sessionId: toSessionUuid(sessionID), timeoutMs: DEFAULT_TIMEOUT_MS },
      createMemorySessionConfigStore(),
    );
    const governed = await governStep({
      hookEventName: "tool.execute.before",
      payload: { tool: TOOL, session_id: sessionID, callID: "c1", args },
      hookmap,
      guardian: client,
      session,
      sessionId: sessionID,
      audit: NULL_AUDIT_SINK,
      // What `runExchange` passes: the tool this exchange already scoped on.
      // These fixtures declare `tools: [bash]`, and a gate that declares a
      // list refuses a caller that names no tool.
      scopedTool: TOOL,
    });

    // A REAL modify, and the rewrite it carries is right there on the decision.
    expect(governed.decision?.decision).toBe("modify");
    expect((governed.decision as { applied_input?: Record<string, unknown> }).applied_input).toEqual({
      command: "echo [REDACTED]",
    });

    // The part that makes this worse than silent: `stage: "honoured"` is what
    // an audit entry for this step would record -- a decision that arrived
    // and was honoured -- and nothing was applied. The audit trail is not
    // merely missing the fault; it asserts the opposite of it.
    expect(governed.stage).toBe("honoured");

    // A reason and nothing else: `reason.text` renders the sentence the
    // Guardian composed for this redaction, and no field able to land the
    // rewrite is declared. The explanation arrives; the redaction does not.
    expect(governed.output).toEqual({
      reason: {
        text:
          "A secret in this step's arguments was replaced before it ran. " +
          "Policy: redaction_applied, from AGT's stock bundle (agt_stock).",
      },
    });

    expect(() => applyOpenCodeOutput(governed.output, { gate: "request", args })).not.toThrow();
    // The command runs unredacted.
    expect(args.command).toBe(SECRET_COMMAND);
  });

  /**
   * Runs the same chain for one `modify` output block, and reports what the
   * applier did to the live args -- so the three shapes below are compared on
   * exactly one variable.
   */
  async function modifyThrough(
    modifyBlock: string,
    fixtureName: string,
    sessionID: string,
  ): Promise<{ output: Record<string, unknown>; args: { command: string }; threw: unknown }> {
    const hookmapPath = join(SCRATCH_DIR, fixtureName);
    writeFileSync(hookmapPath, REQUEST_GATE_HEAD_FOR_FAILOPEN + modifyBlock);
    const hookmap: Hookmap = loadHookmap(hookmapPath);
    const args = { command: "echo ghp_ABCDEF123456" };
    const client = createGuardianClient(guardian.url);
    const session = await resolveSessionConfig(
      { guardian: client, agentId: hookmap.host, sessionId: toSessionUuid(sessionID), timeoutMs: DEFAULT_TIMEOUT_MS },
      createMemorySessionConfigStore(),
    );
    const governed = await governStep({
      hookEventName: "tool.execute.before",
      payload: { tool: TOOL, session_id: sessionID, callID: "c1", args },
      hookmap,
      guardian: client,
      session,
      sessionId: sessionID,
      audit: NULL_AUDIT_SINK,
      // What `runExchange` passes: the tool this exchange already scoped on.
      // These fixtures declare `tools: [bash]`, and a gate that declares a
      // list refuses a caller that names no tool.
      scopedTool: TOOL,
    });
    expect(governed.decision?.decision).toBe("modify");
    let threw: unknown;
    try {
      applyOpenCodeOutput(governed.output, { gate: "request", args });
    } catch (error) {
      threw = error;
    }
    return { output: governed.output as Record<string, unknown>, args, threw };
  }

  // The request gate's own copies of the two shapes `declaresSinkFrom`
  // accepts while checking only what the sink is named, never whether the
  // field can actually render.
  it("modify declaring args with type: string renders {} -- applied_input is an object, so the type filter drops it", async () => {
    const { output, args, threw } = await modifyThrough(
      "      modify:\n" + "        output:\n" + "          args: { from: applied_input, type: string }\n",
      "request-modify-type-string.yaml",
      "ses-request-gate-modify-type-string",
    );
    expect(output).toEqual({});
    expect(threw).toBeUndefined();
    expect(args.command).toBe("echo ghp_ABCDEF123456");
  });

  it("modify declaring a literal args BESIDE the right from: lands the author's own command on every rewrite", async () => {
    // Worse than a no-op at this gate: `renderDecision` prefers `value` and
    // never reads `applied_input`, so the applier merges a command the
    // Guardian never chose -- identical on every modify this deployment ever
    // sees, and the actual rewrite never lands.
    const { output, args, threw } = await modifyThrough(
      "      modify:\n" +
        "        output:\n" +
        '          args: { value: { command: "echo pwned" }, from: applied_input }\n',
      "request-modify-value-beside-from.yaml",
      "ses-request-gate-modify-value-beside-from",
    );
    expect(output).toEqual({ args: { command: "echo pwned" } });
    expect(threw).toBeUndefined();
    expect(args.command).toBe("echo pwned");
    expect(args.command).not.toBe("echo [REDACTED]");
  });

  // A `modify` an author chose to map to a refusal instead of a rewrite.
  // Blocking the tool is strictly more conservative than rewriting its
  // arguments -- the command never runs at all -- and it is the shipped
  // hookmap's own idiom for `ask`/`defer` at this gate. Not a silent no-op,
  // so not this gate's to refuse.
  //
  // The request gate's own table entry is wrong whenever the entry declares
  // `outputs:` instead of `arguments:`. `governStep` builds its output
  // location off the entry's shape, so a request hook declaring `outputs:`
  // gets one -- and `resolveModify` (decision-modify.ts) then fills
  // `applied_output` instead of `applied_input`. The sink this gate demands
  // (`args: { from: applied_input }`) is correct, declared, and unfillable.
  it("a request hook declaring outputs: gets applied_output, not applied_input -- the mandated args sink renders nothing", async () => {
    const hookmapPath = join(SCRATCH_DIR, "request-hook-with-outputs.yaml");
    writeFileSync(
      hookmapPath,
      "host: opencode\n" +
        "hooks:\n" +
        "  tool.execute.before:\n" +
        "    acs_method: steps/toolCallResult\n" +
        "    tool_name: $.tool\n" +
        "    outputs:\n" +
        "      from: $.args.command\n" +
        "      within: $.args\n" +
        "    exit_status: { literal: success }\n" +
        "    decisions:\n" +
        "      allow:\n" +
        "        output:\n" +
        "          reason.text: { from: reasoning, type: string }\n" +
        "      deny:\n" +
        "        output:\n" +
        "          refuse.denied: { value: true }\n" +
        "      modify:\n" +
        "        output:\n" +
        "          args: { from: applied_input }\n" +
        "          reason.text: { from: reasoning, type: string }\n",
    );
    const hookmap: Hookmap = loadHookmap(hookmapPath);
    const sessionID = "ses-request-hook-with-outputs";
    const args = { command: "echo ghp_ABCDEF123456" };
    const client = createGuardianClient(guardian.url);
    const session = await resolveSessionConfig(
      { guardian: client, agentId: hookmap.host, sessionId: toSessionUuid(sessionID), timeoutMs: DEFAULT_TIMEOUT_MS },
      createMemorySessionConfigStore(),
    );
    const governed = await governStep({
      hookEventName: "tool.execute.before",
      payload: { tool: TOOL, session_id: sessionID, callID: "c1", args },
      hookmap,
      guardian: client,
      session,
      sessionId: sessionID,
      audit: NULL_AUDIT_SINK,
      // What `runExchange` passes: the tool this exchange already scoped on.
      // These fixtures declare `tools: [bash]`, and a gate that declares a
      // list refuses a caller that names no tool.
      scopedTool: TOOL,
    });

    expect(governed.decision?.decision).toBe("modify");
    // The rewrite arrived on the OTHER field.
    const decision = governed.decision as { applied_input?: unknown; applied_output?: unknown };
    expect(decision.applied_input).toBeUndefined();
    expect(decision.applied_output).toBeDefined();

    // So the mandated sink renders nothing, and the audit says honoured.
    expect(Object.hasOwn(governed.output, "args")).toBe(false);
    expect(governed.stage).toBe("honoured");
    expect(() => applyOpenCodeOutput(governed.output, { gate: "request", args })).not.toThrow();
    expect(args.command).toBe("echo ghp_ABCDEF123456");
  });

  // The adapter tells `governStep` the tool `runExchange` scoped on, so the
  // step is governed -- and the envelope that goes out names the command as
  // the tool, because `tool_name` is what `buildEnvelope` reads for the wire.
  // That is a wrong question asked, not a question skipped, and it is what
  // `assertEntryMatchesGate` still refuses at load time (acs-plugin.test.ts's
  // own gate for this hookmap).
  it("a tool_name path pointing away from $.tool no longer skips the step -- it asks the Guardian about the command", async () => {
    const hookmapPath = join(SCRATCH_DIR, "request-tool-name-diverges.yaml");
    writeFileSync(
      hookmapPath,
      "host: opencode\n" +
        "hooks:\n" +
        "  tool.execute.before:\n" +
        "    acs_method: steps/toolCallRequest\n" +
        "    tool_name: $.args.command\n" +
        "    arguments: $.args\n" +
        "    tools: [bash]\n" +
        "    decisions:\n" +
        "      allow:\n" +
        "        output:\n" +
        "          reason.text: { from: reasoning, type: string }\n" +
        "      deny:\n" +
        "        output:\n" +
        "          refuse.denied: { value: true }\n" +
        "          refuse.reason: { from: reasoning, type: string }\n",
    );
    const hookmap: Hookmap = loadHookmap(hookmapPath);
    const sessionID = "ses-request-tool-name-diverges";
    const args = { command: "rm -rf /" };
    const client = createGuardianClient(guardian.url);
    const session = await resolveSessionConfig(
      { guardian: client, agentId: hookmap.host, sessionId: toSessionUuid(sessionID), timeoutMs: DEFAULT_TIMEOUT_MS },
      createMemorySessionConfigStore(),
    );

    const payload = { tool: TOOL, session_id: sessionID, callID: "c1", args };

    // The shim's own early check says this tool is governed -- it passes
    // `input.tool`, which the `tools` list names -- and it is now the value
    // `governStep` is told, so there is no second answer for it to disagree
    // with.
    expect(governsTool(hookmap, "tool.execute.before", TOOL)).toBe(true);

    // What this hookmap still costs, and the reason the load gate that
    // refuses it is not redundant: `tool_name` is what names the tool on the
    // wire, so the policy runtime is asked about a "tool" called `rm -rf /`
    // -- one this deployment never registered -- while the tool that
    // actually runs is never named to it.
    const envelope = buildEnvelope("tool.execute.before", payload, hookmap) as {
      params: { payload: { tool: { name: string } } };
    };
    expect(envelope.params.payload.tool.name).toBe("rm -rf /");

    const governed = await governStep({
      hookEventName: "tool.execute.before",
      payload,
      hookmap,
      guardian: client,
      session,
      sessionId: sessionID,
      audit: NULL_AUDIT_SINK,
      // What `runExchange` passes -- the tool this exchange already scoped on.
      scopedTool: TOOL,
    });

    // Governed, not skipped: a real decision arrived from the real Guardian
    // for this step.
    expect(governed.stage).toBe("honoured");

    // What the decision is, not merely that one arrived: several comments in
    // this tree say the residual here is over-blocking rather than a bypass,
    // and the only thing making that true is what the shipped
    // policy/manifest.yaml answers for a tool it never registered. Left as "a
    // decision arrived", a later permissive default would turn this envelope
    // into an `allow`, this test would stay green, and every one of those
    // claims would silently become false.
    //
    // The reason code is the half that says why it is over-blocking and not
    // governance: `runtime_error:tool_unknown`, from `agt_stock`. The name on
    // the wire is the command, so this deny is the tool registry refusing a
    // tool it does not know -- this deployment's own `rm -rf /` rule was
    // never consulted, because the envelope never said `bash`. A plain
    // `toBe("deny")` would also pass if the authored rule had answered, which
    // is the outcome this hookmap does not produce and must not be read as
    // producing.
    expect({
      decision: governed.decision?.decision,
      reasonCodes: (governed.decision as { reason_codes?: string[] } | null)?.reason_codes,
    }).toEqual({ decision: "deny", reasonCodes: ["runtime_error:tool_unknown"] });
  });

  // A declared decision name the tables do not know is silently unchecked,
  // because `assertDecisionsCanAct` iterates the table and not the
  // hookmap's own declared decisions. `expectationFor` throws on an unknown
  // hook; the identical skip one level down stays silent.
  //
  // Needs a non-conformant Guardian to reach at runtime, which is why it
  // ranks below the others -- but declaring the inert entry is strictly
  // worse than not declaring it: without the entry `renderDecision` throws,
  // `governStep` catches it, and the posture answers it, audited. With it,
  // nothing happens and nothing is recorded. Constructed decision, same
  // reason as the `ask`/`defer` cases in result-gate.test.ts.
  it("a declared decision name the gate's tables do not know renders an inert reason and applies nothing", () => {
    const hookmapPath = join(SCRATCH_DIR, "request-unknown-decision.yaml");
    writeFileSync(
      hookmapPath,
      "host: opencode\n" +
        "hooks:\n" +
        "  tool.execute.before:\n" +
        "    acs_method: steps/toolCallRequest\n" +
        "    tool_name: $.tool\n" +
        "    arguments: $.args\n" +
        "    decisions:\n" +
        "      allow:\n" +
        "        output:\n" +
        "          reason.text: { from: reasoning, type: string }\n" +
        "      deny:\n" +
        "        output:\n" +
        "          refuse.denied: { value: true }\n" +
        "      block:\n" +
        "        output:\n" +
        "          reason.text: { from: reasoning, type: string }\n",
    );
    const hookmap: Hookmap = loadHookmap(hookmapPath);
    const args = { command: "rm -rf /" };

    const rendered = renderDecision(
      "tool.execute.before",
      { decision: "block", reasoning: "blocked" } as unknown as Parameters<typeof renderDecision>[1],
      hookmap,
    );
    expect(rendered).toEqual({ reason: { text: "blocked" } });
    expect(() => applyOpenCodeOutput(rendered, { gate: "request", args })).not.toThrow();
    expect(args.command).toBe("rm -rf /");

    // Without the inert entry the same decision fails loudly instead -- which
    // is what makes declaring it strictly worse than leaving it out.
    const withoutPath = join(SCRATCH_DIR, "request-no-unknown-decision.yaml");
    writeFileSync(
      withoutPath,
      "host: opencode\n" +
        "hooks:\n" +
        "  tool.execute.before:\n" +
        "    acs_method: steps/toolCallRequest\n" +
        "    tool_name: $.tool\n" +
        "    arguments: $.args\n" +
        "    decisions:\n" +
        "      allow:\n" +
        "        output:\n" +
        "          reason.text: { from: reasoning, type: string }\n" +
        "      deny:\n" +
        "        output:\n" +
        "          refuse.denied: { value: true }\n",
    );
    expect(() =>
      renderDecision(
        "tool.execute.before",
        { decision: "block", reasoning: "blocked" } as unknown as Parameters<typeof renderDecision>[1],
        loadHookmap(withoutPath),
      ),
    ).toThrow(/no decisions entry for ACS decision "block"/);
  });

  it("a request-gate modify mapped to an unconditional refusal throws before the tool runs, and applies nothing", async () => {
    const { output, args, threw } = await modifyThrough(
      "      modify:\n" +
        "        output:\n" +
        "          refuse.denied: { value: true }\n" +
        "          refuse.reason: { from: reasoning, type: string }\n",
      "request-modify-as-refusal.yaml",
      "ses-request-gate-modify-as-refusal",
    );
    expect(output).toEqual({
      refuse: {
        denied: true,
        reason:
          "A secret in this step's arguments was replaced before it ran. " +
          "Policy: redaction_applied, from AGT's stock bundle (agt_stock).",
      },
    });
    expect(threw).toBeInstanceOf(Error);
    // Nothing half-applied: pass 2a throws before any assignment.
    expect(args.command).toBe("echo ghp_ABCDEF123456");
  });
});
