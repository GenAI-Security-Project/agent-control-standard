/**
 * `AcsPlugin`'s own load-time contract, in isolation from OpenCode -- a
 * plain async factory a test can call directly (acs-plugin.ts's own header
 * states why `ACS_HOOKMAP_PATH` is read inside the factory rather than at
 * module scope, exactly so this works). Scoped to what nothing else in this
 * suite exercises: that the factory itself, not only `applyOpenCodeOutput` in
 * isolation (apply-opencode-output.test.ts) or the shipped hookmap's static
 * shape (hookmap.test.ts), refuses to register a hookmap
 * `assertHostAcceptsEveryDecision` would otherwise let govern nothing.
 *
 * Both gates are covered. The request-gate half is a `deny`/`ask`/`defer`
 * that can render empty and therefore cannot refuse. The result-gate half is
 * a `deny`/`modify` that declares no `result` sink and therefore cannot
 * withhold -- the fail-open itself is measured, on the real chain against a
 * live Guardian, in result-gate.test.ts's own "a result-gate decision the
 * hookmap gives no way to withhold with" block; what is pinned here is that
 * such a hookmap never registers.
 */
import { afterAll, describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { AcsPlugin } from "../acs-plugin.ts";

const SCRATCH_DIR = mkdtempSync(join(tmpdir(), "acs-plugin-test-"));

afterAll(() => {
  rmSync(SCRATCH_DIR, { recursive: true, force: true });
});

/** Runs `AcsPlugin` with `ACS_HOOKMAP_PATH` (and nothing else host-specific)
 * pointed at `hookmapPath`, restoring whatever `ACS_HOOKMAP_PATH` was
 * beforehand regardless of outcome -- this factory reads the env var itself,
 * so nothing here needs to touch module state. */
async function runPlugin(hookmapPath: string): Promise<void> {
  const previous = process.env.ACS_HOOKMAP_PATH;
  process.env.ACS_HOOKMAP_PATH = hookmapPath;
  try {
    // AcsPlugin's own factory reads neither of its own two parameters
    // (PluginInput, PluginOptions) -- true regardless of which of its
    // returned gate hooks are wired -- so a placeholder satisfies the
    // `Plugin` type without needing a real PluginInput.
    await AcsPlugin({} as never);
  } finally {
    if (previous === undefined) {
      delete process.env.ACS_HOOKMAP_PATH;
    } else {
      process.env.ACS_HOOKMAP_PATH = previous;
    }
  }
}

describe("AcsPlugin's load-time gate", () => {
  it("registers cleanly against the shipped hookmap", async () => {
    // Sanity: the gate below does not false-positive on the real, shipped
    // opencode.hookmap.yaml, which declares `refuse.denied: { value: true }`
    // on deny/ask/defer precisely so this passes.
    const shipped = new URL("../opencode.hookmap.yaml", import.meta.url).pathname;
    await expect(runPlugin(shipped)).resolves.toBeUndefined();
  });

  it("refuses to register a hookmap whose request-gate deny declares only a conditional (from:) output field", async () => {
    const hookmapPath = join(SCRATCH_DIR, "from-only-deny.yaml");
    // The real hookmap's request gate with refuse.denied's unconditional
    // value: sibling removed -- deny is built only from refuse.reason, a
    // from: field, exactly the shape measured to render `{}` when nothing
    // enforces otherwise (this function's own doc comment, and
    // opencode.hookmap.yaml's header, both record the measurement).
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
        "          refuse.reason: { from: reasoning, type: string }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(
      /declares no unconditional "value:" output field/,
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/decisions\.deny/);
  });

  // The gate refuses any deny/ask/defer entry with a `{value: ...}` field
  // anywhere in its output block other than under `refuse` -- the one key
  // `applyOpenCodeOutput` (apply-opencode-output.ts) actually throws on. Both
  // reproductions below were measured live against the real `AcsPlugin`,
  // `applyOpenCodeOutput`, `loadHookmap`, and a stub Guardian returning a
  // genuine `{"decision":"deny"}`: without this gate, the hookmap loads
  // cleanly, `tool.execute.before` returns normally with no throw,
  // `live.args` is untouched, and no audit entry is written.
  it("refuses to register a hookmap whose deny declares an unconditional value: field outside refuse (reason.text)", async () => {
    const hookmapPath = join(SCRATCH_DIR, "value-outside-refuse-reason.yaml");
    // The author "answers" this gate at the wrong key: reason.text is
    // unconditional, but applyOpenCodeOutput never reads reason to throw -- it
    // is declared-inert (pass 2b). refuse.reason alone is a from: field and
    // can still render nothing.
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
        '          reason.text: { value: "denied by policy" }\n' +
        "          refuse.reason: { from: reasoning, type: string }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(
      /declares no unconditional "value:" output field under "refuse"/,
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/decisions\.deny/);
  });

  it("refuses to register a hookmap whose deny declares an unconditional value: field outside refuse (args, with a rewrite attached)", async () => {
    const hookmapPath = join(SCRATCH_DIR, "value-outside-refuse-args.yaml");
    // Same hole, with a rewrite riding along: args merges onto live.args
    // regardless of whether refuse ever renders, so this variant both fails
    // to refuse and applies an unrelated argument rewrite.
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
        '          args: { value: { command: "echo replaced" } }\n' +
        "          refuse.reason: { from: reasoning, type: string }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(
      /declares no unconditional "value:" output field under "refuse"/,
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/decisions\.deny/);
  });
});

/**
 * The result-gate half -- the gate that holds the secret, and the one
 * `assertRefusalRendersUnconditionally` skipped entirely because it only ever
 * looked at entries declaring `arguments`.
 *
 * The fail-open these refuse is not assumed here: result-gate.test.ts
 * measures it end to end, against a live Guardian, with `AcsPlugin`
 * deliberately out of the path so the gate cannot hide it. These tests pin
 * the other half -- that a hookmap of that class never registers in the
 * first place.
 */
describe("AcsPlugin's load-time gate, at the result gate", () => {
  // The shipped result gate, minus the one line that lands a withholding.
  // Every other line is opencode.hookmap.yaml's own.
  const RESULT_GATE_HEAD =
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
    "          reason.text: { from: reasoning, type: string }\n";

  it("refuses to register a hookmap whose result-gate deny declares only reason.text", async () => {
    const hookmapPath = join(SCRATCH_DIR, "result-deny-without-a-sink.yaml");
    writeFileSync(
      hookmapPath,
      RESULT_GATE_HEAD +
        "      deny:\n" +
        "        output:\n" +
        "          reason.text: { from: reasoning, type: string }\n" +
        "      modify:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n",
    );
    // Names the file, the hook, the decision, and what to add -- the same
    // four the request-gate half's message names -- plus the paths this
    // decision does declare, so a near-miss is legible rather than merely
    // refused.
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/declares no "result" output field at all/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/\["reason\.text"\]/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/result-deny-without-a-sink\.yaml/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/hooks\.tool\.execute\.after\.decisions\.deny/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/EITHER declare 'result: \{ from: applied_output \}'/);
    // Both honest outcomes named -- the gate accepts either, so the message
    // must offer both.
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/OR declare an unconditional refusal/);
  });

  it("refuses the same for a result-gate modify, not only deny", async () => {
    const hookmapPath = join(SCRATCH_DIR, "result-modify-without-a-sink.yaml");
    writeFileSync(
      hookmapPath,
      RESULT_GATE_HEAD +
        "      deny:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n" +
        "      modify:\n" +
        "        output:\n" +
        "          reason.text: { from: reasoning, type: string }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/declares no "result" output field at all/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/decisions\.modify/);
  });

  it("refuses a result-gate deny that names the leaf (result.output) instead of the container", async () => {
    // Not an "already covered by the other test" duplicate: this hookmap does
    // declare a path whose leading segment is `result`, so a gate written the
    // way the request-gate half is written -- leading segment, not exact key
    // -- would accept it. Measured (result-gate.test.ts): it merges the whole
    // patched container into `live.result.output` and never writes the mirror
    // at all.
    const hookmapPath = join(SCRATCH_DIR, "result-deny-naming-the-leaf.yaml");
    writeFileSync(
      hookmapPath,
      RESULT_GATE_HEAD +
        "      deny:\n" +
        "        output:\n" +
        "          result.output: { from: applied_output }\n" +
        "      modify:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/declares no "result" output field at all/);
    // The near-miss made legible: the message prints the path that looks like
    // the sink.
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/"result\.output"/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/NOT a leaf under it/);
  });

  // A rule that checked only whether the key `result` is present, never what
  // it is sourced from, would load this hookmap clean. Measured on the real
  // chain (result-gate.test.ts): a real deny renders no `result` key at all,
  // applies nothing, throws nothing, and `rm -rf /` is delivered in the leaf
  // and the mirror.
  it("refuses a result-gate deny declaring result sourced from applied_input -- the right key, the wrong field", async () => {
    const hookmapPath = join(SCRATCH_DIR, "result-deny-wrong-source.yaml");
    writeFileSync(
      hookmapPath,
      RESULT_GATE_HEAD +
        "      deny:\n" +
        "        output:\n" +
        "          result: { from: applied_input }\n" +
        "          reason.text: { from: reasoning, type: string }\n" +
        "      modify:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n",
    );
    // The wrong-source message is not the absent-key one: it prints the
    // declared field object verbatim, so the near-miss is visible.
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/does not source it from "applied_output"/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/\{"from":"applied_input"\}/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/result-deny-wrong-source\.yaml/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/hooks\.tool\.execute\.after\.decisions\.deny/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/EITHER declare 'result: \{ from: applied_output \}'/);
  });

  it("refuses a result-gate deny declaring result as a literal value: -- a fixed answer the Guardian never chose", async () => {
    // The other way to declare the key without honouring the decision. Refused
    // deliberately, not by accident -- see `declaresSinkFrom`'s own doc comment
    // for why a literal here is a hardcoded answer wearing governance's
    // clothes.
    const hookmapPath = join(SCRATCH_DIR, "result-deny-literal-sink.yaml");
    writeFileSync(
      hookmapPath,
      RESULT_GATE_HEAD +
        "      deny:\n" +
        "        output:\n" +
        '          result: { value: { output: "withheld" } }\n' +
        "      modify:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/renders that LITERAL and never reads "from" at all/);
  });

  // `ask`/`defer` at this gate are held to exactly what `deny` is held to.
  // `withholdsAtResultGate` (result-output.ts) admits every disposition but
  // `allow` and `modify`, so `withResultOutput` attaches `applied_output` for
  // all three and the sink rule governs all three. Declaring one with only
  // `reason.text` is therefore the same fault as declaring `deny` that way:
  // the applier applies nothing, throws nothing, and the tool's own output is
  // delivered in the leaf and its mirror.
  it.each(["ask", "defer"] as const)(
    "refuses a result-gate %s that declares no sink -- declared-but-unlandable, not merely undeclared",
    async (decisionName) => {
      const hookmapPath = join(SCRATCH_DIR, `result-${decisionName}-without-a-sink.yaml`);
      writeFileSync(
        hookmapPath,
        RESULT_GATE_HEAD +
          "      deny:\n" +
          "        output:\n" +
          "          result: { from: applied_output }\n" +
          "      modify:\n" +
          "        output:\n" +
          "          result: { from: applied_output }\n" +
          `      ${decisionName}:\n` +
          "        output:\n" +
          "          reason.text: { from: reasoning, type: string }\n",
      );
      await expect(runPlugin(hookmapPath)).rejects.toThrow(
        /"result" is the ONLY key that withholds anything/,
      );
      await expect(runPlugin(hookmapPath)).rejects.toThrow(new RegExp(`decisions\\.${decisionName}`));
      // Refused for the fault it actually has, and told both ways out -- the
      // sink or an unconditional refusal -- rather than the single shape that
      // was all this decision could take before it carried anything.
      await expect(runPlugin(hookmapPath)).rejects.toThrow(/OR declare an\s+unconditional refusal/);
    },
  );

  // The inverse of the fault above, and the one that used to be refused. When
  // `withResultOutput` attached `applied_output` for `deny` alone, this exact
  // declaration -- the one the sink rule demands -- rendered no `result` key
  // and delivered the secret; the gate refused it for that reason. Now it is
  // the correct declaration, and refusing it would refuse the fix. Measured
  // withholding leaf and mirror in result-gate.test.ts.
  it.each(["ask", "defer"] as const)(
    "accepts a result-gate %s declaring the result sink -- withResultOutput fills it",
    async (decisionName) => {
      const hookmapPath = join(SCRATCH_DIR, `result-${decisionName}-mandated-sink.yaml`);
      writeFileSync(
        hookmapPath,
        RESULT_GATE_HEAD +
          "      deny:\n" +
          "        output:\n" +
          "          result: { from: applied_output }\n" +
          "      modify:\n" +
          "        output:\n" +
          "          result: { from: applied_output }\n" +
          `      ${decisionName}:\n` +
          "        output:\n" +
          "          result: { from: applied_output }\n",
      );
      await expect(runPlugin(hookmapPath)).resolves.toBeUndefined();
    },
  );

  it.each(["ask", "defer"] as const)(
    "accepts a result-gate %s that refuses instead -- the one shape it can honestly take",
    async (decisionName) => {
      const hookmapPath = join(SCRATCH_DIR, `result-${decisionName}-refusal-only.yaml`);
      writeFileSync(
        hookmapPath,
        RESULT_GATE_HEAD +
          "      deny:\n" +
          "        output:\n" +
          "          result: { from: applied_output }\n" +
          "      modify:\n" +
          "        output:\n" +
          "          result: { from: applied_output }\n" +
          `      ${decisionName}:\n` +
          "        output:\n" +
          "          refuse.denied: { value: true }\n" +
          "          refuse.reason: { from: reasoning, type: string }\n",
      );
      await expect(runPlugin(hookmapPath)).resolves.toBeUndefined();
    },
  );

  // The same unsatisfiable-by-construction fault reached from the entry, and
  // this one hits `deny`.
  it("refuses a result hook that declares no outputs block -- every sink there is unfillable by construction", async () => {
    const hookmapPath = join(SCRATCH_DIR, "result-hook-without-outputs.yaml");
    // A perfectly-declared sink on a `deny`. The entry is what is wrong: it
    // declares `arguments:` at the result hook, so governStep builds no output
    // location and withResultOutput no-ops for every decision.
    writeFileSync(
      hookmapPath,
      "host: opencode\n" +
        "hooks:\n" +
        "  tool.execute.after:\n" +
        "    acs_method: steps/toolCallRequest\n" +
        "    tool_name: $.tool\n" +
        "    arguments: $.args\n" +
        "    decisions:\n" +
        "      allow:\n" +
        "        output:\n" +
        "          reason.text: { from: reasoning, type: string }\n" +
        "      deny:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/declares no usable "outputs"/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/withResultOutput .* returns every decision untouched/);
    // Blames the entry, not the correctly-declared decision.
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/"hooks\.tool\.execute\.after" declares no usable/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/result-hook-without-outputs\.yaml/);
  });

  it("still asks nothing of an ask/defer the hookmap does not declare at all", async () => {
    // A decision the hookmap never declares has nothing here to check.
    // `renderDecision` throws on an arriving one, `governStep` catches it,
    // and the deployment's posture answers it -- audited either way. This is
    // the shipped file's own shape, and it must keep loading.
    const hookmapPath = join(SCRATCH_DIR, "result-gate-no-ask-no-defer.yaml");
    writeFileSync(
      hookmapPath,
      RESULT_GATE_HEAD +
        "      deny:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n" +
        "      modify:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n",
    );
    await expect(runPlugin(hookmapPath)).resolves.toBeUndefined();
  });

  // `declaresSinkFrom` checks what the sink is named, not whether the
  // declaration can actually render. Both shapes below name `result` and
  // name `applied_output`, and both were measured (result-gate.test.ts) to
  // deliver the secret in leaf and mirror.
  it("refuses a result-gate deny whose sink declares type: string -- applied_output is an object, so it never renders", async () => {
    const hookmapPath = join(SCRATCH_DIR, "result-deny-type-string.yaml");
    writeFileSync(
      hookmapPath,
      RESULT_GATE_HEAD +
        "      deny:\n" +
        "        output:\n" +
        "          result: { from: applied_output, type: string }\n" +
        "      modify:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/declares a "type" of "string"/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/typeof filter/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/hooks\.tool\.execute\.after\.decisions\.deny/);
  });

  it("refuses a result-gate deny whose sink declares a literal BESIDE the right from:", async () => {
    // renderDecision checks for `value` first and never reads `from`, so this
    // renders `{"result":{}}` -- a key present, nothing landed.
    const hookmapPath = join(SCRATCH_DIR, "result-deny-value-beside-from.yaml");
    writeFileSync(
      hookmapPath,
      RESULT_GATE_HEAD +
        "      deny:\n" +
        "        output:\n" +
        "          result: { value: {}, from: applied_output }\n" +
        "      modify:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/renders that LITERAL and never reads "from" at all/);
  });

  it("accepts a result-gate sink declaring type: object -- the one type that can match", async () => {
    // Not over-refusal by accident: `type` is a typeof filter and
    // `applied_output` is an object, so this declaration renders exactly as
    // the untyped one does.
    const hookmapPath = join(SCRATCH_DIR, "result-deny-type-object.yaml");
    writeFileSync(
      hookmapPath,
      RESULT_GATE_HEAD +
        "      deny:\n" +
        "        output:\n" +
        "          result: { from: applied_output, type: object }\n" +
        "      modify:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n",
    );
    await expect(runPlugin(hookmapPath)).resolves.toBeUndefined();
  });

  // The gate's rule is "land it or unconditionally refuse it", because both
  // are honest outcomes and only the silent no-op is not. On this host
  // over-refusal is not free: a load-time throw leaves the plugin unloaded
  // and the session completely ungoverned, which is strictly worse than a
  // conservative mapping this gate did not anticipate. The throw itself is
  // measured in result-gate.test.ts -- these hookmaps stop the tool, they do
  // not no-op.
  it.each(["deny", "modify", "ask", "defer"] as const)(
    "accepts a result-gate %s mapped to an unconditional refusal instead of a replacement",
    async (decisionName) => {
      const hookmapPath = join(SCRATCH_DIR, `result-${decisionName}-as-refusal.yaml`);
      const sink = (name: string) =>
        name === decisionName
          ? `      ${name}:\n        output:\n          refuse.denied: { value: true }\n`
          : `      ${name}:\n        output:\n          result: { from: applied_output }\n`;
      writeFileSync(hookmapPath, RESULT_GATE_HEAD + sink("deny") + sink("modify") + (decisionName === "ask" || decisionName === "defer" ? sink(decisionName) : ""));
      await expect(runPlugin(hookmapPath)).resolves.toBeUndefined();
    },
  );

  it("accepts a result gate that declares the sink on both deny and modify", async () => {
    // The shape the shipped hookmap uses, in isolation from it -- so this
    // gate's accept case is pinned by something other than "the shipped file
    // happens to pass", which the first test in this file already covers.
    const hookmapPath = join(SCRATCH_DIR, "result-gate-with-both-sinks.yaml");
    writeFileSync(
      hookmapPath,
      RESULT_GATE_HEAD +
        "      deny:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n" +
        "          reason.text: { from: reasoning, type: string }\n" +
        "      modify:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n" +
        "          reason.text: { from: reasoning, type: string }\n",
    );
    await expect(runPlugin(hookmapPath)).resolves.toBeUndefined();
  });
});

/**
 * The request gate's `modify` rule -- its own rule, not the refusal rule its
 * `deny`/`ask`/`defer` siblings get: a `modify` asks for the step to run,
 * rewritten, so what it needs is a sink for the rewrite, exactly as a
 * result-gate `deny` needs one for the withholding.
 *
 * The fail-open is measured in request-gate.test.ts, against a live Guardian,
 * with `AcsPlugin` out of the path -- including the part that makes it worse
 * than silent: `governStep` returns `stage: "honoured"`, so the audit trail
 * records the rewrite as honoured while nothing was applied.
 */
describe("AcsPlugin's load-time gate, for a request-gate modify", () => {
  const REQUEST_GATE_HEAD =
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

  it("refuses a modify that declares only reason.text", async () => {
    const hookmapPath = join(SCRATCH_DIR, "request-modify-without-a-sink.yaml");
    writeFileSync(
      hookmapPath,
      REQUEST_GATE_HEAD + "      modify:\n" + "        output:\n" + "          reason.text: { from: reasoning, type: string }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/declares no "args" output field at all/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/request-modify-without-a-sink\.yaml/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/hooks\.tool\.execute\.before\.decisions\.modify/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/EITHER declare 'args: \{ from: applied_input \}'/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/OR declare an unconditional refusal/);
    // The audit consequence is in the message, because it is the reason this
    // is a fault rather than a gap.
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/stage "honoured"/);
  });

  it("refuses a modify sourcing args from applied_output -- the result gate's field at the request gate", async () => {
    const hookmapPath = join(SCRATCH_DIR, "request-modify-wrong-source.yaml");
    writeFileSync(
      hookmapPath,
      REQUEST_GATE_HEAD + "      modify:\n" + "        output:\n" + "          args: { from: applied_output }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/does not source it from "applied_input"/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/\{"from":"applied_output"\}/);
  });

  it("refuses a modify naming an argument under args (args.command) rather than the bag itself", async () => {
    const hookmapPath = join(SCRATCH_DIR, "request-modify-naming-a-leaf.yaml");
    writeFileSync(
      hookmapPath,
      REQUEST_GATE_HEAD + "      modify:\n" + "        output:\n" + "          args.command: { from: applied_input }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/declares no "args" output field at all/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/"args\.command"/);
  });

  it("refuses a modify whose args sink declares type: string -- applied_input is an object, so it never renders", async () => {
    const hookmapPath = join(SCRATCH_DIR, "request-modify-type-string.yaml");
    writeFileSync(
      hookmapPath,
      REQUEST_GATE_HEAD + "      modify:\n" + "        output:\n" + "          args: { from: applied_input, type: string }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/declares a "type" of "string"/);
  });

  it("refuses a modify whose args sink declares a literal BESIDE the right from: -- the author's own command on every rewrite", async () => {
    const hookmapPath = join(SCRATCH_DIR, "request-modify-value-beside-from.yaml");
    writeFileSync(
      hookmapPath,
      REQUEST_GATE_HEAD +
        "      modify:\n" +
        "        output:\n" +
        '          args: { value: { command: "echo pwned" }, from: applied_input }\n',
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/renders that LITERAL and never reads "from" at all/);
  });

  it("accepts a modify mapped to an unconditional refusal -- blocking the tool is more conservative than rewriting it", async () => {
    // Measured in request-gate.test.ts: this mapping throws before the tool
    // runs and applies nothing -- an honest outcome, and the shipped
    // hookmap's own idiom for `ask`/`defer` at this very gate.
    const hookmapPath = join(SCRATCH_DIR, "request-modify-as-refusal.yaml");
    writeFileSync(
      hookmapPath,
      REQUEST_GATE_HEAD +
        "      modify:\n" +
        "        output:\n" +
        "          refuse.denied: { value: true }\n" +
        "          refuse.reason: { from: reasoning, type: string }\n",
    );
    await expect(runPlugin(hookmapPath)).resolves.toBeUndefined();
  });

  it("accepts the shipped shape, and asks nothing of a request gate declaring no modify at all", async () => {
    const withModify = join(SCRATCH_DIR, "request-modify-with-sink.yaml");
    writeFileSync(
      withModify,
      REQUEST_GATE_HEAD +
        "      modify:\n" +
        "        output:\n" +
        "          args: { from: applied_input }\n" +
        "          reason.text: { from: reasoning, type: string }\n",
    );
    await expect(runPlugin(withModify)).resolves.toBeUndefined();

    // `modify` is optional -- assertRenderableDecisions requires only allow and
    // deny -- so a hookmap that never declares one has nothing here to check.
    const withoutModify = join(SCRATCH_DIR, "request-no-modify.yaml");
    writeFileSync(withoutModify, REQUEST_GATE_HEAD);
    await expect(runPlugin(withoutModify)).resolves.toBeUndefined();
  });
});

/**
 * The entry-shape and fixed-path rules apply to both gates and are therefore
 * their own block.
 *
 * Every fail-open they close was measured first, routed around `AcsPlugin`,
 * in request-gate.test.ts and result-gate.test.ts. See `GateEntryShape`'s own
 * doc comment (acs-plugin.ts) for each one.
 */
describe("AcsPlugin's load-time gate, on the entry's own shape and paths", () => {
  const REQUEST_DECISIONS =
    "    decisions:\n" +
    "      allow:\n" +
    "        output:\n" +
    "          reason.text: { from: reasoning, type: string }\n" +
    "      deny:\n" +
    "        output:\n" +
    "          refuse.denied: { value: true }\n";
  const RESULT_DECISIONS =
    "    decisions:\n" +
    "      allow:\n" +
    "        output:\n" +
    "          reason.text: { from: reasoning, type: string }\n" +
    "      deny:\n" +
    "        output:\n" +
    "          result: { from: applied_output }\n";

  // A request hook declaring `outputs:` gets an output location, so
  // `resolveModify` fills `applied_output` and the `args` sink this gate
  // demands is unfillable. Measured: stage "honoured", rewrite landed
  // nowhere.
  it("refuses a request hook declaring outputs: instead of arguments:", async () => {
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
        REQUEST_DECISIONS,
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/declares no usable "arguments"/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/fills "applied_output" instead of "applied_input"/);
  });

  it("refuses a request hook declaring both arguments: and outputs:", async () => {
    // `assertRequestGateDeclaresNoOutputs` (build-envelope.ts) already refuses
    // this one upstream -- asserted here so the two checks' division stays
    // visible, and so this gate's own coverage does not depend on which fires
    // first.
    const hookmapPath = join(SCRATCH_DIR, "request-hook-with-both.yaml");
    writeFileSync(
      hookmapPath,
      "host: opencode\n" +
        "hooks:\n" +
        "  tool.execute.before:\n" +
        "    acs_method: steps/toolCallRequest\n" +
        "    tool_name: $.tool\n" +
        "    arguments: $.args\n" +
        "    outputs:\n" +
        "      from: $.args.command\n" +
        "      within: $.args\n" +
        "    exit_status: { literal: success }\n" +
        REQUEST_DECISIONS,
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow();
  });

  const resultHook = (from: string, within: string) =>
    "host: opencode\n" +
    "hooks:\n" +
    "  tool.execute.after:\n" +
    "    acs_method: steps/toolCallResult\n" +
    "    tool_name: $.tool\n" +
    "    outputs:\n" +
    `      from: ${from}\n` +
    `      within: ${within}\n` +
    "    exit_status: { from: $.result.metadata.exit }\n" +
    RESULT_DECISIONS;

  // `outputs.within` must name the object this shim hands the applier. Each
  // case below leaves `outputs.from` correct, so the failure is attributable
  // to `within` alone.
  it.each(["$", "$.result.metadata"] as const)(
    "refuses a result hook whose outputs.within is %s rather than $.result",
    async (within) => {
      const hookmapPath = join(SCRATCH_DIR, `result-within-${within === "$" ? "root" : "metadata"}.yaml`);
      writeFileSync(hookmapPath, resultHook("$.result.output", within));
      await expect(runPlugin(hookmapPath)).rejects.toThrow(/outputs\.within" is/);
      await expect(runPlugin(hookmapPath)).rejects.toThrow(/patched clone OF the container/);
    },
  );

  // The `outputs.from` rule is the only thing that refuses a `from` outside
  // a correct `within`. Deliberately not `from: $.result.output` / `within:
  // $.result.metadata`: the `within` rule alone already refuses that
  // combination, so it would demonstrate nothing about the `outputs.from`
  // rule specifically (it still passes with the `outputs.from` entry
  // removed).
  //
  // Without the `outputs.from` rule this hookmap loads, and `buildEnvelope`
  // then fails at stage "request" -- a failure whose outcome depends on the
  // negotiated posture. Under this deployment's fail-closed posture,
  // `replacingOutput` throws out of `governStep`; under a `proceed` posture
  // it is an audited ungoverned delivery. With the rule, it is refused at
  // load and neither happens.
  it("refuses a from outside a correct within at load -- only the outputs.from rule catches this", async () => {
    const hookmapPath = join(SCRATCH_DIR, "result-from-outside-within.yaml");
    writeFileSync(hookmapPath, resultHook("$.tool", "$.result"));
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/outputs\.from" is "\$\.tool"/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/the value the policy runtime is asked ABOUT/);
  });

  // `outputs.from` is the leaf that goes on the wire as this step's
  // `outputs[0].value`, so pointing it elsewhere does not withhold the wrong
  // field: it asks the policy runtime about a different value, which it then
  // answers correctly. Measured (result-gate.test.ts): envelope carries the
  // tool's own title, decision `allow`, `stage: "honoured"`, and `rm -rf /`
  // delivered in leaf and mirror.
  it.each(["$.result.title", "$.result.metadata.output"] as const)(
    "refuses a result hook whose outputs.from is %s rather than $.result.output",
    async (from) => {
      const hookmapPath = join(SCRATCH_DIR, `result-from-${from.split(".").pop()}.yaml`);
      // `within` correct in both, so the failure is attributable to `from`.
      writeFileSync(hookmapPath, resultHook(from, "$.result"));
      await expect(runPlugin(hookmapPath)).rejects.toThrow(/outputs\.from" is/);
      await expect(runPlugin(hookmapPath)).rejects.toThrow(/the value the policy runtime is asked ABOUT/);
    },
  );

  it("accepts the shipped result hook's own from/within pair", async () => {
    // The accept case, so the two refusals above cannot pass by refusing
    // everything.
    const hookmapPath = join(SCRATCH_DIR, "result-shipped-paths.yaml");
    writeFileSync(hookmapPath, resultHook("$.result.output", "$.result"));
    await expect(runPlugin(hookmapPath)).resolves.toBeUndefined();
  });

  // Measured first as a scoping divergence: the shim and `governStep` asked
  // `governsTool` with different arguments, so `governStep` skipped a
  // governed tool as "ungoverned" with no Guardian request and no audit
  // entry. That divergence is closed in the adapter now (`governStep` is
  // told the scoped tool), and this gate stays for the fault that remains --
  // re-measured with `tool_name: $.args.command` and the tool told: the step
  // is governed and audited normally while the envelope carries
  // `payload.tool.name: "rm -rf /"`, so the policy runtime is asked about a
  // tool this deployment never registered. Only this file can say which
  // field the shim feeds.
  it.each(["tool.execute.before", "tool.execute.after"] as const)(
    "refuses a %s entry whose tool_name points away from $.tool",
    async (hookEventName) => {
      const hookmapPath = join(SCRATCH_DIR, `tool-name-diverges-${hookEventName}.yaml`);
      const body =
        hookEventName === "tool.execute.before"
          ? "    arguments: $.args\n" + REQUEST_DECISIONS
          : "    outputs:\n" +
            "      from: $.result.output\n" +
            "      within: $.result\n" +
            "    exit_status: { from: $.result.metadata.exit }\n" +
            RESULT_DECISIONS;
      writeFileSync(
        hookmapPath,
        "host: opencode\n" +
          "hooks:\n" +
          `  ${hookEventName}:\n` +
          "    acs_method: steps/toolCallRequest\n" +
          "    tool_name: $.args.command\n" +
          "    tools: [bash]\n" +
          body,
      );
      await expect(runPlugin(hookmapPath)).rejects.toThrow(/tool_name" is "\$\.args\.command"/);
      await expect(runPlugin(hookmapPath)).rejects.toThrow(/NAME THE TOOL ON THE WIRE/);
    },
  );

  it("refuses a request hook whose arguments path points away from $.args", async () => {
    const hookmapPath = join(SCRATCH_DIR, "request-arguments-diverges.yaml");
    writeFileSync(
      hookmapPath,
      "host: opencode\n" +
        "hooks:\n" +
        "  tool.execute.before:\n" +
        "    acs_method: steps/toolCallRequest\n" +
        "    tool_name: $.tool\n" +
        "    arguments: $.result\n" +
        REQUEST_DECISIONS,
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/arguments" is "\$\.result"/);
  });
});

/**
 * The enforcement loop iterates the table, not the hookmap, so a declared
 * decision name outside the gate's tables is refused rather than silently
 * passed through. Measured in request-gate.test.ts: declaring the inert
 * entry is strictly worse than leaving it out, because without it
 * `renderDecision` throws and the posture answers it, audited.
 */
describe("AcsPlugin's load-time gate, for a decision name it has no expectation for", () => {
  it.each(["block", "Deny", "warn"] as const)(
    "refuses a request-gate hookmap declaring decisions.%s",
    async (decisionName) => {
      const hookmapPath = join(SCRATCH_DIR, `request-unknown-decision-${decisionName}.yaml`);
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
          `      ${decisionName}:\n` +
          "        output:\n" +
          "          reason.text: { from: reasoning, type: string }\n",
      );
      await expect(runPlugin(hookmapPath)).rejects.toThrow(
        new RegExp(`declares "${decisionName}", which this shim has no expectation for at this gate`),
      );
      await expect(runPlugin(hookmapPath)).rejects.toThrow(/strictly WORSE than leaving it out/);
    },
  );

  it("refuses the same at the result gate", async () => {
    const hookmapPath = join(SCRATCH_DIR, "result-unknown-decision.yaml");
    writeFileSync(
      hookmapPath,
      "host: opencode\n" +
        "hooks:\n" +
        "  tool.execute.after:\n" +
        "    acs_method: steps/toolCallResult\n" +
        "    tool_name: $.tool\n" +
        "    outputs:\n" +
        "      from: $.result.output\n" +
        "      within: $.result\n" +
        "    exit_status: { from: $.result.metadata.exit }\n" +
        "    decisions:\n" +
        "      allow:\n" +
        "        output:\n" +
        "          reason.text: { from: reasoning, type: string }\n" +
        "      deny:\n" +
        "        output:\n" +
        "          result: { from: applied_output }\n" +
        "      block:\n" +
        "        output:\n" +
        "          reason.text: { from: reasoning, type: string }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/has no expectation for at this gate/);
  });

  it("still accepts every decision name the tables do know, and allow", async () => {
    // The accept case, so the throw above cannot pass by refusing everything.
    const hookmapPath = join(SCRATCH_DIR, "request-all-known-decisions.yaml");
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
        "      ask:\n" +
        "        output:\n" +
        "          refuse.denied: { value: true }\n" +
        "      defer:\n" +
        "        output:\n" +
        "          refuse.denied: { value: true }\n" +
        "      modify:\n" +
        "        output:\n" +
        "          args: { from: applied_input }\n",
    );
    await expect(runPlugin(hookmapPath)).resolves.toBeUndefined();
  });
});

/**
 * A hook the table has no entry for is a throw, not a skip -- the rule
 * `expectationFor` states in hosts/claude-code/acs-hook.ts, adopted here for
 * the same reason and one more.
 */
describe("AcsPlugin's load-time gate, for a hook it has no expectation for", () => {
  it("refuses a hookmap mapping a hook this shim never registers", async () => {
    const hookmapPath = join(SCRATCH_DIR, "unknown-hook.yaml");
    // A perfectly well-formed request-gate entry -- `loadHookmap` accepts it,
    // `refuse.denied` is present, every field names a value or a from. The
    // only thing wrong with it is the event name, and that is enough: this
    // plugin returns "tool.execute.before" and "tool.execute.after" and
    // nothing else, so this entry would never be registered with OpenCode at
    // all while sitting in the hookmap looking like governance.
    writeFileSync(
      hookmapPath,
      "host: opencode\n" +
        "hooks:\n" +
        "  tool.execute.during:\n" +
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
        "          refuse.reason: { from: reasoning, type: string }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/this shim has no expectation for/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/tool\.execute\.during/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/unknown-hook\.yaml/);
  });

  it("refuses a hookmap naming a hook after a prototype-chain key, with the message that says which hook is unknown", async () => {
    // `hasOwnProperty`, not a bare index, in `expectationFor`: a bare index
    // would read `Object.prototype.constructor` here, pass the `undefined`
    // check, and then die on a missing `assertDecisions` -- an unrelated
    // TypeError in place of the message naming the hook. Same probe
    // acs-hook.ts's own gate reasons about.
    const hookmapPath = join(SCRATCH_DIR, "prototype-hook.yaml");
    writeFileSync(
      hookmapPath,
      "host: opencode\n" +
        "hooks:\n" +
        "  constructor:\n" +
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
        "          refuse.reason: { from: reasoning, type: string }\n",
    );
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/this shim has no expectation for/);
    await expect(runPlugin(hookmapPath)).rejects.toThrow(/"constructor"/);
  });
});

/**
 * The registration itself, which is the one thing every other gate in this
 * file assumes and none of them checks.
 *
 * `AcsPlugin` hands OpenCode its hooks as OBJECT KEYS, and OpenCode
 * dispatches by reading them -- `const hook = plugin[eventName]; if (!hook)
 * continue;`, out of 1.18.18's own compiled `Plugin.trigger`. A key that does
 * not match the name OpenCode fires is never called: no throw, no exit code,
 * no audit entry, an entirely ungoverned session that looks like a quiet one.
 * So "this plugin registers what it thinks it registers" is a load-bearing
 * claim, and `assertRegistrationMatchesIntent` is what turns it into a
 * startup failure instead of an assumption.
 *
 * DEFECT INJECTED INTO A COPY OF THE REAL SOURCE, rather than by exporting
 * the check. `acs-plugin.ts` exports exactly one symbol on purpose --
 * test/invariants.test.ts pins that, because a second export makes OpenCode's
 * loader mis-invoke it and disables governance for the whole session -- so
 * neither the gate nor its two tables can be imported here. What a test CAN
 * do is take the real file, rename one hook key in exactly the way an
 * upstream rename would be half-applied, and load the result. That drives the
 * real gate over real code, which is the claim; asserting against a
 * reimplementation of the check would only pin the reimplementation.
 *
 * The copy is written BESIDE the original, in `hosts/opencode/`, and not into
 * the scratch dir: `acs-plugin.ts` imports `./apply-opencode-output.ts` and
 * resolves its default hookmap through `import.meta.url`, so only a sibling
 * path resolves the way the original does. Uniquely named and removed in
 * `finally`, so a failing assertion cannot leave one behind.
 */
describe("AcsPlugin's load-time gate, on the hooks it actually registers", () => {
  const SHIM = fileURLToPath(new URL("../acs-plugin.ts", import.meta.url));
  const SHIM_DIR = dirname(SHIM);

  /**
   * Loads a copy of the shim with `edit` applied to its source, and answers
   * with whatever the factory did. The `edit` is asserted to have changed
   * something: a search string that stopped matching would silently make
   * every case below load an unmodified shim and pass for no reason.
   */
  async function loadMutatedShim(label: string, edit: (source: string) => string): Promise<unknown> {
    const original = readFileSync(SHIM, "utf8");
    const mutated = edit(original);
    expect(mutated).not.toBe(original);

    const copyPath = join(SHIM_DIR, `acs-plugin.${label}.${crypto.randomUUID()}.ts`);
    const previous = process.env.ACS_HOOKMAP_PATH;
    try {
      writeFileSync(copyPath, mutated);
      process.env.ACS_HOOKMAP_PATH = fileURLToPath(new URL("../opencode.hookmap.yaml", import.meta.url));
      // Dynamic because the specifier IS the runtime artifact: the module
      // does not exist until the line above writes it, and the whole point
      // is to load a deliberately-defective copy of the shim. A static
      // import cannot name a file that is created per test case.
      const module = (await import(copyPath)) as { AcsPlugin: typeof AcsPlugin };
      return await module.AcsPlugin({} as never).then(
        () => undefined,
        (error: unknown) => error,
      );
    } finally {
      rmSync(copyPath, { force: true });
      if (previous === undefined) {
        delete process.env.ACS_HOOKMAP_PATH;
      } else {
        process.env.ACS_HOOKMAP_PATH = previous;
      }
    }
  }

  // The positive half, and not a formality: this is what says the two keys
  // OpenCode is handed are the two names the rest of this file reasons
  // about. A rename in either hook method fails here as well as at the gate.
  it("registers exactly the two hooks the shipped hookmap declares", async () => {
    const previous = process.env.ACS_HOOKMAP_PATH;
    process.env.ACS_HOOKMAP_PATH = fileURLToPath(new URL("../opencode.hookmap.yaml", import.meta.url));
    try {
      const hooks = await AcsPlugin({} as never);
      expect(Object.keys(hooks).sort()).toEqual(["tool.execute.after", "tool.execute.before"]);
    } finally {
      if (previous === undefined) {
        delete process.env.ACS_HOOKMAP_PATH;
      } else {
        process.env.ACS_HOOKMAP_PATH = previous;
      }
    }
  });

  // Direction one: a rename applied to the hook METHOD and not to the table.
  // This is the shape an upstream rename takes while it is half-applied, and
  // it is the shape that used to register silently -- OpenCode would have
  // fired `tool.execute.after`, found no key, and skipped the result gate for
  // the life of the session.
  it("refuses when a registered hook name is one it has no expectation for", async () => {
    const error = await loadMutatedShim("renamed-key", (source) =>
      source.replace('    "tool.execute.after": async (input, output) =>', '    "tool.execute.after.v2": async (input, output) =>'),
    );
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/not the same set/);
    expect((error as Error).message).toMatch(/tool\.execute\.after\.v2/);
    // Both halves named, so the message says which way round the drift is
    // rather than leaving an operator to diff two JSON arrays by eye.
    expect((error as Error).message).toMatch(/registered and unknown here/);
    expect((error as Error).message).toMatch(/known here and never registered/);
  });

  // Direction two: the table knows a hook the plugin never registers -- an
  // expectation that governs nothing, which is the exact fault
  // `expectationFor`'s own doc comment describes for a hookmap entry ("would
  // sit in the hookmap looking like governance and govern nothing") arriving
  // one level up instead.
  it("refuses when it has an expectation for a hook it never registers", async () => {
    const error = await loadMutatedShim("extra-expectation", (source) =>
      source.replace(
        '  "tool.execute.after": {\n    assertEntry(entry, path, hookEventName) {',
        '  "tool.execute.never.fired": { assertEntry() {} },\n  "tool.execute.after": {\n    assertEntry(entry, path, hookEventName) {',
      ),
    );
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/not the same set/);
    expect((error as Error).message).toMatch(/known here and never registered.*tool\.execute\.never\.fired/);
  });

  // The residual gap, asserted rather than described, so nobody reads the
  // gate for more than it is: rename BOTH sides -- the plugin's key and its
  // expectation -- and the check is satisfied, because the agreement it
  // verifies is internal. This is what an upstream rename looks like once it
  // has been applied consistently to the wrong name, and no check inside this
  // repository can see it: OpenCode's plugin API publishes no registry of
  // event names to compare against.
  it("does NOT catch a rename applied consistently -- the agreement it checks is internal", async () => {
    const error = await loadMutatedShim("renamed-both", (source) =>
      source
        .replace('    "tool.execute.after": async (input, output) =>', '    "tool.execute.after.v2": async (input, output) =>')
        .replace(
          '  "tool.execute.after": {\n    assertEntry(entry, path, hookEventName) {',
          '  "tool.execute.after.v2": {\n    assertEntry(entry, path, hookEventName) {',
        ),
    );
    // It stops for the OTHER reason -- the shipped hookmap still declares the
    // old name, which `expectationFor` refuses. That is the accident this
    // test exists to distinguish from a check that saw the rename: the gate
    // under test was satisfied, and something else caught it.
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toMatch(/this shim has no expectation for/);
    expect((error as Error).message).not.toMatch(/not the same set/);
  });
});
