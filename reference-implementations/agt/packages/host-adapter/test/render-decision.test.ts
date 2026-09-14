import { describe, expect, it } from "bun:test";
import { loadHookmap, type Hookmap, type HookmapRequestHookEntry } from "../src/build-envelope.ts";
import { renderDecision } from "../src/render-decision.ts";
import { validateDecision } from "../src/validate-decision.ts";

/**
 * A hookmap for a host that is not Claude Code, deliberately: using the real
 * hookmap's decisions block here would make every assertion in this file
 * also an assertion about one host's field names, so the adapter's own
 * tests could not tell "renders what the hookmap says" apart from "renders
 * permissionDecision". This host nests its decision two levels deep under
 * different names, carries a field OUTSIDE that wrapper, and has no
 * permission-style field at all. Nothing in the module under test knows any
 * of it.
 *
 * The `decisions` block lives under the hook that asked, so this fixture
 * declares one hook and hangs its decisions off it. `renderDecision` is told
 * which hook it is rendering for, because a host with two gates renders a
 * different shape at each -- and it must not be able to answer one gate with
 * the other's rule.
 *
 * The tests at the bottom do load the real file, so the shipped hookmap is
 * still exercised end to end, at both of its hooks.
 */
const BEFORE_TOOL: HookmapRequestHookEntry = {
  acs_method: "steps/toolCallRequest",
  tool_name: "$.tool_name",
  arguments: "$.tool_input",
};

/** The fixture, with `BeforeTool`'s own decisions block. */
function withDecisions(decisions: Record<string, unknown>): Hookmap {
  return { host: "some-other-host", hooks: { BeforeTool: { ...BEFORE_TOOL, decisions } } };
}

const hookmap: Hookmap = withDecisions({
  allow: {
    output: {
      "gate.verdict": { value: "pass" },
      "gate.note": { from: "reasoning", type: "string" },
    },
  },
  deny: {
    output: {
      "gate.verdict": { value: "fail" },
      "gate.note": { from: "reasoning", type: "string" },
      blocked: { value: true },
    },
  },
  modify: {
    output: {
      "gate.verdict": { value: "pass" },
      "gate.rewritten": { from: "modifications" },
    },
  },
});

describe("renderDecision", () => {
  it("renders exactly the object the hookmap's output paths describe, nesting as declared", () => {
    expect(
      renderDecision("BeforeTool", { decision: "deny", reasoning: "blocked: destructive command" }, hookmap),
    ).toEqual({
      gate: { verdict: "fail", note: "blocked: destructive command" },
      blocked: true,
    });
  });

  it("leaves a `from` field off entirely when the decision does not carry it", () => {
    expect(renderDecision("BeforeTool", { decision: "allow" }, hookmap)).toEqual({ gate: { verdict: "pass" } });
  });

  it("leaves a `from` field off when the decision carries the wrong type for it", () => {
    // A Guardian putting an object where the hookmap declared prose would
    // otherwise produce an output the host cannot render -- and a host that
    // rejects the whole output treats the hook as having produced no decision,
    // which is a fail-open from a decision that arrived perfectly well.
    expect(renderDecision("BeforeTool", { decision: "allow", reasoning: { text: "not a string" } }, hookmap)).toEqual({
      gate: { verdict: "pass" },
    });
  });

  it("a warn-derived allow (allow + non-empty policy_references) still renders as a plain allow -- no separate rendering", () => {
    expect(
      renderDecision(
        "BeforeTool",
        {
          decision: "allow",
          policy_references: [{ policy_id: "stock_policy_bundle", rule_id: "drift_detected" }],
        },
        hookmap,
      ),
    ).toEqual({ gate: { verdict: "pass" } });
  });

  it("copies a whole object through a `from` field with no declared type", () => {
    expect(
      renderDecision(
        "BeforeTool",
        {
          decision: "modify",
          reasoning: "redacted a secret",
          modifications: { parameter_overrides: { command: "echo [REDACTED]" } },
        },
        hookmap,
      ),
    ).toEqual({
      gate: { verdict: "pass", rewritten: { parameter_overrides: { command: "echo [REDACTED]" } } },
    });
  });

  it("is hookmap-driven: mutating a decision's literal changes the rendered output with no code change", () => {
    const mutated = withDecisions({ allow: { output: { "gate.verdict": { value: "review" } } } });

    expect(renderDecision("BeforeTool", { decision: "allow" }, hookmap)).toEqual({ gate: { verdict: "pass" } });
    expect(renderDecision("BeforeTool", { decision: "allow" }, mutated)).toEqual({ gate: { verdict: "review" } });
  });

  it("is hookmap-driven: mutating a `from` changes which decision field feeds the host field", () => {
    const mutated = withDecisions({
      deny: { output: { "gate.verdict": { value: "fail" }, "gate.note": { from: "reason_codes" } } },
    });

    expect(
      renderDecision("BeforeTool", { decision: "deny", reasoning: "human text", reason_codes: "machine_code" }, mutated),
    ).toEqual({ gate: { verdict: "fail", note: "machine_code" } });
  });

  it("is hookmap-driven: a path with no dot puts the field alongside the wrapper, not inside it", () => {
    // The shape the old, host-named types could not express at all.
    const flat = withDecisions({ allow: { output: { verdict: { value: "pass" } } } });

    expect(renderDecision("BeforeTool", { decision: "allow" }, flat)).toEqual({ verdict: "pass" });
  });

  it("throws on an ACS decision absent from the hookmap's decisions block, rather than defaulting", () => {
    const noDeny = withDecisions({ allow: { output: { "gate.verdict": { value: "pass" } } } });

    expect(() => renderDecision("BeforeTool", { decision: "deny", reasoning: "x" }, noDeny)).toThrow(
      /no decisions entry/,
    );
  });

  it("throws when the hook declares no decisions block at all", () => {
    const noDecisions: Hookmap = { host: "some-other-host", hooks: { BeforeTool: BEFORE_TOOL } };

    expect(() => renderDecision("BeforeTool", { decision: "allow" }, noDecisions)).toThrow(/no decisions block/);
  });

  it("throws on an entry with an empty or missing output block, rather than rendering nothing", () => {
    // An output with no decision in it is read by a host as "the hook produced
    // nothing", which is the same bypass a missing entry is, only quieter.
    for (const broken of [{}, { output: {} }, null]) {
      const bad = withDecisions({ allow: broken });
      expect(() => renderDecision("BeforeTool", { decision: "allow" }, bad)).toThrow(/non-empty "output" block/);
    }
  });

  it("throws on an output field naming neither a literal nor a source", () => {
    const bad = withDecisions({ allow: { output: { "gate.verdict": { tpye: "string" } } } });

    expect(() => renderDecision("BeforeTool", { decision: "allow" }, bad)).toThrow(/must name a literal/);
  });

  it("throws on two output paths that collide, rather than silently picking one", () => {
    const collides = withDecisions({
      allow: { output: { gate: { value: "pass" }, "gate.verdict": { value: "pass" } } },
    });

    expect(() => renderDecision("BeforeTool", { decision: "allow" }, collides)).toThrow(/nests under/);
  });

  it("throws on an output path naming a reserved segment, which would mutate a prototype instead of adding a key", () => {
    const reserved = withDecisions({ allow: { output: { "__proto__.verdict": { value: "pass" } } } });

    expect(() => renderDecision("BeforeTool", { decision: "allow" }, reserved)).toThrow(/addresses no field/);
  });

  // The lookup is per-hook, so a rule declared for one gate must not answer
  // the other. A hookmap declaring two hooks whose decisions render different
  // shapes is the whole reason the hook name is a parameter, and a lookup that
  // fell back to some other hook's block would render a request-gate permission
  // field at a gate where the step has already run.
  it("renders the block belonging to the hook that asked, never another hook's", () => {
    const twoGates: Hookmap = {
      host: "some-other-host",
      hooks: {
        BeforeTool: { ...BEFORE_TOOL, decisions: { allow: { output: { "gate.verdict": { value: "pass" } } } } },
        AfterTool: {
          acs_method: "steps/toolCallResult",
          tool_name: "$.tool_name",
          outputs: { from: "$.tool_response.stdout", within: "$.tool_response" },
          exit_status: { literal: "success" },
          decisions: { allow: { output: { delivered: { value: true } } } },
        },
      },
    };

    expect(renderDecision("BeforeTool", { decision: "allow" }, twoGates)).toEqual({ gate: { verdict: "pass" } });
    expect(renderDecision("AfterTool", { decision: "allow" }, twoGates)).toEqual({ delivered: true });
  });

  it("pins the real hookmap's rendering of a warn-derived allow: reasoning surfaces", () => {
    // The real hookmap's allow entry (claude-code.hookmap.yaml) declares
    // `reason_from: reasoning`, which the local `hookmap` fixture above
    // deliberately does not carry -- this test locks in the real file's
    // behaviour directly. Shape matches what an observe-only upstream signal
    // (mapping.yaml's warn -> allow, require_policy_references: true)
    // actually produces: `reasoning` and `policy_references` both set.
    const real = loadHookmap("hosts/claude-code/claude-code.hookmap.yaml");

    const rendered = renderDecision(
      "PreToolUse",
      {
        decision: "allow",
        reasoning: "drift_score 0.9 reached threshold 0.5",
        reason_codes: ["drift_detected"],
        policy_references: [{ policy_id: "agt_stock", rule_id: "drift_detected" }],
      },
      real,
    );

    // No hookEventName: it is not a function of the decision, so the shim adds
    // it as it wraps. hosts/claude-code/test/wire-shape.test.ts pins the
    // wrapped stdout; this pins what the adapter is responsible for.
    expect(rendered).toEqual({
      hookSpecificOutput: {
        permissionDecision: "allow",
        permissionDecisionReason: "drift_score 0.9 reached threshold 0.5",
      },
    });
  });

  // The coupling nothing else guards: `validateDecision` puts the applied
  // arguments in `applied_input`, and the real hookmap's `modify` entry
  // names `updatedInput_from: applied_input`. Every other modify test in
  // this file uses the local fixture above, whose `modify` entry names
  // `modifications` instead -- so renaming either half would leave the real
  // deployment rendering `allow` with no `updatedInput` at all, and the
  // whole suite would still pass. This is the one test that fails when the
  // two names stop agreeing.
  it("loads the real hookmap and renders a modify with updatedInput carrying the applied arguments", () => {
    const real = loadHookmap("hosts/claude-code/claude-code.hookmap.yaml");
    const modificationDocument = { command: "echo ghp_SECRET123456" };

    const validated = validateDecision(
      {
        decision: "modify",
        reasoning: "redaction_applied",
        modifications: { parameter_overrides: { command: "echo [REDACTED]" } },
      },
      { elapsedMs: 10, modificationDocument },
    );

    const rendered = renderDecision("PreToolUse", validated, real);
    const hookSpecificOutput = rendered.hookSpecificOutput as Record<string, unknown>;

    expect(hookSpecificOutput.permissionDecision).toBe("allow");
    expect(hookSpecificOutput.updatedInput).toEqual({ command: "echo [REDACTED]" });
    // The rewrite is only real if the original does not survive into what the
    // host is told to run.
    expect(JSON.stringify(hookSpecificOutput.updatedInput)).not.toContain("ghp_SECRET123456");
    // And the transcript says WHY it changed. `modify` was the one entry in
    // the real hookmap with no `reason_from`, so a policy-ordered rewrite
    // reached a human as a command that silently differed from the one they
    // asked for, while every sibling decision explained itself. Pinned
    // against the whole output, so a `reason_from` pointed at the wrong field
    // fails here rather than reading as "some reason surfaced".
    expect(hookSpecificOutput).toEqual({
      permissionDecision: "allow",
      permissionDecisionReason: "redaction_applied",
      updatedInput: { command: "echo [REDACTED]" },
    });
  });

  it("loads the real claude-code.hookmap.yaml and renders a deny end to end", () => {
    const real = loadHookmap("hosts/claude-code/claude-code.hookmap.yaml");

    expect(renderDecision("PreToolUse", { decision: "deny", reasoning: "blocked" }, real)).toEqual({
      hookSpecificOutput: {
        permissionDecision: "deny",
        permissionDecisionReason: "blocked",
      },
    });
  });
});

/**
 * These are the exact outputs `PreToolUse` renders, restated against the
 * per-hook lookup: if that lookup ever changed any of them, this fails first.
 *
 * `renderDecision` returns one flat object -- a dotted path lands under the
 * wrapper, a dotless one beside it -- and the shim adds `hookEventName`, so it
 * is absent from every expectation here. The wrapped stdout a Claude Code
 * process actually reads back is pinned, unchanged, in
 * hosts/claude-code/test/wire-shape.test.ts.
 */
describe("renderDecision against the shipped hookmap, per hook", () => {
  const real = loadHookmap("hosts/claude-code/claude-code.hookmap.yaml");

  it.each([
    ["allow", { decision: "allow" }, { permissionDecision: "allow" }],
    ["deny", { decision: "deny", reasoning: "nope" }, { permissionDecision: "deny", permissionDecisionReason: "nope" }],
    ["ask", { decision: "ask", reasoning: "confirm?" }, { permissionDecision: "ask", permissionDecisionReason: "confirm?" }],
    [
      "modify",
      { decision: "modify", reasoning: "rewritten", applied_input: { command: "echo [REDACTED]" } },
      { permissionDecision: "allow", permissionDecisionReason: "rewritten", updatedInput: { command: "echo [REDACTED]" } },
    ],
  ])("renders PreToolUse %s exactly as before", (_name, result, expected) => {
    expect(renderDecision("PreToolUse", result as never, real)).toEqual({ hookSpecificOutput: expected });
  });

  // The reason field is the second half: a rewrite is the only decision that
  // changes what runs while the transcript says nothing, and the same rule
  // applies to PreToolUse's `modify`. It is worse at this gate, because what
  // the model reads is the rewritten text -- without a reason the model is
  // handed altered output with nothing saying it was altered, and may take
  // `[REDACTED]` for the command's own answer.
  it("renders a PostToolUse modify as updatedToolOutput AND the reason for it, with no permissionDecision", () => {
    const output = renderDecision(
      "PostToolUse",
      { decision: "modify", reasoning: "redacted", applied_output: { stdout: "TOKEN=[REDACTED]", stderr: "" } } as never,
      real,
    );

    expect(output).toEqual({
      hookSpecificOutput: {
        updatedToolOutput: { stdout: "TOKEN=[REDACTED]", stderr: "" },
        additionalContext: "redacted",
      },
    });
  });

  // `block` alone does not suppress anything. Deny at this gate must also
  // replace the output, or it reports a suppression that did not happen --
  // a rewrite reported but never taking effect. The dotless
  // `decision`/`reason` paths are what put those two beside the wrapper
  // rather than inside it.
  it("renders a PostToolUse deny as block AND a replacing output", () => {
    expect(
      renderDecision(
        "PostToolUse",
        {
          decision: "deny",
          reasoning: "secret in output",
          applied_output: { stdout: "[OUTPUT WITHHELD BY POLICY]" },
        } as never,
        real,
      ),
    ).toEqual({
      decision: "block",
      reason: "secret in output",
      hookSpecificOutput: { updatedToolOutput: { stdout: "[OUTPUT WITHHELD BY POLICY]" } },
    });
  });

  // The clean result: nothing to change, so nothing is rendered. The `allow`
  // entry declares one conditional field, so the rule is non-empty (which
  // assertRenderableDecisions still requires) while the output is empty --
  // and an empty output at this gate means "deliver it unchanged", which is
  // the honest answer once the tool has already run.
  it("renders a plain PostToolUse allow as nothing at all", () => {
    expect(renderDecision("PostToolUse", { decision: "allow" } as never, real)).toEqual({});
  });

  // The same requirement PreToolUse's allow answers, symmetrically: an
  // observe-only allow (AGT `warn`) carries a synthesized reasoning, and it
  // has to reach the transcript a human reads. `additionalContext` is the
  // PostToolUse field for it (present in 2.1.227's schema).
  it("renders an observe-only PostToolUse allow as additionalContext", () => {
    expect(
      renderDecision("PostToolUse", { decision: "allow", reasoning: "token pattern seen, not blocked" } as never, real),
    ).toEqual({ hookSpecificOutput: { additionalContext: "token pattern seen, not blocked" } });
  });

  it("throws naming the hook when that hook declares no decisions block", () => {
    expect(() =>
      renderDecision("PostToolUse", { decision: "allow" } as never, { host: "x", hooks: { PostToolUse: {} } } as never),
    ).toThrow(/PostToolUse/);
  });

  it("throws naming the hook when the hookmap does not map it at all", () => {
    expect(() => renderDecision("SessionStart", { decision: "allow" } as never, real)).toThrow(/SessionStart/);
  });
});
