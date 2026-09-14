import { describe, expect, it } from "bun:test";
import type { AgtVerdict } from "agt-bridge";
import {
  loadMapping,
  mapVerdict,
  resolveInterventionPoint,
  resolvePolicyTargetArgument,
  type Mapping,
} from "../src/map-verdict.ts";

const m = loadMapping("mapping.yaml");

describe("mapVerdict", () => {
  it("maps allow to allow", () => {
    expect(mapVerdict({ decision: "allow" }, m, "pre_tool_call", "command").decision).toBe("allow");
  });

  it("maps deny, carrying reason and message into ACS fields", () => {
    const d = mapVerdict(
      { decision: "deny", reason: "destructive_shell_command_blocked", message: "matched pattern X at offset 5" },
      m,
      "pre_tool_call",
      "command",
    );
    expect(d.decision).toBe("deny");
    expect(d.reason_codes).toEqual(["destructive_shell_command_blocked"]);
    expect(d.policy_references?.[0]?.rule_id).toBe("destructive_shell_command_blocked");
  });

  // The whole warn round trip rests on this.
  it("maps warn to allow WITH non-empty policy_references", () => {
    const d = mapVerdict(
      { decision: "warn", reason: "drift_detected", message: "drift 0.8" },
      m,
      "pre_tool_call",
      "command",
    );
    expect(d.decision).toBe("allow");
    expect(d.policy_references?.length).toBeGreaterThan(0);
    expect(d.policy_references?.[0]?.rule_id).toBe("drift_detected");
  });

  it("distinguishes warn-allow from clean allow by policy_references", () => {
    expect(mapVerdict({ decision: "allow" }, m, "pre_tool_call", "command").policy_references ?? []).toHaveLength(0);
  });

  it("maps escalate to ask and transform to modify", () => {
    expect(mapVerdict({ decision: "escalate", reason: "approval_required" }, m, "pre_tool_call", "command").decision)
      .toBe("ask");
    expect(
      mapVerdict(
        { decision: "transform", reason: "redacted", transform: { path: "$policy_target", value: "x" } },
        m,
        "pre_tool_call",
        "command",
      ).decision,
    ).toBe("modify");
  });

  it("emits only lowercase decisions", () => {
    for (const dec of ["allow", "deny", "warn", "escalate", "transform"] as const) {
      // transform maps to a MODIFY, which requires a transform object -- this
      // loop's own point is decision casing, not that shape, so it supplies
      // one for the one decision that needs it.
      const verdict =
        dec === "transform"
          ? { decision: dec, reason: "r", transform: { path: "$policy_target", value: "x" } }
          : { decision: dec, reason: "r" };
      const out = mapVerdict(verdict, m, "pre_tool_call", "command").decision;
      expect(out.toLowerCase()).toBe(out);
    }
  });

  // This throw path (require_policy_references marked true, but no
  // policy_references could be synthesized) is real: a "warn" verdict with
  // no `reason` hits it directly, and it's exactly what the Guardian's
  // evaluation-failure catch (server.test.ts) has to survive without turning
  // it into an HTML 500 or a silent decision.
  it("throws when require_policy_references is set but verdict.reason is empty", () => {
    expect(() => mapVerdict({ decision: "warn" }, m, "pre_tool_call", "command")).toThrow(/require_policy_references/);
  });

  // Confirms mapVerdict reads `field_synthesis.reason_codes.wrap` from the
  // mapping declaration rather than assuming array-wrapping, so an edit to
  // the table changes behaviour.
  describe("field_synthesis.reason_codes.wrap is read, not assumed", () => {
    it("wraps per the declared mode, on the shipped mapping", () => {
      expect(mapVerdict({ decision: "deny", reason: "r" }, m, "pre_tool_call", "command").reason_codes).toEqual(["r"]);
    });

    it("throws for a wrap mode this mapping cannot express, rather than array-wrapping anyway", () => {
      // loadMapping casts the parsed YAML and validates nothing, so a mapping
      // declaring an unknown mode type-checks and reaches mapVerdict. Silently
      // array-wrapping it would synthesize a reason_codes the mapping never
      // asked for and hand it to a host as a decision's machine-readable half.
      const unknownMode = {
        ...m,
        field_synthesis: { ...m.field_synthesis, reason_codes: { source: "verdict.reason", wrap: "csv" } },
      } as unknown as Mapping;

      expect(() => mapVerdict({ decision: "deny", reason: "r" }, unknownMode, "pre_tool_call", "command")).toThrow(
        /field_synthesis\.reason_codes\.wrap as "csv"/,
      );
    });
  });

  // AGT writes verdict.message for an operator reading a log: patterns.rego
  // sprintf's "matched pattern <regex> at offset <n>". That file is vendored
  // byte-identical from AGT and verify:pin proves it, so the sentence a human
  // or a model reads is composed on this side of the boundary and never
  // upstream. What arrives at a host is one sentence of ordinary English, the
  // rule that decided, and the attribution to AGT's bundle.
  describe("reasoning reads as English, names the rule, and attributes AGT", () => {
    it("composes a deny from the rule's declared summary, dropping AGT's regex", () => {
      const d = mapVerdict(
        {
          decision: "deny",
          reason: "destructive_shell_command_blocked",
          message: "matched pattern (?i)rm\\s+-[a-z]*r[a-z]*f[a-z]*\\s+/(?:\\s|$) at offset 5",
        },
        m,
        "pre_tool_call",
        "command",
      );
      expect(d.reasoning).toBe(
        "This command was blocked because it matches a destructive-shell-command pattern. " +
          "Policy: destructive_shell_command_blocked, from AGT's stock bundle (agt_stock). Matched at offset 5.",
      );
    });

    // One AGT rule, two gates, two different things to say about it: the same
    // redaction_applied rewrites the command at the request gate and the
    // output at the result gate, and a reader cannot tell which from the rule
    // name alone.
    it("says something different for the same rule at each gate", () => {
      const verdict = {
        decision: "transform" as const,
        reason: "redaction_applied",
        transform: { path: "$policy_target", value: "echo [REDACTED]" },
      };
      expect(mapVerdict(verdict, m, "pre_tool_call", "command").reasoning).toBe(
        "A secret in this step's arguments was replaced before it ran. " +
          "Policy: redaction_applied, from AGT's stock bundle (agt_stock).",
      );
      expect(mapVerdict(verdict, m, "post_tool_call", undefined).reasoning).toBe(
        "Secrets in this output were replaced before the model saw them. " +
          "Policy: redaction_applied, from AGT's stock bundle (agt_stock).",
      );
    });

    // A rule this table has no sentence for still gets named and attributed,
    // and AGT's own message is passed through whole rather than dropped. A
    // summary table that silently swallowed an unrecognised rule would be
    // worse than the raw message it replaced.
    it("falls back for an unknown rule without losing AGT's message", () => {
      const d = mapVerdict(
        { decision: "deny", reason: "some_future_agt_rule", message: "whatever AGT said" },
        m,
        "pre_tool_call",
        "command",
      );
      expect(d.reasoning).toBe(
        "This step was decided by AGT's stock policy bundle. " +
          "Policy: some_future_agt_rule, from AGT's stock bundle (agt_stock). AGT reported: whatever AGT said.",
      );
    });

    it("omits the detail clause when AGT supplied no message", () => {
      const d = mapVerdict({ decision: "escalate", reason: "approval_required" }, m, "pre_tool_call", "command");
      expect(d.reasoning).toBe(
        "This step needs human approval before it can run. " +
          "Policy: approval_required, from AGT's stock bundle (agt_stock).",
      );
    });

    // A clean allow carries no rule and nothing to explain. Composing a
    // sentence for it would put reasoning on the one decision whose whole
    // signature is the absence of it.
    it("leaves a clean allow with no reasoning at all", () => {
      expect(mapVerdict({ decision: "allow" }, m, "pre_tool_call", "command").reasoning).toBeUndefined();
    });

    // Composition is what a `template` asks for. A mapping that declares only
    // a source is asking for that field copied, and copying it is
    // implementing that table exactly -- which is what lets a fixture pinning
    // some other part of the translation stay a two-line declaration instead
    // of carrying a wording table it does not test.
    it("copies the source verbatim for a mapping that declares no template", () => {
      const sourceOnly = {
        ...m,
        field_synthesis: { ...m.field_synthesis, reasoning: { source: "verdict.message" } },
      } as unknown as Mapping;

      const d = mapVerdict(
        { decision: "deny", reason: "destructive_shell_command_blocked", message: "matched pattern X at offset 5" },
        sourceOnly,
        "pre_tool_call",
        "command",
      );
      expect(d.reasoning).toBe("matched pattern X at offset 5");
    });
  });
});

// These tests read the real mapping.yaml's intervention_points table, so a
// row edited there without a matching runtime change fails somewhere rather
// than nowhere.
describe("resolveInterventionPoint", () => {
  it("answers the ACS method the shipped mapping wires, from the table rather than a literal", () => {
    expect(resolveInterventionPoint("steps/toolCallRequest", m)).toBe("pre_tool_call");
    expect(resolveInterventionPoint("steps/agentResponse", m)).toBe("output");
  });

  it("throws for a method no row names, rather than defaulting to a point", () => {
    // The fail-open this function is shaped against: any default here would
    // evaluate one intervention point's policy for a different method's
    // snapshot and call the result a decision.
    expect(() => resolveInterventionPoint("steps/userMessage", { ...m, intervention_points: {} })).toThrow(
      /maps no AGT intervention point/,
    );
  });

  it("throws when two rows name the same ACS method, rather than letting YAML key order pick", () => {
    const ambiguous = {
      ...m,
      intervention_points: {
        pre_tool_call: { acs_method: "steps/toolCallRequest" },
        pre_model_call: { acs_method: "steps/toolCallRequest" },
      },
    };

    expect(() => resolveInterventionPoint("steps/toolCallRequest", ambiguous)).toThrow(/more than one/);
  });

  it("resolves every other declared ACS method from the same table", () => {
    // One row resolving is not evidence the table is being read -- a literal
    // would satisfy that. These are the rest of the rows mapping.yaml ships.
    expect(resolveInterventionPoint("steps/toolCallResult", m)).toBe("post_tool_call");
    expect(resolveInterventionPoint("steps/sessionStart", m)).toBe("agent_startup");
    expect(resolveInterventionPoint("steps/agentResponse", m)).toBe("output");
  });

  it("never resolves to a row whose acs_method is null", () => {
    // mapping.yaml really does ship two of these: the model-call points have
    // no ACS v0.1.0 target. A resolver comparing loosely would match a
    // null row and evaluate the wrong intervention point's policy.
    const allNull = {
      ...m,
      intervention_points: {
        pre_model_call: { acs_method: null },
        post_model_call: { acs_method: null },
      },
    } as unknown as Mapping;

    expect(() => resolveInterventionPoint("steps/toolCallRequest", allNull)).toThrow(
      /maps no AGT intervention point/,
    );
  });

  it("throws when the mapping declares no intervention_points table at all", () => {
    // loadMapping's `as Mapping` is unchecked, so a mapping.yaml edited to
    // drop the table type-checks and reaches here. Standing in for that.
    const tableless = { ...m, intervention_points: undefined } as unknown as Mapping;

    expect(() => resolveInterventionPoint("steps/toolCallRequest", tableless)).toThrow(
      /no intervention_points table/,
    );
  });
});

describe("mapVerdict — transform becomes a MODIFY that carries modifications", () => {
  it("synthesizes parameter_overrides from the transform's $policy_target value", () => {
    const decision = mapVerdict(
      {
        decision: "transform",
        reason: "redaction_applied",
        transform: { path: "$policy_target", value: "echo [REDACTED]" },
      },
      m,
      "pre_tool_call",
      "command",
    );
    expect(decision.decision).toBe("modify");
    expect(decision.modifications).toEqual({ parameter_overrides: { command: "echo [REDACTED]" } });
  });

  it("keeps the synthesized reason_codes and policy_references a MODIFY still needs", () => {
    const decision = mapVerdict(
      { decision: "transform", reason: "redaction_applied", transform: { path: "$policy_target", value: "x" } },
      m,
      "pre_tool_call",
      "command",
    );
    expect(decision.reason_codes).toEqual(["redaction_applied"]);
    expect(decision.policy_references).toEqual([{ policy_id: "agt_stock", rule_id: "redaction_applied" }]);
  });

  // A MODIFY with no modifications is invalid per §6, and silently emitting
  // one would make the host apply nothing while reporting a rewrite. Fail loudly.
  it("throws when a transform verdict carries no transform object", () => {
    expect(() =>
      mapVerdict({ decision: "transform", reason: "redaction_applied" }, m, "pre_tool_call", "command"),
    ).toThrow(/transform/);
  });

  it("throws when the transform names a path this mapping cannot express", () => {
    expect(() =>
      mapVerdict(
        { decision: "transform", reason: "x", transform: { path: "$.some.other.leaf", value: "y" } },
        m,
        "pre_tool_call",
        "command",
      ),
    ).toThrow(/\$policy_target/);
  });

  it("leaves every other verdict's shape untouched", () => {
    expect(mapVerdict({ decision: "allow" }, m, "pre_tool_call", "command").modifications).toBeUndefined();
    expect(mapVerdict({ decision: "deny", reason: "r", message: "m" }, m, "pre_tool_call", "command").modifications)
      .toBeUndefined();
    // `escalate -> ask` is asserted above, in the test whose subject that is;
    // this line is about the same thing as its two neighbours -- that only a
    // `modify` grows a `modifications` object.
    expect(
      mapVerdict({ decision: "escalate", reason: "approval_required", message: "m" }, m, "pre_tool_call", "command")
        .modifications,
    ).toBeUndefined();
  });

  // `into` is a closed union of the shapes this mapping can build (two of
  // them, one per gate), each added by widening the union with a checked
  // value and never by casting an arbitrary value into it. This test
  // simulates a mapping.yaml edit that loadMapping's unchecked `as Mapping`
  // would let through unnoticed, standing in for malformed YAML, and proves
  // the runtime rejects it loudly instead of silently misbuilding or
  // disagreeing with the declaration.
  //
  // `modified_content` is the §6.3 shape this deployment does not build: it
  // is a legal ACS modification and an illegal one here, which is exactly
  // the gap between "the spec permits it" and "this mapping can express it"
  // that the check exists to keep loud.
  it("throws when mapping.yaml declares an into this mapping cannot express", () => {
    const withUnsupportedInto = {
      ...m,
      intervention_points: {
        ...m.intervention_points,
        pre_tool_call: {
          ...m.intervention_points.pre_tool_call,
          modifications: { ...m.intervention_points.pre_tool_call?.modifications, into: "modified_content" },
        },
      },
    } as unknown as Mapping;
    expect(() =>
      mapVerdict(
        { decision: "transform", reason: "x", transform: { path: "$policy_target", value: "y" } },
        withUnsupportedInto,
        "pre_tool_call",
        "command",
      ),
    ).toThrow(/modified_content/);
  });
});

// The same AGT transform has to land in a different ACS modification
// depending on which gate asked: the request gate rewrites a tool argument
// (parameter_overrides, keyed by argument name) and the result gate rewrites
// the result payload's own leaf (a redaction, keyed by JSON pointer). The
// synthesis lives under each intervention point in mapping.yaml rather than
// in `field_synthesis` -- the same table resolveInterventionPoint already
// reads -- and mapVerdict takes the point that decides which.
describe("mapVerdict — the modifications synthesis is per intervention point", () => {
  const transformVerdict = {
    decision: "transform",
    reason: "redaction_applied",
    transform: { path: "$policy_target", value: "TOKEN=[REDACTED]" },
  } as const;

  it("maps a post-tool transform to a redaction on the output path", () => {
    const decision = mapVerdict(transformVerdict, m, "post_tool_call", undefined);
    expect(decision.decision).toBe("modify");
    expect(decision.modifications).toEqual({
      redactions: [{ path: "/outputs/0/value", replacement: "TOKEN=[REDACTED]" }],
    });
  });

  it("still maps a pre-tool transform to parameter_overrides", () => {
    const decision = mapVerdict(
      { decision: "transform", reason: "redaction_applied", transform: { path: "$policy_target", value: "echo [REDACTED]" } },
      m,
      "pre_tool_call",
      "command",
    );
    expect(decision.modifications).toEqual({ parameter_overrides: { command: "echo [REDACTED]" } });
  });

  // §6.3's oneOf: the two shapes never combine. A synthesis producing both
  // would be rejected by the Guardian's own response validation.
  it("never emits both shapes at once", () => {
    for (const point of ["pre_tool_call", "post_tool_call"]) {
      // The shipped mapping declares no policy_target_argument for
      // post_tool_call, so "command" is not a value resolvePolicyTargetArgument
      // could ever answer there -- only pre_tool_call's parameter_overrides
      // branch reads this argument at all.
      const policyTargetArgument = point === "pre_tool_call" ? "command" : undefined;
      const mods = mapVerdict(transformVerdict, m, point, policyTargetArgument).modifications as Record<
        string,
        unknown
      >;
      expect(["redactions", "parameter_overrides"].filter((k) => k in mods)).toHaveLength(1);
      expect("modified_content" in mods).toBe(false);
    }
  });

  // mapping.yaml declares six methods with intervention points and gives two
  // of them a synthesis rule. A `transform` arriving at any of the others is a
  // verdict this mapping cannot express, and it throws -- the Guardian's
  // evaluation catch then turns that into an honoured `deny` (§6.4).
  //
  // What it must never do is answer with a `modify` carrying no
  // modifications: §6 requires a `modify` to carry them, and one the host
  // cannot apply is a rewrite reported as applied while the original is
  // delivered.
  it("throws for a transform at a point with no modifications rule, rather than an empty modify", () => {
    // Seven points, and three distinct kinds of gap, because they do not all
    // mean the same thing:
    //   - `input` / `output` / `agent_startup` / `agent_shutdown`: mapped to an
    //     ACS method, given no synthesis rule. A property of this deployment,
    //     not of the spec.
    //   - `pre_model_call` / `post_model_call`: `acs_method: null`. A point
    //     AGT supports that ACS v0.1.0 has no target for at all, so there is
    //     nothing for a rule to describe. This is a permanent property of
    //     the pinned spec version rather than of this deployment, and the
    //     most worth naming: it cannot be closed by writing more mapping.
    //   - `no_such_point`: no row names it. A missing row and a row missing
    //     its rule reach the same `?.` and must not diverge.
    for (const point of [
      "input",
      "output",
      "agent_startup",
      "agent_shutdown",
      "pre_model_call",
      "post_model_call",
      "no_such_point",
    ]) {
      expect(() => mapVerdict(transformVerdict, m, point, undefined)).toThrow(/no modifications rule/);
    }
  });

  // A redaction's `replacement` is a string in modifications.json, so a
  // transform value that is not one is a rewrite this mapping cannot express
  // as a redaction. Throwing beats coercing: `String(value)` would put a
  // replacement nobody chose into the delivered output, and the whole point of
  // moving AGT's already-substituted text is that the Guardian never invents
  // the replacement.
  it("throws when the transform value could not be a redaction replacement", () => {
    expect(() =>
      mapVerdict(
        { decision: "transform", reason: "x", transform: { path: "$policy_target", value: { some: "object" } } },
        m,
        "post_tool_call",
        undefined,
      ),
    ).toThrow(/replacement/);
  });
});

describe("which argument a tool's policy target is read from", () => {
  const shipped = loadMapping("mapping.yaml");

  it("answers the argument the table names for that tool", () => {
    expect(resolvePolicyTargetArgument(shipped, "pre_tool_call", "WebFetch")).toBe("url");
    expect(resolvePolicyTargetArgument(shipped, "pre_tool_call", "Bash")).toBe("command");
  });

  it("falls back to the default for a tool the table does not name", () => {
    expect(resolvePolicyTargetArgument(shipped, "pre_tool_call", "SomeToolNobodyRegistered")).toBe("command");
  });

  it("answers nothing for a gate that rewrites a payload leaf rather than an argument", () => {
    expect(resolvePolicyTargetArgument(shipped, "post_tool_call", "Bash")).toBeUndefined();
  });

  it("throws for a point the mapping has no row for at all", () => {
    expect(() => resolvePolicyTargetArgument(shipped, "not_a_point", "Bash")).toThrow(/no row/);
  });

  it("throws when the table names neither a default nor an entry for this tool", () => {
    const broken = {
      intervention_points: {
        pre_tool_call: { acs_method: "steps/toolCallRequest", policy_target_argument: { by_tool: { Bash: "command" } } },
      },
    } as unknown as Mapping;
    expect(() => resolvePolicyTargetArgument(broken, "pre_tool_call", "WebFetch")).toThrow(/default/);
  });
});

describe("a rewrite lands on the argument the tool actually sent it in", () => {
  const shipped = loadMapping("mapping.yaml");
  const redaction: AgtVerdict = {
    decision: "transform",
    reason: "redaction_applied",
    transform: { path: "$policy_target", value: "https://docs.anthropic.com/?t=[REDACTED]" },
  };

  it("keys the parameter override by the resolved argument, not by a literal", () => {
    expect(mapVerdict(redaction, shipped, "pre_tool_call", "url").modifications).toEqual({
      parameter_overrides: { url: "https://docs.anthropic.com/?t=[REDACTED]" },
    });
  });

  it("keys a shell rewrite the same way, from the same declaration", () => {
    expect(mapVerdict(redaction, shipped, "pre_tool_call", "command").modifications).toEqual({
      parameter_overrides: { command: "https://docs.anthropic.com/?t=[REDACTED]" },
    });
  });

  it("refuses to report a rewrite with no argument to land it on", () => {
    expect(() => mapVerdict(redaction, shipped, "pre_tool_call", undefined)).toThrow(/policy_target_argument/);
  });

  it("leaves the result gate's redaction pointer alone -- it addresses a payload leaf, not an argument", () => {
    expect(mapVerdict(redaction, shipped, "post_tool_call", undefined).modifications).toEqual({
      redactions: [{ path: "/outputs/0/value", replacement: "https://docs.anthropic.com/?t=[REDACTED]" }],
    });
  });
});
