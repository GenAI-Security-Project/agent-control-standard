import { describe, expect, it } from "bun:test";
import { validateDecision } from "../src/validate-decision.ts";

const FRESH = { elapsedMs: 10 };
const ARGS = { command: "echo ghp_ABCDEF123456", timeout: 30 };

describe("validateDecision — malformed modifications fail closed (§6.3)", () => {
  it("passes a modify whose modifications are well formed, and applies them", () => {
    const out = validateDecision(
      { decision: "modify", reasoning: "redacted", modifications: { parameter_overrides: { command: "echo [REDACTED]" } } },
      { ...FRESH, modificationDocument: ARGS },
    );
    expect(out.decision).toBe("modify");
    expect(out.applied_input).toEqual({ command: "echo [REDACTED]", timeout: 30 });
  });

  it("denies when modified_content is combined with parameter_overrides", () => {
    const out = validateDecision(
      {
        decision: "modify",
        reasoning: "r",
        modifications: { modified_content: "whole", parameter_overrides: { command: "x" } },
      },
      { ...FRESH, modificationDocument: ARGS },
    );
    expect(out.decision).toBe("deny");
    expect(out.reason_codes).toContain("modifications_invalid");
  });

  it("denies when a redaction path and an override key address the same field", () => {
    const out = validateDecision(
      {
        decision: "modify",
        reasoning: "r",
        modifications: { redactions: [{ path: "/command" }], parameter_overrides: { command: "x" } },
      },
      { ...FRESH, modificationDocument: ARGS },
    );
    expect(out.decision).toBe("deny");
  });

  // Two redactions must be disjoint from each other, not only from the
  // overrides. Without this check, `/a` then `/a/b` would yield
  // `{a: {b: "[REDACTED]"}}`: the first redaction discarded, `keep` silently
  // gone from the arguments the host was about to run, and the decision
  // still rendered as an applied modify. Losing an argument is worse than
  // failing to redact one, and both are worse than a deny.
  it("denies two redaction paths that overlap each other", () => {
    const out = validateDecision(
      { decision: "modify", reasoning: "r", modifications: { redactions: [{ path: "/a" }, { path: "/a/b" }] } },
      { elapsedMs: 10, modificationDocument: { a: { b: 1, keep: "important" } } },
    );
    expect(out.decision).toBe("deny");
    expect(out.reason_codes).toContain("modifications_invalid");
    expect(out.reasoning).toMatch(/not disjoint/);
  });

  it("denies two identical redaction paths", () => {
    const out = validateDecision(
      { decision: "modify", reasoning: "r", modifications: { redactions: [{ path: "/a" }, { path: "/a" }] } },
      { elapsedMs: 10, modificationDocument: { a: "x" } },
    );
    expect(out.decision).toBe("deny");
  });

  it("still allows two redactions on genuinely disjoint paths", () => {
    const out = validateDecision(
      { decision: "modify", reasoning: "r", modifications: { redactions: [{ path: "/a" }, { path: "/b" }] } },
      { elapsedMs: 10, modificationDocument: { a: "x", b: "y", c: "keep" } },
    );
    expect(out.decision).toBe("modify");
    expect(out.applied_input).toEqual({ a: "[REDACTED]", b: "[REDACTED]", c: "keep" });
  });

  it("denies on ancestor/descendant overlap, not just exact equality", () => {
    const out = validateDecision(
      {
        decision: "modify",
        reasoning: "r",
        modifications: { redactions: [{ path: "/env/TOKEN" }], parameter_overrides: { env: {} } },
      },
      { ...FRESH, modificationDocument: { env: { TOKEN: "t" } } },
    );
    expect(out.decision).toBe("deny");
  });

  it("denies a modify carrying no modifications at all", () => {
    const out = validateDecision({ decision: "modify", reasoning: "r" }, { ...FRESH, modificationDocument: ARGS });
    expect(out.decision).toBe("deny");
  });

  // An empty path segment list ("" or "/") addresses
  // no field. Applying it would report a successful modify while redacting
  // nothing -- a policy that fired and did not take effect -- so this fails
  // closed the same as any other unusable modifications object.
  it("denies a redaction with an empty path -- it would redact nothing while reporting success", () => {
    expect(validateDecision(
      { decision: "modify", reasoning: "r", modifications: { redactions: [{ path: "" }] } },
      { ...FRESH, modificationDocument: ARGS },
    ).decision).toBe("deny");
    expect(validateDecision(
      { decision: "modify", reasoning: "r", modifications: { redactions: [{ path: "/" }] } },
      { ...FRESH, modificationDocument: ARGS },
    ).decision).toBe("deny");
  });

  // A malformed redactions entry must be denied whether or not
  // parameter_overrides is also present -- validation must not depend on
  // which other fields happen to be there.
  it("denies a redaction with a missing or non-string path even with no parameter_overrides present", () => {
    expect(validateDecision(
      { decision: "modify", reasoning: "r", modifications: { redactions: [{}] } },
      { ...FRESH, modificationDocument: ARGS },
    ).decision).toBe("deny");
  });

  // The hazard this guards against: if unchecked, the decision would stay
  // `modify`, `applied_input` would carry both the invented key and the
  // untouched original, the hookmap would render `permissionDecision: allow`
  // with that updatedInput, and the host would run the original
  // un-redacted command -- while reporting the rewrite as applied. Nothing
  // would be audited, because the audit sink records delivery failures, not
  // this.
  it("denies a parameter_overrides key that names no existing argument, instead of inventing the field", () => {
    const out = validateDecision(
      {
        decision: "modify",
        reasoning: "redacted",
        // "cmd", not "command": one character away from the real argument.
        modifications: { parameter_overrides: { cmd: "echo [REDACTED]" } },
      },
      { ...FRESH, modificationDocument: { command: "echo ghp_SECRET123456" } },
    );
    expect(out.decision).toBe("deny");
    expect(out.reason_codes).toContain("modifications_invalid");
    // The secret must not survive into anything the host would run.
    expect(out.applied_input).toBeUndefined();
    expect(JSON.stringify(out)).not.toContain("ghp_SECRET123456");
  });

  it("denies a redaction path whose target is absent from the arguments that were sent", () => {
    const out = validateDecision(
      {
        decision: "modify",
        reasoning: "redacted",
        modifications: { redactions: [{ path: "/env/TOKEN" }] },
      },
      { ...FRESH, modificationDocument: { command: "echo ghp_SECRET123456" } },
    );
    expect(out.decision).toBe("deny");
    expect(out.reason_codes).toContain("modifications_invalid");
    expect(out.applied_input).toBeUndefined();
  });

  // The ACS result payload's redaction path is /outputs/0/value, so a
  // Guardian must be able to address an array element. A naive write turns
  // ["a","b"] into {"0":"[REDACTED]","1":"b"}, which is not the edit that
  // was asked for and would reach the host as an object where it expects a
  // list -- so the refusal is conditional on the index being real
  // (modifications.ts), and this test is deliberately the positive case
  // rather than a relaxed one: checking only `decision` would pass with the
  // array-safe write path deleted, the same weakness the comment below
  // calls out for the reserved-segment tests.
  it("applies a redaction addressing an array element, and keeps the array an array", () => {
    const out = validateDecision(
      { decision: "modify", reasoning: "r", modifications: { redactions: [{ path: "/items/0" }] } },
      { ...FRESH, modificationDocument: { items: ["a", "b"] } },
    );
    expect(out.decision).toBe("modify");
    expect(out.applied_input).toEqual({ items: ["[REDACTED]", "b"] });
    expect(Array.isArray((out.applied_input as { items: unknown }).items)).toBe(true);
  });

  // The reasoning is asserted, not just the deny: an absent-target check
  // alone already denies all three of these (none is an own property of an
  // arguments object), so a test that only checked `decision` would pass with
  // this guard deleted -- blind to the thing it exists to pin.
  for (const segment of ["__proto__", "constructor", "prototype"]) {
    it(`denies a redaction path or override key naming ${segment}, and says why`, () => {
      const redaction = validateDecision(
        { decision: "modify", reasoning: "r", modifications: { redactions: [{ path: `/${segment}` }] } },
        { ...FRESH, modificationDocument: ARGS },
      );
      expect(redaction.decision).toBe("deny");
      expect(redaction.reasoning).toContain(`reserved segment "${segment}"`);

      const override = validateDecision(
        { decision: "modify", reasoning: "r", modifications: { parameter_overrides: { [segment]: "x" } } },
        { ...FRESH, modificationDocument: ARGS },
      );
      expect(override.decision).toBe("deny");
      expect(override.reasoning).toContain(`reserved segment "${segment}"`);
    });
  }

  // modified_content alone passed validation and then applied nothing: it
  // returned the arguments untouched and still reported `modify`. Same shape as
  // an absent target, one branch over.
  //
  // The reason is not that this apply step lacks a mapping. Both documents
  // these pointers can address are field-addressed structures, and an opaque
  // replacement string is a field of neither, so there is no target for it
  // at either gate. That claim is pinned at both: here for the arguments, and
  // in the result-gate describe below for the outputs. Pinning it at one gate
  // only would leave the word "either" resting on nothing.
  it("denies a modify carrying only modified_content, for want of a target in an arguments object", () => {
    const out = validateDecision(
      { decision: "modify", reasoning: "r", modifications: { modified_content: "echo [REDACTED]" } },
      { ...FRESH, modificationDocument: ARGS },
    );
    expect(out.decision).toBe("deny");
    expect(out.applied_input).toBeUndefined();
    expect(out.reasoning).toContain("the arguments it was asked to run with");
    expect(out.reasoning).toContain("no target for it at either gate");
    expect(out.reasoning).not.toContain("no defined mapping");
  });

  // Both of these fail closed either way, but the raw JS error text
  // ("...map is not a function") should never be what lands in the deny's
  // reasoning, which is the audit record a human reads.
  it("reports a clean ModificationsInvalidError for a non-object redactions entry or a non-array redactions", () => {
    for (const modifications of [{ redactions: [null] }, { redactions: "abc" }, { redactions: [42] }]) {
      const out = validateDecision(
        { decision: "modify", reasoning: "r", modifications },
        { ...FRESH, modificationDocument: ARGS },
      );
      expect(out.decision).toBe("deny");
      expect(out.reasoning).toContain("modifications cannot be honoured as specified");
      expect(out.reasoning).not.toContain("is not a function");
    }
  });

  it("reports a clean ModificationsInvalidError for a non-object parameter_overrides", () => {
    const out = validateDecision(
      { decision: "modify", reasoning: "r", modifications: { parameter_overrides: ["command"] } },
      { ...FRESH, modificationDocument: ARGS },
    );
    expect(out.decision).toBe("deny");
    expect(out.reasoning).toContain("parameter_overrides must be an object");
  });
});

describe("validateDecision — ASK and DEFER expiry", () => {
  it("passes a fresh ask through untouched", () => {
    const ask = {
      decision: "ask",
      reasoning: "approval required",
      ask_details: { approver: { type: "user" }, question: "ok?", timeout_seconds: 60 },
    };
    expect(validateDecision(ask, { ...FRESH, modificationDocument: ARGS }).decision).toBe("ask");
  });

  it("substitutes an expired ask with its timeout_disposition", () => {
    const out = validateDecision(
      {
        decision: "ask",
        reasoning: "approval required",
        ask_details: { approver: { type: "user" }, question: "ok?", timeout_seconds: 1, timeout_disposition: "allow" },
      },
      { elapsedMs: 2_000, modificationDocument: ARGS },
    );
    expect(out.decision).toBe("allow");
    expect(out.reason_codes).toContain("ask_expired");
  });

  // ask-details.json defaults timeout_disposition to "deny", and §6 says that
  // default is deliberate. Absent must mean deny, never allow.
  it("denies an expired ask that names no timeout_disposition", () => {
    const out = validateDecision(
      {
        decision: "ask",
        reasoning: "approval required",
        ask_details: { approver: { type: "user" }, question: "ok?", timeout_seconds: 1 },
      },
      { elapsedMs: 2_000, modificationDocument: ARGS },
    );
    expect(out.decision).toBe("deny");
  });

  // Every other `ask` test here produces the same verdict
  // whether or not the timeout_seconds -> ms conversion happens at all
  // (1s/2000ms reads "expired" either way; 60s/10ms reads "not expired"
  // either way), so the `* 1000` was unverified. timeout_seconds: 1 is
  // 1000ms; elapsedMs: 500 is under that and so correctly not expired --
  // but if the conversion were dropped (comparing 500 against the bare
  // "1"), this would wrongly read as expired. Kept as its own case so a
  // future "simplification" that drops the multiply cannot pass unnoticed.
  it("does not expire an ask at 500ms against a 1-second timeout -- the case that catches a dropped seconds->ms conversion", () => {
    const out = validateDecision(
      {
        decision: "ask",
        reasoning: "approval required",
        ask_details: { approver: { type: "user" }, question: "ok?", timeout_seconds: 1 },
      },
      { elapsedMs: 500, modificationDocument: ARGS },
    );
    expect(out.decision).toBe("ask");
  });

  // Pins the exact boundary (strict `>`, per the module's own comment) so a
  // regression to `>=` would fail here even though every other `ask` test
  // above sits far past the boundary.
  // timeout_seconds: 1 -> timeoutMs 1000. Below, exactly at, and just past.
  it("expires an ask strictly after its timeout, not at or before it", () => {
    const askDetails = { approver: { type: "user" }, question: "ok?", timeout_seconds: 1 };
    expect(
      validateDecision(
        { decision: "ask", reasoning: "r", ask_details: askDetails },
        { elapsedMs: 999, modificationDocument: ARGS },
      ).decision,
    ).toBe("ask");
    expect(
      validateDecision(
        { decision: "ask", reasoning: "r", ask_details: askDetails },
        { elapsedMs: 1_000, modificationDocument: ARGS },
      ).decision,
    ).toBe("ask");
    expect(
      validateDecision(
        { decision: "ask", reasoning: "r", ask_details: askDetails },
        { elapsedMs: 1_001, modificationDocument: ARGS },
      ).decision,
    ).not.toBe("ask");
  });

  it("substitutes an expired defer with its timeout_decision, defaulting to deny", () => {
    const details = { reason: "low_confidence", resolution_method: "timeout", resolution_timeout_ms: 50 };
    // This pair already discriminates resolution_timeout_ms's own unit
    // (milliseconds, no conversion): 500 is past a 50ms timeout only because
    // 50 is read as milliseconds, not, say, mistakenly multiplied up as if
    // it were seconds (which would put the timeout at 50000ms and make 500
    // read as not-expired instead). No separate conversion case needed here
    // the way `ask` needed one above.
    expect(
      validateDecision({ decision: "defer", reasoning: "r", defer_details: details }, { elapsedMs: 500, modificationDocument: ARGS })
        .decision,
    ).toBe("deny");
    expect(
      validateDecision({ decision: "defer", reasoning: "r", defer_details: details }, { elapsedMs: 10, modificationDocument: ARGS })
        .decision,
    ).toBe("defer");
  });

  // defer-details.json permits `timeout_decision: "ask"`. Substituting it
  // naively would emit `{decision: "ask"}` with no `ask_details` -- a
  // message ACS's own schema rejects, and one this module's peer resolver
  // would deny as `ask_details_invalid` if anything ever asked it. Nothing
  // does: no substitution re-enters `validateDecision`, so a malformed ask
  // would go straight to the host's renderer.
  describe("an expired defer whose timeout_decision is ask", () => {
    const askOnTimeout = {
      reason: "low_confidence",
      resolution_method: "human_approval",
      resolution_timeout_ms: 50,
      timeout_decision: "ask",
    };

    const expired = () =>
      validateDecision(
        { decision: "defer", reasoning: "r", defer_details: askOnTimeout },
        { elapsedMs: 500, modificationDocument: ARGS },
      );

    it("denies closed rather than raising a question it cannot form", () => {
      expect(expired().decision).toBe("deny");
    });

    it("names the configuration fault, not merely an expiry", () => {
      // Its own code: an operator needs to know the deployment declared an
      // escalation the Guardian gave it no means to make.
      expect(expired().reason_codes).toEqual(["defer_ask_unaskable"]);
      expect(expired().reasoning).toContain("timeout_decision=ask");
    });

    it("never emits an ask whose ask_details its own peer would reject", () => {
      // The precise defect: an `ask` reaching a host with no approver,
      // question or timeout_seconds behind it.
      const substituted = expired();
      expect(substituted.decision).not.toBe("ask");
      expect(substituted.ask_details).toBeUndefined();
    });

    it("still returns the defer untouched inside its window", () => {
      expect(
        validateDecision(
          { decision: "defer", reasoning: "r", defer_details: askOnTimeout },
          { elapsedMs: 10, modificationDocument: ARGS },
        ).decision,
      ).toBe("defer");
    });
  });

  // `defer`'s own boundary, pinned the same way as `ask`'s above.
  // resolution_timeout_ms: 50 -- below, exactly at, and just past.
  it("expires a defer strictly after its resolution_timeout_ms, not at or before it", () => {
    const deferDetails = { reason: "low_confidence", resolution_method: "timeout", resolution_timeout_ms: 50 };
    expect(
      validateDecision(
        { decision: "defer", reasoning: "r", defer_details: deferDetails },
        { elapsedMs: 49, modificationDocument: ARGS },
      ).decision,
    ).toBe("defer");
    expect(
      validateDecision(
        { decision: "defer", reasoning: "r", defer_details: deferDetails },
        { elapsedMs: 50, modificationDocument: ARGS },
      ).decision,
    ).toBe("defer");
    expect(
      validateDecision(
        { decision: "defer", reasoning: "r", defer_details: deferDetails },
        { elapsedMs: 51, modificationDocument: ARGS },
      ).decision,
    ).not.toBe("defer");
  });

  it("denies an ask or defer whose details are missing entirely", () => {
    expect(validateDecision({ decision: "ask", reasoning: "r" }, { ...FRESH, modificationDocument: ARGS }).decision)
      .toBe("deny");
    expect(validateDecision({ decision: "defer", reasoning: "r" }, { ...FRESH, modificationDocument: ARGS }).decision)
      .toBe("deny");
  });
});

describe("validateDecision — everything else passes through", () => {
  it("leaves allow and deny exactly as they arrived", () => {
    const allow = { decision: "allow", reason_codes: ["drift_detected"], policy_references: [{ policy_id: "agt_stock", rule_id: "drift_detected" }] };
    expect(validateDecision(allow, { ...FRESH, modificationDocument: ARGS })).toEqual(allow);
    const deny = { decision: "deny", reasoning: "blocked", reason_codes: ["destructive_shell_command_blocked"] };
    expect(validateDecision(deny, { ...FRESH, modificationDocument: ARGS })).toEqual(deny);
  });

  // An arriving deny is honoured. There is no path in this
  // module that can turn one into anything else.
  it("never rewrites a deny", () => {
    for (const elapsed of [0, 1, 1_000_000]) {
      expect(validateDecision({ decision: "deny", reasoning: "r" }, { elapsedMs: elapsed, modificationDocument: ARGS }).decision)
        .toBe("deny");
    }
  });
});

/**
 * At a gate that sees what a step produced, the applied document still has
 * to be projected onto the output object the host already holds -- and that
 * projection happens inside this module's apply step, so a projection that
 * cannot land is the same `deny` as a rewrite that could not be applied.
 *
 * That placement is the property these tests exist for. Projecting after
 * `validateDecision` returned would put these failures outside the only catch
 * that can answer them with a decision, where a caller's delivery posture would
 * answer them instead -- and a `proceed` posture there is an unredacted output
 * delivered because a redaction could not be expressed. The end-to-end proof is
 * hosts/claude-code/test/post-tool-use.test.ts; this is the seam.
 */
describe("validateDecision — the result gate projects the applied document onto the host's output", () => {
  const OUTPUT_TARGET = {
    payload: {
      tool_response: { stdout: "TOKEN=ghp_ABCDEF123456", stderr: "", interrupted: false, isImage: false },
    },
    outputs: { from: "$.tool_response.stdout", within: "$.tool_response" },
  };
  /** The result payload the pointer below addresses -- what `modificationDocument`
   * answers for a result envelope, and not an arguments bag. */
  const RESULT_DOCUMENT = { tool: { name: "Bash" }, exit_status: "success", outputs: [{ value: "TOKEN=ghp_ABCDEF123456" }] };
  const REDACT = {
    decision: "modify",
    reasoning: "redaction_applied",
    modifications: { redactions: [{ path: "/outputs/0/value", replacement: "TOKEN=[REDACTED]" }] },
  };

  it("lands the applied leaf in `applied_output`, a clone of `within` with every sibling intact", () => {
    const out = validateDecision(REDACT, {
      ...FRESH,
      modificationDocument: RESULT_DOCUMENT,
      outputLocation: OUTPUT_TARGET,
    });

    expect(out.decision).toBe("modify");
    // The whole object: a replacement carrying the redacted leaf alone is the
    // shape the host silently discards, delivering the original.
    expect(out.applied_output).toEqual({
      stdout: "TOKEN=[REDACTED]",
      stderr: "",
      interrupted: false,
      isImage: false,
    });
    // `applied_input` is the other gate's field. A decision carries one or the
    // other, never both: an arguments bag is a tool input and a projected output
    // object is a tool result, and a host renders from the one its gate names.
    expect(out.applied_input).toBeUndefined();
  });

  it("does not mutate the payload the host handed us", () => {
    validateDecision(REDACT, { ...FRESH, modificationDocument: RESULT_DOCUMENT, outputLocation: OUTPUT_TARGET });

    expect(OUTPUT_TARGET.payload.tool_response.stdout).toBe("TOKEN=ghp_ABCDEF123456");
  });

  // The fail-closed case, and the reason `replacingOutput` compares types at
  // all: the host validates a replacement against the tool's own output schema
  // and delivers the original when it does not match. Prose in place of a number
  // is exactly that mismatch, so writing it would withhold nothing and redact
  // nothing -- while the decision reported a rewrite.
  it("denies, rather than throwing, when the replacement is not a shape the host's own leaf admits", () => {
    const out = validateDecision(REDACT, {
      ...FRESH,
      modificationDocument: RESULT_DOCUMENT,
      outputLocation: {
        payload: { tool_response: { stdout: 42, stderr: "" } },
        outputs: OUTPUT_TARGET.outputs,
      },
    });

    expect(out.decision).toBe("deny");
    expect(out.reason_codes).toContain("modifications_invalid");
    expect(out.applied_output).toBeUndefined();
    // The reason a human reads, and the defect this pins: rendering this
    // error's `.toString()` instead of its `.message` for a failed
    // projection would produce "guardian's modifications could not be
    // applied: Error: result-output: ..." -- raw JS error text in the
    // transcript and in the audit trail.
    expect(out.reasoning).toContain("guardian's modifications could not be applied: result-output:");
    expect(out.reasoning).not.toContain("Error:");
  });

  // The direction that is actually reachable, and the reason the comparison in
  // `replacingOutput` cannot be replaced by a claim about ACS's types.
  // `Redaction.replacement?: string` is a TypeScript type on a value that arrives
  // over the wire, and nothing checks it at runtime -- so a Guardian sending a
  // number reaches the projection with a number for a string leaf. The mirror
  // above (a non-string leaf, `stdout: 42`) is the one this deployment cannot
  // reach: `Bash`'s stdout is always prose, and a hookmap naming a leaf that is
  // not is refused by `assertOutputIsReplaceable` before a decision is sought.
  // This one needs no hookmap mistake at all, only a Guardian.
  it("denies a redaction whose replacement is not prose, for a leaf that is", () => {
    const out = validateDecision(
      {
        decision: "modify",
        reasoning: "redaction_applied",
        modifications: { redactions: [{ path: "/outputs/0/value", replacement: 42 }] },
      },
      { ...FRESH, modificationDocument: RESULT_DOCUMENT, outputLocation: OUTPUT_TARGET },
    );

    expect(out.decision).toBe("deny");
    expect(out.reason_codes).toContain("modifications_invalid");
    expect(out.applied_output).toBeUndefined();
    expect(out.reasoning).toContain("is a number where this tool produced a string");
  });

  // The hole in the guarantee, and the reason nothing here re-joins segments
  // into a path to look one up again. A type check that read its value
  // through `resolve(container, segments.join("."))` would re-parse -- and
  // the parse strips a leading `$`, because a hookmap path may start with
  // one. So a leaf segment of `$raw` would read as `raw` while the patch
  // still landed on `$raw`: the guard would inspect one field and the
  // replacement would go into another. Both fields are present below, with
  // different types, which is what makes the mismatch visible: re-joining
  // and re-parsing would return a `modify` carrying `{raw: "prose", $raw:
  // "TOKEN=[REDACTED]"}` -- prose where a boolean was, the exact shape the
  // host discards while delivering the original, produced by the check that
  // exists to prevent it.
  it("type-checks the field it patches, not one a re-parsed path resolves to", () => {
    const out = validateDecision(REDACT, {
      ...FRESH,
      modificationDocument: RESULT_DOCUMENT,
      outputLocation: {
        payload: { tool_response: { raw: "prose", $raw: false } },
        outputs: { from: "$.tool_response.$raw", within: "$.tool_response" },
      },
    });

    expect(out.decision).toBe("deny");
    expect(out.reason_codes).toContain("modifications_invalid");
    expect(out.applied_output).toBeUndefined();
    // Named for the boolean it would have replaced, not the string beside it.
    expect(out.reasoning).toContain("is a string where this tool produced a boolean");
  });

  // The path relation, checked on the segment arrays the patch is applied through
  // rather than inferred from their lengths. `buildEnvelope` checks the raw strings
  // and refuses this pair -- but `resolveByPosture` calls the projection on the
  // stage-"request" path, where `buildEnvelope` failed and may have failed on
  // exactly this check, so the projection cannot borrow it.
  it("refuses a path pair where `within` is not a leading part of `from`", () => {
    const out = validateDecision(REDACT, {
      ...FRESH,
      modificationDocument: RESULT_DOCUMENT,
      outputLocation: {
        payload: { tool_response: { stdout: "TOKEN=ghp_ABCDEF123456" }, other: { stdout: "x" } },
        outputs: { from: "$.other.stdout", within: "$.tool_response" },
      },
    });

    expect(out.decision).toBe("deny");
    expect(out.reason_codes).toContain("modifications_invalid");
    expect(out.reasoning).toContain("do not describe one leaf inside one object");
  });

  // The reserved-segment guard, which is the third place in this codebase to need
  // one. `$.tool_response.__proto__` resolves through inherited lookup, so it
  // satisfies every check both sides make, and `clone["__proto__"] = x` would set
  // a prototype instead of creating a field -- a clone identical to the payload,
  // and a decision reporting an applied rewrite that changed nothing. Refused by
  // name rather than left to the type comparison that happens to catch it.
  it("denies a rewrite whose hookmap path names a prototype segment rather than a field", () => {
    const out = validateDecision(REDACT, {
      ...FRESH,
      modificationDocument: RESULT_DOCUMENT,
      outputLocation: {
        payload: { tool_response: { stdout: "TOKEN=ghp_ABCDEF123456" } },
        outputs: { from: "$.tool_response.__proto__", within: "$.tool_response" },
      },
    });

    expect(out.decision).toBe("deny");
    expect(out.reason_codes).toContain("modifications_invalid");
    expect(out.reasoning).toContain('reserved segment "__proto__"');
  });

  // A pointer the ACS payload does have and the host's output object does not
  // reach. It applies cleanly to the document and changes nothing the host can
  // see, so the projection is the only place left that can notice -- and it
  // notices by finding no leaf to patch.
  it("denies a rewrite whose leaf the host payload does not have", () => {
    const out = validateDecision(REDACT, {
      ...FRESH,
      modificationDocument: RESULT_DOCUMENT,
      outputLocation: { payload: { tool_response: { stderr: "" } }, outputs: OUTPUT_TARGET.outputs },
    });

    expect(out.decision).toBe("deny");
    expect(out.reason_codes).toContain("modifications_invalid");
  });

  // The one the projection could not notice by failing, because it does not
  // fail. `/exit_status` is a field the ACS result payload really has, so §6.3's
  // apply step honours the redaction exactly as written; but the ACS payload
  // carries one leaf of the host's output object, and this rewrite went
  // somewhere else in the payload. The projection then builds a replacement out
  // of the untouched leaf and hands back the object the host already holds --
  // a `modify` reported as applied, an audit line recording a redaction, and the
  // original secret delivered to the model.
  //
  // Detected by asking whether the rewrite reached the leaf this gate projects,
  // rather than by comparing the pointer against `/outputs/0/value`: a pointer
  // comparison has to decide what an ancestor pointer means (`parameter_overrides`
  // replacing the whole `outputs` array does land) and still cannot say whether
  // an ancestor edit reached the leaf. This asks the question the hazard is
  // actually about -- did what the model reads change -- and it cannot drift from
  // the projection, because it is asked of the projection's own inputs.
  for (const modifications of [
    { redactions: [{ path: "/exit_status" }] },
    { redactions: [{ path: "/tool/name" }] },
    { parameter_overrides: { exit_status: "failure" } },
  ]) {
    it(`denies a rewrite that lands somewhere the host cannot be handed: ${JSON.stringify(modifications)}`, () => {
      const out = validateDecision(
        { decision: "modify", reasoning: "redaction_applied", modifications },
        { ...FRESH, modificationDocument: RESULT_DOCUMENT, outputLocation: OUTPUT_TARGET },
      );

      expect(out.decision).toBe("deny");
      expect(out.reason_codes).toContain("modifications_invalid");
      // Never an "applied" that applied nothing -- and never the original output
      // dressed as a rewrite.
      expect(out.applied_output).toBeUndefined();
      expect(out.reasoning).toContain("exactly as the step produced it");
      expect(out.reasoning).not.toContain("Error:");
    });
  }

  // The case the refusal above cannot tell apart from the ones above it, stated
  // as a test rather than left for a reader to discover: a redaction that
  // replaces the leaf with the value already there. The pointer is the right one
  // and nothing is malformed, and it is still refused -- because what this gate
  // can observe is the object the host will be handed, and that object is the
  // one the tool produced. A Guardian that wants the output delivered as
  // produced has `allow` for it; a `modify` indistinguishable from one is not a
  // rewrite this host can report. An over-refusal, deliberately, on the same
  // side as `assertOutputIsReplaceable`'s.
  //
  // This redaction's own target (`/outputs/0/value`) is a no-op on the ACS
  // document itself, so `applyModifications`'s post-condition
  // (modifications.ts) refuses it before `projectAppliedOutput` -- and its
  // own landing check -- is ever reached. The ruling this test demonstrates
  // is the same regardless of which check states it.
  it("denies a redaction that replaces the leaf with the value it already had", () => {
    const out = validateDecision(
      {
        decision: "modify",
        reasoning: "redaction_applied",
        modifications: { redactions: [{ path: "/outputs/0/value", replacement: "TOKEN=ghp_ABCDEF123456" }] },
      },
      { ...FRESH, modificationDocument: RESULT_DOCUMENT, outputLocation: OUTPUT_TARGET },
    );

    expect(out.decision).toBe("deny");
    expect(out.reason_codes).toContain("modifications_invalid");
    expect(out.applied_output).toBeUndefined();
    // The clause, not merely the disposition. This test is the only evidence for
    // the second half of the refusal's sentence, and without this assertion that
    // half could be deleted with the whole suite still passing -- so the test
    // would pass for a reason other than the one its name claims.
    expect(out.reasoning).toContain('the modification targeting "/outputs/0/value"');
    expect(out.reasoning).toContain("left that target exactly as it found it");
  });

  // The ancestor pointer, which is why this refusal asks whether the rewrite
  // reached the leaf rather than comparing the pointer against `/outputs/0/value`.
  // `parameter_overrides` replacing the whole `outputs` array is an ancestor of
  // the leaf and genuinely lands -- a strict pointer comparison would refuse it,
  // and one admitting ancestors would then have to allow the identical-value
  // version below, which does not land. Only asking the value can do both.
  it("applies an ancestor override that reaches the leaf, and denies the one that does not change it", () => {
    const landed = validateDecision(
      {
        decision: "modify",
        reasoning: "redaction_applied",
        modifications: { parameter_overrides: { outputs: [{ value: "TOKEN=[REDACTED]" }] } },
      },
      { ...FRESH, modificationDocument: RESULT_DOCUMENT, outputLocation: OUTPUT_TARGET },
    );
    expect(landed.decision).toBe("modify");
    expect(landed.applied_output).toEqual({
      stdout: "TOKEN=[REDACTED]",
      stderr: "",
      interrupted: false,
      isImage: false,
    });

    const unchanged = validateDecision(
      {
        decision: "modify",
        reasoning: "redaction_applied",
        modifications: { parameter_overrides: { outputs: [{ value: "TOKEN=ghp_ABCDEF123456" }] } },
      },
      { ...FRESH, modificationDocument: RESULT_DOCUMENT, outputLocation: OUTPUT_TARGET },
    );
    expect(unchanged.decision).toBe("deny");
    expect(unchanged.reason_codes).toContain("modifications_invalid");
  });

  // The landing check asks about one leaf, so a `modifications` object
  // bundling a leaf edit with a non-leaf one is a hazard: without the bundle
  // check below, the leaf would change, the non-leaf edit would be silently
  // dropped, and the whole `modify` would be reported applied. Each of these
  // non-leaf edits alone is denied by the cases above -- it is the bundling
  // that would hide it.
  //
  // `projectAppliedOutput`'s bundle check (result-output.ts) catches every
  // one of these: the leaf still lands, so the landing check above stays
  // silent, but comparing both documents with that one leaf subtracted out
  // finds the non-leaf edit every time. No secret ever reaches the model
  // here (the leaf redaction does land) -- what this closes is a false
  // audit and transcript record, a best-effort partial apply reported as a
  // full one. `mapVerdict` emits exactly one redaction, so nothing in this
  // deployment produces the shape either way; the test still pins the
  // adapter's own behaviour rather than leaving it to that.
  for (const modifications of [
    { redactions: [{ path: "/outputs/0/value", replacement: "TOKEN=[REDACTED]" }, { path: "/exit_status" }] },
    {
      redactions: [{ path: "/outputs/0/value", replacement: "TOKEN=[REDACTED]" }],
      parameter_overrides: { exit_status: "failure" },
    },
    { redactions: [{ path: "/outputs/0/value", replacement: "TOKEN=[REDACTED]" }, { path: "/tool/name" }] },
    { parameter_overrides: { outputs: [{ value: "TOKEN=[REDACTED]" }, { value: "nothing projects this" }] } },
  ]) {
    it(`denies a bundle whose non-leaf half would have been dropped: ${JSON.stringify(modifications)}`, () => {
      const out = validateDecision(
        { decision: "modify", reasoning: "redaction_applied", modifications },
        { ...FRESH, modificationDocument: RESULT_DOCUMENT, outputLocation: OUTPUT_TARGET },
      );

      expect(out.decision).toBe("deny");
      expect(out.reason_codes).toContain("modifications_invalid");
      // Never an "applied" that applied only part of itself.
      expect(out.applied_output).toBeUndefined();
      expect(out.reasoning).toContain("changed more of the ACS result payload than the one leaf");
    });
  }

  // The other refusal this gate owns. It is already refused before any
  // target is consulted (`assertValidModifications`), which is why this pins
  // the sentence rather than the disposition: the refusal has to be true of
  // the document these pointers actually address at a gate where the step
  // has already run, naming the outputs rather than an arguments object
  // alone.
  it("denies a modified_content result modification, naming the outputs as well as the arguments", () => {
    const out = validateDecision(
      { decision: "modify", reasoning: "r", modifications: { modified_content: "wholesale replacement" } },
      { ...FRESH, modificationDocument: RESULT_DOCUMENT, outputLocation: OUTPUT_TARGET },
    );

    expect(out.decision).toBe("deny");
    expect(out.reason_codes).toContain("modifications_invalid");
    expect(out.applied_output).toBeUndefined();
    expect(out.reasoning).toContain("the outputs it produced");
    // "no target", not "no mapping in this adapter" -- the fact is about what
    // the two documents a step's pointers address can hold, which is why it is
    // true at both gates, not only one of them.
    expect(out.reasoning).toContain("no target for it at either gate");
  });
});
