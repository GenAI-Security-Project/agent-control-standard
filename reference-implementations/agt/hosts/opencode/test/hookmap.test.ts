/**
 * opencode.hookmap.yaml's load-time contract: it loads, maps both gates onto
 * the right ACS method, declares the metadata mirror the result gate needs
 * (`outputs.mirrors`), and expresses a request-gate deny as a refusal but a
 * result-gate deny as a replacement -- never a throw, because a throw at the
 * result gate discards the plugin's mutations and OpenCode rebuilds `metadata`
 * from its own pre-hook copy (measured).
 *
 * Same shape as hosts/claude-code/test/hook.test.ts's own hookmap coverage;
 * this file is scoped to the hookmap alone, not the plugin shim.
 */
import { describe, expect, it } from "bun:test";
import { fileURLToPath } from "node:url";
import { buildEnvelope, loadHookmap } from "host-adapter";
import { validateEnvelope } from "guardian";

const HOOKMAP = fileURLToPath(new URL("../opencode.hookmap.yaml", import.meta.url));

// `Hookmap.decisions` is deliberately typed `Record<string, unknown>` -- this
// package knows ACS and hookmaps, nothing else, so it names no decision
// vocabulary of its own. Indexing into a specific decision's `output` block
// therefore needs a local, test-only shape -- the same move
// hosts/claude-code/test/posture.test.ts makes when it reads a hookmap's
// decisions directly.
type DecisionsShape = Record<string, { output: Record<string, unknown> }>;

describe("opencode.hookmap.yaml", () => {
  it("loads, and maps both gates", () => {
    const hookmap = loadHookmap(HOOKMAP);
    expect(hookmap.host).toBe("opencode");
    expect(hookmap.hooks["tool.execute.before"]?.acs_method).toBe("steps/toolCallRequest");
    expect(hookmap.hooks["tool.execute.after"]?.acs_method).toBe("steps/toolCallResult");
  });

  it("declares the metadata mirror at the result gate", () => {
    const after = loadHookmap(HOOKMAP).hooks["tool.execute.after"];
    expect(after?.outputs?.mirrors).toEqual(["$.result.metadata.output"]);
  });

  it("expresses a request-gate deny as a refusal and a result-gate deny as a replacement", () => {
    const hooks = loadHookmap(HOOKMAP).hooks;
    const requestDecisions = hooks["tool.execute.before"]!.decisions as DecisionsShape;
    expect(Object.keys(requestDecisions.deny!.output)).toContain("refuse.reason");
    // `refuse.reason` alone is a `from:` field and renders nothing when the
    // arriving decision carries no `reasoning` (or the wrong type of it).
    // `refuse.denied: { value: true }` is the unconditional sibling that
    // keeps `deny`/`ask`/`defer` from ever rendering `{}`. Declared on all
    // three; asserted on all three here, not only `deny`.
    for (const decisionName of ["deny", "ask", "defer"] as const) {
      expect(Object.keys(requestDecisions[decisionName]!.output)).toContain("refuse.denied");
    }
    // Measured: a throw at the result gate discards the mutation channel, so the
    // mirror keeps the secret. Deny there withholds by replacing, never by throwing.
    //
    // The sink is `result`, the container at `outputs.within` -- not
    // `result.output`, a leaf. `result` is a string on this host;
    // `applied_output` is the whole patched clone of the `outputs.within`
    // object, mirror included, so naming the leaf would assign an object to a
    // string field and bury the mirror's own patched copy one level too deep
    // for OpenCode to ever apply.
    const resultDecisions = hooks["tool.execute.after"]!.decisions as DecisionsShape;
    const resultDeny = Object.keys(resultDecisions.deny!.output);
    expect(resultDeny).toContain("result");
    expect(resultDeny).not.toContain("result.output");
    expect(resultDeny).not.toContain("refuse.reason");
  });

  it("exercises acs-plugin.ts's assertHostAcceptsEveryDecision sink branch, not its refusal branch -- non-vacuously", () => {
    // The gate accepts a decision that can either land what it arrived
    // carrying or unconditionally refuse (acs-plugin.ts's `satisfiesGate`).
    // That means "the shipped hookmap passes the gate" is not, by itself,
    // evidence that the sink rules work: a file that declared `refuse.denied`
    // everywhere would pass them too, via the other branch, and every sink
    // test in acs-plugin.test.ts would still be green while this file's own
    // decisions rendered nothing.
    //
    // This pins that the shipped file takes the sink branch, by asserting it
    // declares no `refuse` path at all on any decision the sink rules govern.
    // A future edit that "fixed" a gate failure by adding a refusal marker to
    // one of these would fail here rather than quietly turning the sink rules
    // vacuous.
    const hooks = loadHookmap(HOOKMAP).hooks;
    const requestDecisions = hooks["tool.execute.before"]!.decisions as DecisionsShape;
    const resultDecisions = hooks["tool.execute.after"]!.decisions as DecisionsShape;

    const refusePaths = (paths: string[]) => paths.filter((path) => path.split(".")[0] === "refuse");

    // The request gate's `modify` is governed by the args-sink rule.
    expect(Object.keys(requestDecisions.modify!.output)).toContain("args");
    expect(refusePaths(Object.keys(requestDecisions.modify!.output))).toEqual([]);

    // The result gate's withholding decisions are governed by the result-sink
    // rule, and `ask`/`defer` are now among them: `withholdsAtResultGate`
    // admits every disposition but `allow` and `modify`, so all four declared
    // here must name the sink rather than a refusal. Listing them explicitly,
    // rather than walking whatever the file happens to declare, is what makes
    // a dropped entry fail here -- an absent decision declares nothing, and a
    // check that only walked what is present would pass on the gap.
    expect(Object.keys(resultDecisions).sort()).toEqual(["allow", "ask", "defer", "deny", "modify"]);
    for (const decisionName of ["deny", "modify", "ask", "defer"] as const) {
      expect(Object.keys(resultDecisions[decisionName]!.output)).toContain("result");
      expect(refusePaths(Object.keys(resultDecisions[decisionName]!.output))).toEqual([]);
    }

    // And the sinks are a renderable declaration, not merely the right key:
    // no `value` beside the `from`, and no `type` that a `typeof` check on an
    // object would fail.
    for (const output of [
      requestDecisions.modify!.output as Record<string, Record<string, unknown>>,
      resultDecisions.deny!.output as Record<string, Record<string, unknown>>,
      resultDecisions.modify!.output as Record<string, Record<string, unknown>>,
    ]) {
      const sink = (output.args ?? output.result)!;
      expect(Object.hasOwn(sink, "value")).toBe(false);
      expect(sink.type === undefined || sink.type === "object").toBe(true);
    }
  });

  it("scopes the result gate to bash alone, and the request gate to bash and webfetch", () => {
    // OpenCode fires the result gate's hook for every tool with no matcher,
    // and `metadata` is per-tool -- only `bash` carries
    // `metadata.exit`/`metadata.output`, which this gate's `outputs` and
    // `exit_status` paths are shaped for. The Claude Code host gets the
    // equivalent scoping for free from settings.json's anchored `^Bash$`
    // matcher; OpenCode has none, so it is declared here instead.
    const hooks = loadHookmap(HOOKMAP).hooks;
    expect(hooks["tool.execute.after"]?.tools).toEqual(["bash"]);
    // The request gate's own paths ($.tool, $.args) resolving for every tool
    // does not mean the gate governs every tool -- measured directly against
    // policy/manifest.yaml's fixed `policy_target`, which is checked before
    // any authored rule runs, independent of the tool registry. An unscoped
    // request gate would ask the Guardian about every tool it can never
    // register a target for, and get an unconditional deny back rather than a
    // policy decision. Scoped to `bash` and `webfetch` -- the two tools
    // mapping.yaml's policy_target_argument table now knows how to read a
    // target from -- for the same reason the result gate is scoped at all:
    // every other tool is declined here, not asked and mis-answered.
    expect(hooks["tool.execute.before"]?.tools).toEqual(["bash", "webfetch"]);
  });

  it("builds a wire payload of exactly {tool, exit_status, outputs:[{value}]}, with no mirrors anywhere in it", () => {
    // This is the first hookmap that actually declares `outputs.mirrors`, so
    // this is the first place a mirror leaking onto the wire could be caught.
    // `buildPayload` never reads `mirrors` -- this asserts the envelope it
    // produces proves that, not just that the function doesn't.
    const hookmap = loadHookmap(HOOKMAP);
    const payload = {
      tool: "bash",
      // buildEnvelope reads `session_id` directly (not hookmap-driven, the
      // same ACS-side convention every host's assembled payload supplies) --
      // `sessionID` is OpenCode's own field name, carried alongside it the way
      // the plugin shim will actually assemble this object.
      sessionID: "6c616a11-495a-4f05-878a-c1bfaa29f0e5",
      session_id: "6c616a11-495a-4f05-878a-c1bfaa29f0e5",
      callID: "call-1",
      args: { command: "cat .env" },
      result: {
        title: "bash",
        output: "TOKEN=ghp_ABCDEF123456",
        metadata: { output: "TOKEN=ghp_ABCDEF123456", exit: 0, truncated: false },
        attachments: [],
      },
    };

    const envelope = buildEnvelope("tool.execute.after", payload, hookmap);

    expect(() => validateEnvelope(envelope)).not.toThrow();
    expect(envelope.params.payload).toEqual({
      tool: { name: "bash" },
      exit_status: "success",
      outputs: [{ value: "TOKEN=ghp_ABCDEF123456" }],
    });
    expect(JSON.stringify(envelope.params.payload)).not.toContain("mirrors");
  });
});
