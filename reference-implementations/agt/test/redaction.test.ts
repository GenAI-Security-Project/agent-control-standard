import { describe, expect, it } from "bun:test";
import { fileURLToPath } from "node:url";
import { POLICY_TARGET_LEAF } from "guardian";
// The deployment subpath, not the barrel: the barrel is the governance verbs,
// and this is how the deployment builds a bridge. Using it rather than
// `createBridge` directly is what makes the bridges below the same ones a real
// Guardian evaluates against -- annotator included. The result-gate tests here
// would survive a bare bridge (that point declares no `annotations`), but a
// bridge that behaves like the deployment's at one gate and not the other is a
// trap for whoever adds the next test.
import { createDeploymentBridge } from "guardian/deployment";

const MANIFEST = fileURLToPath(new URL("../policy/manifest.yaml", import.meta.url));
const budgets = { budgets: { tool_call_count: 0, token_count: 0, elapsed_seconds: 0, cost_usd: 0 } };
// The label the Guardian's own session seed would have supplied. AGT's own
// severity ranking checks IFC first -- ahead of
// confidence, budgets, content_hash, egress, and pattern
// (policy/lib/agt_default.rego's header: "IFC deny > confidence deny >
// budget deny > content_hash deny > egress deny > pattern deny > drift warn
// > allow") -- so a hand-built snapshot with no labels at all no longer
// exercises the rule each of these tests is actually about; it denies with
// `ifc_clearance_violation` instead, before the redaction/pattern rule below
// it ever runs. This is what every Guardian-assembled snapshot now carries
// (packages/guardian/src/assemble-snapshot.ts), so it belongs here too.
const publicLabel = { input: { ifc: { source_labels: ["public"] } } };

describe("the shipped bundle redacts at the result gate", () => {
  it("returns a transform carrying the fully substituted output", async () => {
    const bridge = createDeploymentBridge(MANIFEST);
    const verdict = await bridge.evaluate("post_tool_call", {
      envelope: budgets,
      tool_call: { name: "Bash" },
      tool_result: { outputs: [{ value: "TOKEN=ghp_ABCDEF123456" }] },
      ...publicLabel,
    });
    expect(verdict).toEqual({
      decision: "transform",
      reason: "redaction_applied",
      transform: { path: "$policy_target", value: "TOKEN=[REDACTED]" },
    });
  });

  // AGT resolves `tool_name_from` before policy runs, so a snapshot with no
  // `tool_call` fails CLOSED rather than evaluating with a missing name.
  // Pinned because the Guardian synthesizes that member from the ACS payload,
  // and nothing else would notice if it stopped.
  it("fails closed when the snapshot carries no tool_call", async () => {
    const bridge = createDeploymentBridge(MANIFEST);
    const verdict = await bridge.evaluate("post_tool_call", {
      envelope: budgets,
      tool_result: { outputs: [{ value: "TOKEN=ghp_ABCDEF123456" }] },
    });
    expect(verdict.decision).toBe("deny");
    expect(verdict.reason).toBe("runtime_error:path_missing");
  });

  it("leaves output with nothing to redact as a clean allow", async () => {
    const bridge = createDeploymentBridge(MANIFEST);
    const verdict = await bridge.evaluate("post_tool_call", {
      envelope: budgets,
      tool_call: { name: "Bash" },
      tool_result: { outputs: [{ value: "hello world" }] },
      ...publicLabel,
    });
    // `result_labels: ["public"]` rides along now (measured): no
    // deny/transform/warn rule fires, so `agt_default.rego`'s severity
    // chain falls through to its own last "else" clause -- ifc_verdict's
    // allow, carrying whatever it propagated -- rather than the bare
    // `default verdict := {"decision": "allow"}`. A real, load-bearing
    // consequence of the gate being live and the snapshot carrying a label,
    // not a redaction-rule change.
    expect(verdict).toEqual({ decision: "allow", result_labels: ["public"] });
  });

  // The pre-tool gate must be untouched by adding a point below it in the
  // manifest. This is the assertion that would catch an additive manifest
  // edit turning out not to be additive.
  it("leaves the pre-tool deny exactly as it was", async () => {
    const bridge = createDeploymentBridge(MANIFEST);
    const verdict = await bridge.evaluate("pre_tool_call", {
      envelope: budgets,
      // `raw_command` for the same reason POLICY_TARGET_LEAF is here: this
      // point declares `annotations.egress.from: "$.tool_call.raw_command"`,
      // and that path is a liveness precondition -- unresolved, AGT denies
      // on runtime_error:path_missing before the pattern rule under test
      // runs. Every Guardian-assembled snapshot carries it
      // (packages/guardian/src/assemble-snapshot.ts), so this stand-in does
      // too. The post_tool_call fixtures above need none: `annotations` is
      // declared on the request gate only.
      tool_call: {
        name: "Bash",
        args: { command: "rm -rf / ", [POLICY_TARGET_LEAF]: "rm -rf / " },
        raw_command: "rm -rf / ",
      },
      ...publicLabel,
    });
    expect(verdict.decision).toBe("deny");
    expect(verdict.reason).toBe("destructive_shell_command_blocked");
  });
});
