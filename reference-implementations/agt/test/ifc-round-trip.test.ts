/**
 * The IFC round trip, against the real pinned bundle: AGT emits
 * `result_labels` at one step and reads them back as
 * `input.ifc.source_labels` at the next.
 *
 * Nothing here stubs the policy runtime. The gate is AGT's own
 * `agt.defaults` rule set, turned on through `data.agt.defaults.config`
 * alone, and the labels travel the path `policy/lib/agt_ifc.rego` actually
 * resolves.
 */
import { describe, expect, it } from "bun:test";
import { fileURLToPath } from "node:url";
import {
  createMemorySessionContextStore,
  persistIfcLabels,
  supplySourceLabels,
  POLICY_TARGET_LEAF,
} from "guardian";
// The deployment subpath, not the barrel: the barrel is the governance verbs,
// and this is how the deployment builds a bridge. Using it rather than
// `createBridge` directly is what makes the bridges below the same ones a real
// Guardian evaluates against -- annotator included.
import { createDeploymentBridge } from "guardian/deployment";

const MANIFEST = fileURLToPath(new URL("../policy/manifest.yaml", import.meta.url));
const budgets = { budgets: { tool_call_count: 0, token_count: 0, elapsed_seconds: 0, cost_usd: 0 } };
// Every pre_tool_call fixture below carries `raw_command` for the same reason
// it carries POLICY_TARGET_LEAF: policy/manifest.yaml's pre_tool_call point
// now declares `annotations.egress.from: "$.tool_call.raw_command"`, and that
// path is a liveness precondition -- AGT denies the whole call on
// runtime_error:path_missing when it does not resolve, before any rule these
// tests are about ever runs. assemble-snapshot.ts writes the member on every
// Guardian-assembled snapshot (the empty string when the wire carried none),
// so a hand-built stand-in has to carry it too. The values here reach no
// allowlisted or denied host, so the egress gate stays undefined and the
// gates under test keep their turn.

describe("the IFC round trip, on the shipped bundle", () => {
  it("propagates a label the session already carries, and returns it", async () => {
    const bridge = createDeploymentBridge(MANIFEST);
    const verdict = await bridge.evaluate("pre_tool_call", {
      envelope: budgets,
      tool_call: {
        name: "Bash",
        args: { command: "echo hello", [POLICY_TARGET_LEAF]: "echo hello" },
        raw_command: "echo hello",
        id: "req-1",
      },
      input: { ifc: { source_labels: ["confidential"] } },
    });
    expect(verdict.decision).toBe("allow");
    expect(verdict.result_labels).toEqual(["confidential"]);
  });

  it("denies a flow the configured clearance does not dominate", async () => {
    const bridge = createDeploymentBridge(MANIFEST);
    const verdict = await bridge.evaluate("pre_tool_call", {
      envelope: budgets,
      tool_call: {
        name: "Bash",
        args: { command: "echo hello", [POLICY_TARGET_LEAF]: "echo hello" },
        raw_command: "echo hello",
        id: "req-1",
      },
      input: { ifc: { source_labels: ["secret"] } },
    });
    expect(verdict.decision).toBe("deny");
    expect(verdict.reason).toBe("ifc_clearance_violation");
  });

  // Once the gate is live, an empty label set also denies
  // (agt_ifc.rego's own `test_missing_and_empty_labels_deny_fail_closed`
  // fails closed on `count(labels) == 0`), so a snapshot carrying only the
  // wrong-path label and nothing at the right path denies regardless of
  // which path AGT actually read -- "not deny" would not distinguish "read
  // nothing" from "read the secret". Supplying a valid, allow-worthy label at
  // the right path turns that ambiguity back into a real signal: if the
  // wrong-path "secret" label were read too, the effective label set would be
  // `["confidential", "secret"]`, "secret" would dominate, and a
  // "confidential" clearance would deny -- so an "allow" here is possible
  // only if the root-level `ifc` this snapshot also carries was never read.
  it("reads nothing from the path the upstream library uses, which AGT hosts do not populate", async () => {
    const bridge = createDeploymentBridge(MANIFEST);
    const verdict = await bridge.evaluate("pre_tool_call", {
      envelope: budgets,
      tool_call: {
        name: "Bash",
        args: { command: "echo hello", [POLICY_TARGET_LEAF]: "echo hello" },
        raw_command: "echo hello",
        id: "req-1",
      },
      input: { ifc: { source_labels: ["confidential"] } },
      // The trap agt_ifc_test.rego pins: labels at the snapshot root are not
      // read. Deliberately placed at the snapshot root rather than nested
      // under `input`.
      ifc: { source_labels: ["secret"] },
    } as never);
    expect(verdict.decision).toBe("allow");
    expect(verdict.result_labels).toEqual(["confidential"]);
  });

  // A fresh session starts at the lattice floor, not at `[]` --
  // `emptySessionState` seeds `ifc_labels: ["public"]`
  // (packages/guardian/src/session-context.ts) because AGT's own gate denies
  // a zero-label flow outright (the next test measures exactly that), so an
  // unseeded session could do nothing at all.
  it("carries one step's returned labels into the next step's snapshot", () => {
    const store = createMemorySessionContextStore();
    expect(supplySourceLabels(store, "sess-a")).toEqual(["public"]);
    persistIfcLabels(store, "sess-a", ["confidential"]);
    expect(supplySourceLabels(store, "sess-a")).toEqual(["confidential"]);
  });

  // Pinned here: an empty label set is a denied flow, not a permissive one.
  // `flow_allowed_with_lattice` (policy/lib/agt_ifc.rego) requires
  // `count(labels) > 0`, so `source_labels: []` never reaches the dominance
  // check at all -- `verdict_propagating` takes its violation branch
  // regardless of how permissive the configured clearance is. This is what
  // makes the session seed load-bearing rather than cosmetic: without it, a
  // fresh session's first step hits exactly this case.
  it("denies a session whose labels were cleared outright, because zero labels is a denied flow", async () => {
    const bridge = createDeploymentBridge(MANIFEST);
    const verdict = await bridge.evaluate("pre_tool_call", {
      envelope: budgets,
      tool_call: {
        name: "Bash",
        args: { command: "echo hello", [POLICY_TARGET_LEAF]: "echo hello" },
        raw_command: "echo hello",
        id: "req-1",
      },
      input: { ifc: { source_labels: [] } },
    });
    expect(verdict.decision).toBe("deny");
    expect(verdict.reason).toBe("ifc_clearance_violation");
  });

  // The precedence property the label-free fixtures elsewhere in this suite
  // depend on, pinned rather than assumed. `agt_default.rego`'s own header
  // states the combination order: "consults each one in priority order: IFC
  // deny > confidence deny > budget deny > content_hash deny > egress deny >
  // pattern deny > drift warn > allow" -- IFC deny outranks every other
  // gate, so a labelled snapshot that ALSO trips the pattern rule must
  // still deny for the pattern's own reason, not for IFC's: IFC has to
  // allow the flow (the seeded "public" label is dominated by this
  // deployment's "confidential" clearance) before the pattern check ever
  // runs. Without this test, giving those fixtures a `["public"]` label
  // would be indistinguishable from silencing them -- this is what proves
  // the gates still compose once a label is present, not just that adding
  // one makes a denial go away.
  it("still reaches the pattern gate once IFC allows the flow -- a labelled destructive command denies for the pattern's own reason", async () => {
    const bridge = createDeploymentBridge(MANIFEST);
    const verdict = await bridge.evaluate("pre_tool_call", {
      envelope: budgets,
      tool_call: {
        name: "Bash",
        args: { command: "rm -rf /", [POLICY_TARGET_LEAF]: "rm -rf /" },
        raw_command: "rm -rf /",
        id: "req-1",
      },
      input: { ifc: { source_labels: ["public"] } },
    });
    expect(verdict.decision).toBe("deny");
    expect(verdict.reason).toBe("destructive_shell_command_blocked");
  });
});
