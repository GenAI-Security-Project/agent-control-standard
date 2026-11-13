import { createHash } from "node:crypto";
import { describe, expect, it } from "bun:test";
import { type AgtEvidence, type EvidenceBridge } from "agt-bridge";
import { POLICY_TARGET_LEAF } from "guardian";
// The deployment subpath, not the barrel: the barrel is the governance verbs,
// and this is how the deployment builds a bridge. Same reason src/main.ts uses
// it -- these findings are only about the shipped deployment if the bridge is
// the shipped one.
import { createDeploymentBridge } from "guardian/deployment";
import { canonicalIdentity, measureIdentity, coverageCellsFromIdentity } from "../src/identity.ts";

const bridge = createDeploymentBridge("policy/manifest.yaml");

const REDACTABLE = {
  envelope: { budgets: { tool_call_count: 0, token_count: 0, elapsed_seconds: 0, cost_usd: 0 } },
  tool_call: { name: "Bash" },
  tool_result: { outputs: [{ value: "TOKEN=ghp_ONLYINOUTPUT999\n" }] },
  input: { ifc: { source_labels: ["public"] } },
};

describe("recomputing AGT's identity rather than believing it", () => {
  it("reproduces the identity of a policy input AGT hashed", async () => {
    const finding = await measureIdentity(bridge, "post_tool_call", REDACTABLE);

    expect(finding.input.recomputed).toBe(true);
  });

  it("finds the enforced identity bound to the policy target, not to the snapshot the host executes", async () => {
    const finding = await measureIdentity(bridge, "post_tool_call", REDACTABLE);

    expect(finding.input.identity).not.toBe(finding.enforced.identity);
    // The finding the slice publishes: boundTo resolves "policy_target", not
    // "snapshot", precisely because the snapshot's own copy of the redacted
    // leaf (policyInput.snapshot.tool_result.outputs[0].value) is left
    // holding the un-redacted token -- only policy_target.value was
    // replaced. resolveBinding computes the snapshot candidate too and it
    // does not match, which is what this assertion is actually resting on.
    expect(finding.enforced.boundTo).toBe("policy_target");
  });

  it("hashes key-sorted, whitespace-free JSON -- so key order and depth cannot change the identity, and whitespace does", () => {
    expect(canonicalIdentity({ b: 1, a: 2 })).toBe(canonicalIdentity({ a: 2, b: 1 }));
    // Depth: the sort has to reach a nested object, not just the top level.
    expect(canonicalIdentity({ outer: { b: 1, a: 2 } })).toBe(canonicalIdentity({ outer: { a: 2, b: 1 } }));
    // Whitespace: the same sorted document, hashed with JSON.stringify's own
    // indentation option, must NOT match canonicalIdentity's hash of it --
    // proving the function actually strips whitespace rather than happening
    // to produce a compact string today. (This is the same mutation the
    // review's own measurement caught: a 2-space-indent variant produces a
    // different hash than the pinned SDK's.)
    const indented = `sha256:${createHash("sha256").update(JSON.stringify({ a: 1, b: 2 }, null, 2)).digest("hex")}`;
    expect(canonicalIdentity({ a: 1, b: 2 })).not.toBe(indented);
    expect(canonicalIdentity({ a: 1 })).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("resolves the transform column guardian-only at the point actually measured, naming the absent wire field", async () => {
    const cells = coverageCellsFromIdentity(await measureIdentity(bridge, "post_tool_call", REDACTABLE));

    expect(cells).not.toHaveLength(0);
    for (const cell of cells) {
      expect(cell.point).toBe("post_tool_call");
      expect(cell.verdict).toBe("transform");
      expect(cell.status).toBe("guardian_only");
      expect(cell.reason).toMatch(/no action-identity field/);
    }
  });

  it("measures the no-rewrite case directly instead of asserting it: an allow at post_tool_call leaves input and enforced identity equal", async () => {
    // If AGT ever reported no transform while still computing a different
    // enforced identity, resolveBinding's own invariant check would throw
    // here rather than let this test pass silently -- so this test passing
    // at all is the measurement, not the equality assertion alone.
    const BENIGN = { ...REDACTABLE, tool_result: { outputs: [{ value: "hello" }] } };
    const finding = await measureIdentity(bridge, "post_tool_call", BENIGN);

    expect(finding.input.recomputed).toBe(true);
    expect(finding.input.identity).toBe(finding.enforced.identity);
    expect(finding.enforced.boundTo).toBe("no_rewrite");
  });

  it("resolves unexpressed when AGT's reported input identity cannot be reproduced from the policy input it also reported", async () => {
    // A stand-in bridge, not the real one: the pinned SDK always reproduces
    // (the first test above measures that), so the only way to exercise this
    // branch is a bridge that reports an inputIdentity its own policyInput
    // does not hash to.
    const lying: EvidenceBridge = {
      // No `evaluate`: this check depends on `EvidenceBridge` alone.
      async evaluateWithEvidence() {
        return {
          verdict: { decision: "transform", transform: { path: "$policy_target", value: "x" } },
          policyInput: { policy_target: { path: "$.a", value: "y" }, snapshot: { a: "y" } },
          inputIdentity: `sha256:${"0".repeat(64)}`,
          enforcedIdentity: `sha256:${"1".repeat(64)}`,
        };
      },
    };

    const finding = await measureIdentity(lying, "post_tool_call", {});
    expect(finding.input.recomputed).toBe(false);

    const cells = coverageCellsFromIdentity(finding);
    expect(cells).toHaveLength(1);
    expect(cells[0]).toMatchObject({ point: "post_tool_call", verdict: "transform", status: "unexpressed" });
    expect(cells[0]!.reason).toMatch(/could not be reproduced/);
  });

  it("rejects a point AGT does not have, rather than measuring one silently", async () => {
    await expect(measureIdentity(bridge, "not_a_real_point", REDACTABLE)).rejects.toThrow(/not_a_real_point/);
  });
});

describe("the request gate, measured rather than assumed to match the result gate", () => {
  // Same mechanism as REDACTABLE above, at the other of mapping.yaml's two
  // `modifications` rows: policy/lib/agt_default.rego's redact_verdict reads
  // input.policy_target.value regardless of intervention_point, and
  // pre_tool_call's policy_target ("$.tool_call.args.acs_policy_target",
  // policy/manifest.yaml) is a string a ghp_ token can appear in exactly the
  // same way it appears in a tool_result value. `acs_policy_target` mirrors
  // what assemble-snapshot.ts copies a tool's own policy-target argument to;
  // `command` rides along beside it because that is what a real Bash call's
  // snapshot carries too.
  const REDACTABLE_COMMAND = {
    envelope: { budgets: { tool_call_count: 0, token_count: 0, elapsed_seconds: 0, cost_usd: 0 } },
    tool_call: {
      name: "Bash",
      args: { command: "echo ghp_ONLYINCOMMAND999", [POLICY_TARGET_LEAF]: "echo ghp_ONLYINCOMMAND999" },
      // The request gate's `annotations.egress.from` names this member, and an
      // annotation's `from` is a liveness precondition: unresolved, AGT denies
      // the whole call on runtime_error:path_missing before any rule runs.
      raw_command: "echo ghp_ONLYINCOMMAND999",
      id: "t1",
    },
    input: { ifc: { source_labels: ["public"] } },
  };

  it("reproduces the identity and finds the same policy_target binding pre_tool_call finds at post_tool_call", async () => {
    const finding = await measureIdentity(bridge, "pre_tool_call", REDACTABLE_COMMAND);

    expect(finding.input.recomputed).toBe(true);
    expect(finding.input.identity).not.toBe(finding.enforced.identity);
    // MEASURED, not assumed from the result gate's own finding above: the
    // request gate was driven independently through the real bridge and its
    // enforced identity was recomputed against both candidates the same way.
    expect(finding.enforced.boundTo).toBe("policy_target");
  });

  it("resolves both gates' transform cells guardian-only with the identical reason -- not forced to agree, found to", async () => {
    const [preCells, postCells] = await Promise.all([
      measureIdentity(bridge, "pre_tool_call", REDACTABLE_COMMAND).then(coverageCellsFromIdentity),
      measureIdentity(bridge, "post_tool_call", REDACTABLE).then(coverageCellsFromIdentity),
    ]);

    expect(preCells[0]!.point).toBe("pre_tool_call");
    expect(postCells[0]!.point).toBe("post_tool_call");
    expect(preCells[0]!.status).toBe(postCells[0]!.status);
    expect(preCells[0]!.reason).toBe(postCells[0]!.reason);
  });
});

describe("boundTo's four outcomes, each measured with synthetic evidence and asserted against its own reason", () => {
  // resolveBinding's parameter is a structural type (policyInput,
  // inputIdentity, enforcedIdentity, verdict.transform?), so reaching every
  // branch does not need the real bridge -- only a stand-in whose
  // evaluateWithEvidence returns hand-built evidence, the same technique the
  // unexpressed-branch test above uses for `recomputed`. Only "policy_target"
  // is reachable through the real bridge today (both measured gates resolve
  // it); "snapshot", "unattributable" and "no_rewrite" are real, distinct
  // code paths that no real-bridge fixture drives, so this is the only place
  // their reason strings are checked against what actually produced them
  // rather than against the one origin a reader had in mind while writing
  // it.
  const SYNTHETIC_INPUT = {
    policy_target: { path: "$.tool_result.outputs[0].value", value: "before" },
    snapshot: { tool_result: { outputs: [{ value: "before" }] } },
  };
  const inputIdentity = canonicalIdentity(SYNTHETIC_INPUT);

  const evidenceBridge = (evidence: AgtEvidence): EvidenceBridge => ({
    // No `evaluate`: this check depends on `EvidenceBridge` alone.
    async evaluateWithEvidence() {
      return evidence;
    },
  });

  it("policy_target: enforced identity matches a hash with policy_target.value alone replaced", async () => {
    const policyTargetOnly = { ...SYNTHETIC_INPUT, policy_target: { ...SYNTHETIC_INPUT.policy_target, value: "after" } };
    const evidence: AgtEvidence = {
      verdict: { decision: "transform", transform: { path: "$policy_target", value: "after" } },
      policyInput: SYNTHETIC_INPUT,
      inputIdentity,
      enforcedIdentity: canonicalIdentity(policyTargetOnly),
    };

    const finding = await measureIdentity(evidenceBridge(evidence), "post_tool_call", {});
    expect(finding.enforced.boundTo).toBe("policy_target");

    const [cell] = coverageCellsFromIdentity(finding);
    expect(cell!.status).toBe("guardian_only");
    expect(cell!.reason).toBe(
      "ACS v0.1.0 carries no action-identity field on any of its 44 schemas, so a wire consumer cannot bind an " +
        "approval to the action that executed; AGT's enforced identity binds to the policy target it rewrote, not " +
        "to the document the host applies modifications to",
    );
  });

  it("snapshot: enforced identity matches a hash with the snapshot leaf replaced instead of policy_target.value", async () => {
    const snapshotOnly = structuredClone(SYNTHETIC_INPUT);
    snapshotOnly.snapshot.tool_result.outputs[0]!.value = "after";
    const evidence: AgtEvidence = {
      verdict: { decision: "transform", transform: { path: "$policy_target", value: "after" } },
      policyInput: SYNTHETIC_INPUT,
      inputIdentity,
      enforcedIdentity: canonicalIdentity(snapshotOnly),
    };

    const finding = await measureIdentity(evidenceBridge(evidence), "post_tool_call", {});
    expect(finding.enforced.boundTo).toBe("snapshot");

    const [cell] = coverageCellsFromIdentity(finding);
    expect(cell!.status).toBe("guardian_only");
    expect(cell!.reason).toBe(
      "AGT's enforced identity in this run binds to the snapshot leaf policy_target.path addresses -- the document " +
        "the host will actually execute after the rewrite -- rather than to policy_target.value alone; ACS v0.1.0 " +
        "still carries no action-identity field on any of its 44 schemas for a wire consumer to check it against",
    );
  });

  it("unattributable: a transform was reported, both candidates were computed, and neither matched", async () => {
    const evidence: AgtEvidence = {
      verdict: { decision: "transform", transform: { path: "$policy_target", value: "after" } },
      policyInput: SYNTHETIC_INPUT,
      inputIdentity,
      enforcedIdentity: `sha256:${"a".repeat(64)}`,
    };

    const finding = await measureIdentity(evidenceBridge(evidence), "post_tool_call", {});
    expect(finding.enforced.boundTo).toBe("unattributable");

    const [cell] = coverageCellsFromIdentity(finding);
    expect(cell!.status).toBe("unexpressed");
    expect(cell!.reason).toBe(
      "AGT's enforced identity does not match a hash of the policy input with policy_target.value replaced by the " +
        "reported transform, nor one with the snapshot leaf policy_target.path addresses replaced the same way -- " +
        "this check cannot attribute it to either document",
    );
  });

  it("no_rewrite: no transform reported, so no comparison was attempted -- a different claim from unattributable's", async () => {
    const evidence: AgtEvidence = {
      verdict: { decision: "allow" },
      policyInput: SYNTHETIC_INPUT,
      inputIdentity,
      enforcedIdentity: inputIdentity,
    };

    const finding = await measureIdentity(evidenceBridge(evidence), "post_tool_call", {});
    expect(finding.enforced.boundTo).toBe("no_rewrite");

    const [cell] = coverageCellsFromIdentity(finding);
    expect(cell!.status).toBe("unexpressed");
    expect(cell!.reason).toBe(
      "AGT reported no transform for this policy input: there is no rewritten document to attribute its enforced " +
        "identity to, and this check made no policy_target/snapshot comparison -- input and enforced identity are " +
        "equal by construction, not because either candidate was tested and matched",
    );
    // The two "nothing to point at" statuses share `unexpressed`, but their
    // reasons must not collapse back into one claim: this is exactly what
    // round 1's single "neither" value and reason did, and round 2 exists to
    // keep them apart.
    expect(cell!.reason).not.toBe(
      "AGT's enforced identity does not match a hash of the policy input with policy_target.value replaced by the " +
        "reported transform, nor one with the snapshot leaf policy_target.path addresses replaced the same way -- " +
        "this check cannot attribute it to either document",
    );
  });
});
