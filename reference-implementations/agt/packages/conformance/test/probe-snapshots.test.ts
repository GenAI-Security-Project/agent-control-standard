import { describe, expect, it } from "bun:test";
import type { InterventionSnapshot } from "agt-bridge";
import { POLICY_TARGET_LEAF } from "guardian";
import { assertPolicyTarget, PRE_TOOL_CALL_SNAPSHOT } from "../src/probe-snapshots.ts";

const COMMAND = "echo ghp_ONLYINCOMMAND999";

function withLeaf(leaf: unknown): InterventionSnapshot {
  const args: Record<string, unknown> = { command: COMMAND };
  if (leaf !== undefined) args[POLICY_TARGET_LEAF] = leaf;
  return { tool_call: { name: "Bash", args } } as unknown as InterventionSnapshot;
}

describe("the pre_tool_call probe's policy target", () => {
  it("is the request's own command in the snapshot the assembler built", () => {
    const args = (PRE_TOOL_CALL_SNAPSHOT as { tool_call: { args: Record<string, unknown> } }).tool_call.args;
    expect(args[POLICY_TARGET_LEAF]).toBe(COMMAND);
  });

  it("names the field when the leaf is missing", () => {
    expect(() => assertPolicyTarget(withLeaf(undefined), "command", COMMAND)).toThrow(`tool_call.args.${POLICY_TARGET_LEAF}`);
  });

  it("refuses a leaf that holds some other string", () => {
    expect(() => assertPolicyTarget(withLeaf("echo safe"), "command", COMMAND)).toThrow(`not the request's "command" argument`);
  });

  it("accepts the request's own argument", () => {
    expect(() => assertPolicyTarget(withLeaf(COMMAND), "command", COMMAND)).not.toThrow();
  });
});
