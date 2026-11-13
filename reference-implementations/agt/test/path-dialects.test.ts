/**
 * Three path dialects, and the agreements this file checks between them.
 *
 * A single rewrite is addressed several different ways along its route:
 *
 *   AGT   policy/manifest.yaml's `policy_target`, JSONPath over the SNAPSHOT.
 *         For the request gate this is now always the one normalised leaf
 *         (`$.tool_call.args.acs_policy_target`); for the result gate it is
 *         still `$.tool_result.outputs[0].value`.
 *   ACS   mapping.yaml's `policy_target_argument` table (per tool, at the
 *         request gate) and `into_path` (at the result gate), addressing the
 *         ACS PAYLOAD.
 *   host  the hookmap's `outputs.from` / `arguments`, addressing the HOST's own
 *         payload (`$.tool_response.stdout`)
 *
 * Their agreement is checked here rather than left to prose in three files,
 * each telling the reader to go and verify another. A comment is not a check:
 * moving `policy_target` one field over would leave mapping.yaml describing a
 * leaf nothing targets, and the demo would simply stop redacting.
 *
 * THREE AGREEMENTS NOW, NOT ONE DERIVATION. The request gate's manifest
 * target no longer names a host argument at all -- AGT allows an
 * intervention point exactly one target, and two tools disagree about their
 * argument names, so the target instead names the single normalised leaf the
 * Guardian writes. What is checked for that gate is therefore that the
 * manifest and the assembler (assemble-snapshot.ts's POLICY_TARGET_LEAF)
 * name the same leaf, not that the manifest and mapping.yaml derive one
 * another. The result gate keeps the original derivation: its target and
 * mapping.yaml's `into_path` still address the same document, member for
 * member, so one is still derivable from the other. And the by_tool table's
 * own agreement with the manifest is checked too, but only for tool
 * existence: the manifest registry can say WebFetch is registered, not that
 * WebFetch takes a `url`.
 *
 * The host dialect is not derivable and must not be: `$.tool_response.stdout`
 * addresses a document this project does not define, whose shape is the
 * host's own. Absorbing that difference is the hookmap's entire job and the
 * reason the same adapter serves a second host, so a check that "derived" it
 * would be asserting a coincidence of this one deployment. What keeps THAT
 * seam honest is a different mechanism, one gate over: `assertOutputIsReplaceable`
 * refuses, before any decision is sought, a deployment whose hookmap cannot
 * address a replaceable leaf in the payload it was handed.
 */
import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { POLICY_TARGET_LEAF } from "../packages/guardian/src/assemble-snapshot.ts";

type ManifestPoint = { policy_target?: string; policy_target_kind?: string };

type MappingRule = { into: "parameter_overrides" } | { into: "redactions"; into_path: string };
type PolicyTargetArgument = { default: string; by_tool?: Record<string, string> };
type MappingPoint = {
  acs_method: string | null;
  policy_target_argument?: PolicyTargetArgument;
  modifications?: MappingRule;
};
type Mapping = { intervention_points: Record<string, MappingPoint> };
type Manifest = {
  intervention_points: Record<string, ManifestPoint>;
  tools: Record<string, unknown>;
};

const manifest = Bun.YAML.parse(readFileSync("policy/manifest.yaml", "utf8")) as Manifest;
const mapping = Bun.YAML.parse(readFileSync("mapping.yaml", "utf8")) as Mapping;

/**
 * The ACS-side address of the leaf an AGT `policy_target` names.
 *
 * The two notations differ in exactly two ways, and both are mechanical:
 * AGT's path is rooted at the snapshot member for the gate (`tool_call.args`
 * for a request, `tool_result` for a result), and it uses JSONPath's dotted
 * and bracketed segments where ACS uses a JSON pointer.
 *
 * Throws rather than answering for a target it does not recognise: a silent
 * fallback would let a manifest edit pass this file by not matching any rule.
 */
function acsAddressOf(policyTarget: string): { kind: "argument" | "pointer"; address: string } {
  const argument = /^\$\.tool_call\.args\.([A-Za-z_][A-Za-z0-9_]*)$/.exec(policyTarget);
  if (argument) {
    // ACS expresses a rewritten tool argument as parameter_overrides keyed by
    // argument NAME, so the ACS address is the leaf segment alone.
    return { kind: "argument", address: argument[1] as string };
  }

  const result = /^\$\.tool_result((?:\.[A-Za-z_][A-Za-z0-9_]*|\[\d+\])+)$/.exec(policyTarget);
  if (result) {
    // The ACS result payload IS what `$.tool_result` names, so the pointer is
    // the remainder with its segments rewritten: `.value` -> `/value`,
    // `[0]` -> `/0`.
    const pointer = (result[1] as string).replace(/\[(\d+)\]/g, ".$1").replace(/\./g, "/");
    return { kind: "pointer", address: pointer };
  }

  throw new Error(
    `this check does not know how to express the AGT policy_target ${JSON.stringify(policyTarget)} as an ACS ` +
      `address -- add the rule here rather than removing the point from the table below`,
  );
}

describe("the AGT and ACS dialects address the same leaf", () => {
  const gated = Object.entries(mapping.intervention_points).filter(([, row]) => row.modifications !== undefined);

  it("covers every point mapping.yaml gives a modifications rule", () => {
    expect(gated.map(([point]) => point).sort()).toEqual(["post_tool_call", "pre_tool_call"]);
  });

  // AGREEMENT ONE. The request gate's manifest target no longer names a host
  // argument at all: it names the single normalised leaf the Guardian writes
  // every tool's policy target to, because AGT allows an intervention point
  // exactly one target and two tools disagree about their argument names. So
  // what is derived here is that the manifest and the assembler name the SAME
  // leaf -- one derivation, as before, of a different pair.
  it("pre_tool_call: the manifest targets the leaf the assembler writes", () => {
    const policyTarget = manifest.intervention_points.pre_tool_call?.policy_target;
    expect(policyTarget).toBeString();
    const derived = acsAddressOf(policyTarget as string);
    expect(derived.kind).toBe("argument");
    expect(derived.address).toBe(POLICY_TARGET_LEAF);
  });

  // AGREEMENT TWO, unchanged: the result gate rewrites a leaf of the result
  // payload, addressed by an ACS JSON pointer derived from the same JSONPath.
  it("post_tool_call: mapping.yaml's pointer is derivable from the manifest's policy_target", () => {
    const policyTarget = manifest.intervention_points.post_tool_call?.policy_target;
    expect(policyTarget).toBeString();
    const derived = acsAddressOf(policyTarget as string);
    const rule = mapping.intervention_points.post_tool_call?.modifications as { into: "redactions"; into_path: string };
    expect(derived.kind).toBe("pointer");
    expect(rule.into_path).toBe(derived.address);
  });

  // AGREEMENT THREE, and the honest half of it is stated in the test's own
  // name. The registry can say WebFetch is registered; it cannot say WebFetch
  // takes a `url`. Same limit the upstream watch measured for hookmap `tools`
  // entries, and for the same reason: one manifest serves both hosts, so it
  // names more tools than either dispatches.
  it("every tool the by_tool table keys is one the manifest registry knows -- existence only, not argument shape", () => {
    const registered = new Set(Object.keys(manifest.tools ?? {}));
    for (const [point, row] of Object.entries(mapping.intervention_points)) {
      for (const tool of Object.keys(row.policy_target_argument?.by_tool ?? {})) {
        expect({ point, tool, registered: registered.has(tool) }).toEqual({ point, tool, registered: true });
      }
    }
  });

  it("declares a default argument for every gate that rewrites one", () => {
    for (const [point, row] of gated) {
      if ((row.modifications as MappingRule).into !== "parameter_overrides") continue;
      expect({ point, declared: typeof row.policy_target_argument?.default }).toEqual({ point, declared: "string" });
    }
  });

  it("refuses a policy_target shape it cannot express, rather than passing by default", () => {
    expect(() => acsAddressOf("$.tool_call.name")).toThrow(/does not know how to express/);
  });
});
