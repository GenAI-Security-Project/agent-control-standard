import { describe, expect, it } from "bun:test";
import { mergeCells } from "../src/merge-cells.ts";
import { AGT_POINTS, AGT_VERDICTS, type CellStatus } from "../src/cells.ts";

const cell = (point: string, verdict: string, status: CellStatus, by: string, reason?: string) =>
  ({ point, verdict, status, measuredBy: [by], ...(reason ? { reason } : {}) }) as const;

describe("mergeCells -- the worst status wins and every check is named", () => {
  it("lets contract_violated beat unexpressed, unexpressed beat guardian_only, and guardian_only beat expressed", () => {
    const merged = mergeCells(
      [cell("pre_tool_call", "warn", "expressed", "intervention-point round trip")],
      [cell("pre_tool_call", "warn", "guardian_only", "verdict round trip", "no wire source")],
    );
    const at = merged.find((c) => c.point === "pre_tool_call" && c.verdict === "warn")!;

    expect(at.status).toBe("guardian_only");
    expect(at.measuredBy).toEqual(["intervention-point round trip", "verdict round trip"]);
    expect(at.reason).toBe("no wire source");

    // The rung the fourth status added, and the one that has to hold for the
    // exit rule to see a finding at all: a check that found this tree's own
    // declaration broken must not be outvoted by one that found the
    // coordinate merely unreachable, or by one that found nothing wrong.
    const withFinding = mergeCells(
      [cell("output", "deny", "unexpressed", "intervention-point round trip", "no method here")],
      [cell("output", "deny", "expressed", "deny fails closed")],
      [cell("output", "deny", "contract_violated", "verdict round trip", "reads back as nothing")],
    );
    const finding = withFinding.find((c) => c.point === "output" && c.verdict === "deny")!;

    expect(finding.status).toBe("contract_violated");
    expect(finding.reason).toBe("reads back as nothing");
    expect(finding.measuredBy).toEqual([
      "intervention-point round trip",
      "deny fails closed",
      "verdict round trip",
    ]);
  });

  it("carries both reasons when two checks land on the same status", () => {
    const merged = mergeCells(
      [cell("input", "transform", "unexpressed", "intervention-point round trip", "first")],
      [cell("input", "transform", "unexpressed", "verdict round trip", "second")],
    );

    expect(merged.find((c) => c.point === "input" && c.verdict === "transform")!.reason).toBe("first; second");
  });

  it("reports a cell no check measured as unexpressed, never as expressed by default", () => {
    const merged = mergeCells([]);

    expect(merged).toHaveLength(AGT_POINTS.length * AGT_VERDICTS.length);
    for (const c of merged) {
      expect(c.status).toBe("unexpressed");
      expect(c.reason).toBe("no check measured this cell");
      expect(c.measuredBy).toEqual([]);
    }
  });

  // The intervention-point check and the verdict check both read the same
  // mapping.yaml note back for pre_model_call/post_model_call (both fall
  // back to `row.note` on a null acs_method), so two checks landing on this
  // coordinate carry byte-identical text, not two accounts. Joining it
  // against itself would publish "X; X" -- this is the real shape,
  // reproduced directly rather than invented.
  it("dedupes identical reasons rather than joining one check's account against itself", () => {
    const merged = mergeCells(
      [cell("pre_model_call", "deny", "unexpressed", "intervention-point round trip", "no ACS v0.1.0 method carries a model call, so this point is unexpressed at every verdict")],
      [cell("pre_model_call", "deny", "unexpressed", "verdict round trip", "no ACS v0.1.0 method carries a model call, so this point is unexpressed at every verdict")],
    );
    const at = merged.find((c) => c.point === "pre_model_call" && c.verdict === "deny")!;

    expect(at.reason).toBe("no ACS v0.1.0 method carries a model call, so this point is unexpressed at every verdict");
    // Both checks are still named, even though only one copy of their
    // (identical) reason survives.
    expect(at.measuredBy).toEqual(["intervention-point round trip", "verdict round trip"]);
  });

  it("still joins two DIFFERENT reasons on the same status -- dedup is not merging every reason into one", () => {
    const merged = mergeCells(
      [cell("output", "escalate", "unexpressed", "intervention-point round trip", "first account")],
      [cell("output", "escalate", "unexpressed", "verdict round trip", "second account")],
    );

    expect(merged.find((c) => c.point === "output" && c.verdict === "escalate")!.reason).toBe(
      "first account; second account",
    );
  });
});
