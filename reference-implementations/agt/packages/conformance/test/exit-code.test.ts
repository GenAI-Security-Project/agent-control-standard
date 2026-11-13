import { describe, expect, it } from "bun:test";
import { everyCell } from "../src/cells.ts";
import { mergeCells } from "../src/merge-cells.ts";
import { resolveExitCode } from "../src/exit-code.ts";
import { checkInterventionPoints, coverageCellsFromInterventionPoints } from "../src/intervention-points.ts";
import { checkVerdicts } from "../src/verdicts.ts";
import { loadMapping } from "guardian";

describe("resolveExitCode -- a gap the specification has is an answer, a broken declaration is not", () => {
  it("is 0 for the real mapping.yaml's own verdict cells alone -- every coordinate is resolved, never a hole", () => {
    // The verdict round trip is the one check that answers at every one of
    // the 40 coordinates, so merged alone it already leaves none untouched.
    // That is the real, structural reason `bun run conformance` exits 0
    // today, rather than an assumption this test takes on faith.
    const mapping = loadMapping("mapping.yaml");
    const cells = mergeCells(checkVerdicts(mapping));

    expect(resolveExitCode(cells)).toBe(0);
  });

  it("is 0 for the real mapping.yaml's two declaration checks merged -- its unexpressed cells are all answers", () => {
    // Both checks that read mapping.yaml, on the live table: ten cells at the
    // two model-call points ACS v0.1.0 carries no method for, four transform
    // cells at points whose rows declare no modifications rule, and not one
    // contract_violated among them. If this ever fails, the live mapping has
    // acquired a real finding and the rule is reporting it -- the fix is the
    // mapping, never this expectation.
    const mapping = loadMapping("mapping.yaml");
    const cells = mergeCells(
      coverageCellsFromInterventionPoints(checkInterventionPoints(mapping)),
      checkVerdicts(mapping),
    );

    expect(cells.filter((cell) => cell.status === "contract_violated")).toEqual([]);
    expect(resolveExitCode(cells)).toBe(0);
  });

  it("is 0 for a fully-covered matrix where one cell is unexpressed because the specification has no target there", () => {
    // Every one of the 40 coordinates gets a real contribution -- all but one
    // "expressed", the last one a genuine gap ACS v0.1.0 really has -- so the
    // only way this could read non-zero is the rule treating an honest gap as
    // a fault, which would put the matrix under exactly the pressure to be
    // all-expressed that cells.ts's CellStatus doc refuses.
    const cells = mergeCells(
      everyCell().map(({ point, verdict }) =>
        point === "pre_model_call" && verdict === "deny"
          ? {
              point,
              verdict,
              status: "unexpressed" as const,
              reason: "mapping.yaml declares no ACS method for this point",
              measuredBy: ["intervention-point round trip"],
            }
          : { point, verdict, status: "expressed" as const, measuredBy: ["verdict round trip"] },
      ),
    );

    expect(resolveExitCode(cells)).toBe(0);
  });

  it("is non-zero for one contract_violated cell in an otherwise fully resolved matrix", () => {
    // The same 40-coordinate shape as the test above it, one cell apart: this
    // one's declaration was checked and does not hold. Under the rule this
    // replaced -- unexpressed plus one exact reason string -- these two
    // matrices were indistinguishable and both exited 0, which is how a
    // broken verdict round trip could ship.
    const cells = mergeCells(
      everyCell().map(({ point, verdict }) =>
        point === "pre_tool_call" && verdict === "deny"
          ? {
              point,
              verdict,
              status: "contract_violated" as const,
              reason: 'AGT "deny" becomes ACS "deny", which reads back as "escalate"',
              measuredBy: ["verdict round trip"],
            }
          : { point, verdict, status: "expressed" as const, measuredBy: ["verdict round trip"] },
      ),
    );

    expect(resolveExitCode(cells)).not.toBe(0);
  });

  it("is non-zero for a real mapping.yaml whose verdict round trip is broken, through the check that measures it", () => {
    // Not a hand-built cell: `allow` and `warn` share ACS "allow" and are
    // discriminated by whether policy_references is non-empty, so swapping
    // which of them declares require_policy_references leaves the table
    // invertible and stops both verdicts reading back as themselves.
    // checkVerdicts is what notices, and this asserts the runner would
    // actually fail on it -- the case the old rule could not fail on at all.
    const mapping = loadMapping("mapping.yaml");
    const swapped = {
      ...mapping,
      verdicts: {
        ...mapping.verdicts,
        allow: { decision: "allow" as const, require_policy_references: true },
        warn: { decision: "allow" as const },
      },
    };

    expect(resolveExitCode(mergeCells(checkVerdicts(swapped)))).not.toBe(0);
  });

  it("is non-zero when mergeCells is handed no contributions at all -- every one of the 40 coordinates is a hole", () => {
    // mergeCells() with zero arguments is the real function this coordinate
    // shape comes from (merge-cells.ts's own contributions.length === 0
    // branch), not a hand-typed stand-in for it.
    const cells = mergeCells();

    expect(resolveExitCode(cells)).not.toBe(0);
  });

  it("is non-zero when even one of the 40 coordinates has no contribution, the rest fully resolved", () => {
    // The (input, allow) coordinate's own verdict cell is stripped out of the
    // contribution array before merging -- so mergeCells sees zero
    // contributions there (its own hole branch) while every other of the 39
    // coordinates still merges from a real, resolved cell.
    const mapping = loadMapping("mapping.yaml");
    const verdictCells = checkVerdicts(mapping).filter(
      (cell) => !(cell.point === "input" && cell.verdict === "allow"),
    );
    const cells = mergeCells(verdictCells);

    expect(resolveExitCode(cells)).not.toBe(0);
  });

  it("reads a hole off measuredBy, not off the sentence printed beside it", () => {
    // A hole whose reason has been reworded, and an expressed cell no check
    // claims: neither carries merge-cells.ts's literal, and the old rule --
    // status plus that one exact string -- would have exited 0 on both. An
    // unattributed claim is not a measurement, whatever it says of itself.
    const reworded = mergeCells(
      everyCell().map(({ point, verdict }) => ({
        point,
        verdict,
        status: "unexpressed" as const,
        reason: "nothing looked at this coordinate",
        measuredBy: [],
      })),
    );
    const unattributedClaim = mergeCells(
      everyCell().map(({ point, verdict }) => ({
        point,
        verdict,
        status: "expressed" as const,
        measuredBy: [],
      })),
    );

    expect(resolveExitCode(reworded)).not.toBe(0);
    expect(resolveExitCode(unattributedClaim)).not.toBe(0);
  });
});
