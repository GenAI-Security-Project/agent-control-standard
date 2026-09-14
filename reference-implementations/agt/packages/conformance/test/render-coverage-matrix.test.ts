import { describe, expect, it } from "bun:test";
import { AGT_POINTS, AGT_VERDICTS, type CoverageCell } from "../src/cells.ts";
import { mergeCells } from "../src/merge-cells.ts";
import { renderCoverageMatrix } from "../src/render.ts";

// The verdict check's own warn-column reason (verdicts.ts's
// WARN_GUARDIAN_ONLY), reproduced here rather than imported: verdicts.ts
// does not export it, and the point of this fixture is a guardian_only cell
// shaped the way a real check actually produces one, not an invented reason
// string.
const WARN_REASON =
  "AGT's only stock warn gate reads input.annotations.drift_score, which reaches the policy input from a " +
  "manifest-declared annotator and never from the snapshot; no ACS v0.1.0 method payload carries a field a " +
  "drift score could be derived from, so the Guardian must originate it";

const cell = (point: string, verdict: string, status: CoverageCell["status"], reason?: string): CoverageCell =>
  ({ point, verdict, status, measuredBy: ["intervention-point round trip"], ...(reason ? { reason } : {}) }) as CoverageCell;

describe("renderCoverageMatrix -- the published coverage matrix", () => {
  // A fully-measured matrix: every cell expressed except the warn column,
  // which is guardian_only with a real reason -- so the render exercises
  // both a bare symbol and a reason-carrying one in the same table.
  const contributions: CoverageCell[] = AGT_POINTS.flatMap((point) =>
    AGT_VERDICTS.map((verdict) =>
      verdict === "warn" ? cell(point, verdict, "guardian_only", WARN_REASON) : cell(point, verdict, "expressed"),
    ),
  );
  const cells = mergeCells(contributions);
  const table = renderCoverageMatrix(cells);

  it("names every one of the 8 AGT intervention points", () => {
    for (const point of AGT_POINTS) {
      expect(table).toContain(point);
    }
  });

  it("names every one of the 5 AGT verdicts", () => {
    for (const verdict of AGT_VERDICTS) {
      expect(table).toContain(verdict);
    }
  });

  it("says 'AGT verdicts' in its header, not 'the five'", () => {
    expect(table).toContain("AGT verdicts");
  });

  it("names all four statuses on the legend line itself, not merely somewhere in the table", () => {
    // Scoped to the legend line, and word-bounded: `table.toContain("expressed")`
    // is satisfied by the substring inside "unexpressed" and says nothing
    // about the legend specifically -- it would still pass if "expressed"
    // vanished from the legend entirely.
    const legendLine = table.split("\n").find((line) => line.startsWith("Legend:"));
    expect(legendLine).toBeDefined();
    expect(legendLine).toMatch(/\bexpressed\b/);
    expect(legendLine).toMatch(/\bguardian_only\b/);
    expect(legendLine).toMatch(/\bunexpressed\b/);
    expect(legendLine).toMatch(/\bcontract_violated\b/);
  });

  it("renders a contract_violated cell with its own symbol, and says on the table's face that it is the status that fails the run", () => {
    // A status the published table did not show would be an invisible
    // finding -- the same defect as a blank cell, one layer up. And a reader
    // who can see the symbol but not what separates it from ✖ has been shown
    // a distinction without being told which one exits non-zero.
    const violated = mergeCells([
      ...contributions.filter((c) => !(c.point === "input" && c.verdict === "deny")),
      cell("input", "deny", "contract_violated", 'AGT "deny" reads back as "escalate"'),
    ]);
    const violatedTable = renderCoverageMatrix(violated);

    const inputRow = violatedTable.split("\n").find((line) => line.startsWith("input"))!;
    expect(inputRow).toMatch(/‼\[\d+\]/);
    expect(violatedTable).toContain('AGT "deny" reads back as "escalate"');
    expect(violatedTable).toMatch(/contract_violated[\s\S]*exit non-zero/);
  });

  it("renders a guardian_only cell as a footnote marker beside its symbol, with ONE footnote line covering every cell sharing the identical reason", () => {
    // `table.toContain(WARN_REASON)` alone would pass equally if the
    // renderer inlined the full reason into the cell -- a numbered footnote
    // per distinct reason, and the dedup that goes with it, need their own
    // assertion. This checks both: every warn cell (guardian_only in this
    // fixture, all sharing WARN_REASON) renders as "<symbol>[N]" rather than
    // the reason text, every one of them points at the same footnote
    // number, and exactly one footnote line below the legend carries the
    // reason -- once, not the reason joined against itself.
    const warnMarkers = [...table.matchAll(/◐\[(\d+)\]/g)].map((m) => m[1]!);
    expect(warnMarkers).toHaveLength(AGT_POINTS.length);
    expect(new Set(warnMarkers).size).toBe(1);

    const lines = table.split("\n");
    const legendIndex = lines.findIndex((line) => line.startsWith("Legend:"));
    expect(legendIndex).toBeGreaterThan(-1);
    const footnoteLines = lines.slice(legendIndex + 1).filter((line) => line.startsWith(`[${warnMarkers[0]}] `));
    expect(footnoteLines).toEqual([`[${warnMarkers[0]}] ${WARN_REASON}`]);

    // The cell itself never carries the reason text -- only its marker.
    const firstRow = lines.find((line) => line.startsWith(AGT_POINTS[0]!))!;
    expect(firstRow).not.toContain(WARN_REASON);
  });

  it("states its own subject: ACS v0.1.0's expressive power, not what this Guardian evaluates", () => {
    expect(table).toMatch(/expressive power/i);
    expect(table).toMatch(/methods_evaluated/i);
    expect(table).toMatch(/ServerHello/i);
    // The distinction itself, not just the two vocabularies present: a
    // reader must be told this table is NOT a claim about Guardian dispatch.
    expect(table).toMatch(/not[^.]*this Guardian evaluates/i);
  });

  it("renders no cell blank -- every point's row carries exactly 5 status symbols, one per verdict", () => {
    const rows = table.split("\n").filter((line) => AGT_POINTS.some((point) => line.startsWith(point)));
    expect(rows).toHaveLength(AGT_POINTS.length);
    for (const row of rows) {
      const symbols = [...row.matchAll(/[✔◐✖‼]/g)];
      expect(symbols).toHaveLength(AGT_VERDICTS.length);
    }
  });

  it("resolves a cell no check measured as unexpressed and still renders it, never blank", () => {
    const unmeasured = mergeCells([]);
    const unmeasuredTable = renderCoverageMatrix(unmeasured);

    expect(unmeasuredTable).toContain("no check measured this cell");
    for (const point of AGT_POINTS) {
      expect(unmeasuredTable).toContain(point);
    }
  });

  it("is a pure function of the cells it is handed -- rendering twice produces the same string", () => {
    expect(renderCoverageMatrix(cells)).toBe(renderCoverageMatrix(cells));
  });

  it("throws on a duplicate coordinate rather than letting the last cell silently win", () => {
    // The natural misuse is `renderCoverageMatrix([...checkACells,
    // ...checkBCells])` in place of `renderCoverageMatrix(mergeCells(checkACells,
    // checkBCells))` -- both typecheck as CoverageCell[], and without this
    // check whichever cell sorts last at a coordinate would win with no
    // error. If that one said "expressed", the published matrix would be
    // greener than anything measured, silently.
    const duplicated: CoverageCell[] = [
      cell("pre_tool_call", "warn", "unexpressed", "should not silently lose"),
      cell("pre_tool_call", "warn", "expressed"),
    ];

    expect(() => renderCoverageMatrix(duplicated)).toThrow(/pre_tool_call/);
    expect(() => renderCoverageMatrix(duplicated)).toThrow(/warn/);
  });
});

describe("renderCoverageMatrix -- RenderOptions.color is opt-in", () => {
  it("paints only a guardian_only cell, and stripping the ANSI codes back out recovers exactly the plain render -- alignment survives painting", () => {
    const cells = mergeCells([
      cell("pre_tool_call", "warn", "guardian_only", WARN_REASON),
      cell("pre_tool_call", "allow", "expressed"),
    ]);

    const plain = renderCoverageMatrix(cells);
    const colored = renderCoverageMatrix(cells, { color: true });

    expect(colored).not.toBe(plain);
    expect(colored).toContain("[33m"); // YELLOW -- guardian_only's colour
    expect(colored).toContain("[0m"); // RESET

    // paint() wraps the ALREADY-padded token (render.ts's own ordering), so
    // stripping every ANSI escape sequence back out must reproduce the
    // plain-text render byte for byte -- if painting had disturbed a
    // column's width, this equality would catch it.
    const stripped = colored.replace(/\[\d+m/g, "");
    expect(stripped).toBe(plain);
  });
});
