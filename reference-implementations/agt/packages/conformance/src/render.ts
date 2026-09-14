/**
 * Three renderers, one per measurement, and none of them takes a
 * discriminator saying which kind of table it is being asked for.
 *
 *   renderMappingTable   the conformance runner's own declaration --
 *                        mapping.yaml's two tables, unmeasured
 *   renderCoverageMatrix the 8 × 5 coverage matrix the other checks measure
 *   renderTraceRows      the trace pillar's attribute-against-wire-source
 *                        rows
 *
 * A coverage cell is an intervention point against an AGT verdict; a trace
 * row is a required OTel attribute against its wire source; they share a verb
 * and nothing else. A single `renderMatrix()` wired to all three would have
 * let the second and third arrive as columns of the first -- and a coverage
 * claim rendered by the same function as everything beside it is a coverage
 * claim whose subject is whatever was rendered. An upstream-diff renderer,
 * comparing this implementation against a live AGT checkout, is not here and
 * is not this package's: it belongs beside `diffSurfaces()`, wherever that
 * measurement eventually lives.
 *
 * EVERY FUNCTION HERE IS PURE. Each is handed its measurement and renders
 * that one; none reads a file, a clock or a store. This is asserted, not
 * only stated: each renderer's test renders the same input twice and expects
 * the same string.
 */
import type { Mapping } from "guardian";
import type { CellStatus, CoverageCell, CoverageMatrix, MappingTable } from "./cells.ts";
import type { TraceRow } from "./trace-pillar.ts";

/** Colour is opt-in, matching this repository's other renderer
 * (`packages/inspector/src/render.ts`'s own `RenderOptions`): a caller
 * passes `color: true` for a terminal, and every test in this package
 * asserts the plain, uncoloured string. `indent` has no analogue here --
 * none of this file's renderers pretty-print JSON -- so the type carries
 * only what they use.
 *
 * SHARED ACROSS THIS FILE'S RENDERERS, deliberately placed here rather than
 * beside `renderCoverageMatrix`: `renderMappingTable` below does not use it,
 * but `renderTraceRows` does, and the next implementer should find this in
 * one place rather than pulled out of whichever renderer happened to need it
 * first. */
export type RenderOptions = { color?: boolean };

const RESET = "[0m";
const YELLOW = "[33m";

function paint(text: string, color: string | null, enabled: boolean): string {
  return enabled && color !== null ? `${color}${text}${RESET}` : text;
}

/** One row of `Mapping["intervention_points"]` -- read off the type rather
 * than redeclared, so this file cannot drift from what `guardian` actually
 * exports for that table's shape. Same for `VerdictRule` below. */
type IntervRow = Mapping["intervention_points"][string];
type VerdictRule = Mapping["verdicts"][string];

function renderPointRow(point: string, row: IntervRow): string {
  // A point with no ACS method gets its own row's stated reason -- never a
  // blank column, and never a reason invented here that mapping.yaml did not
  // declare. The fallback string only exists to keep this total against a
  // row that lacks `note` too; mapping.yaml's real two null rows both carry
  // one (checked below, and by the intervention-point check's own identical
  // fallback).
  const target = row.acs_method ?? `(${row.note ?? "mapping.yaml declares no ACS method for this point"})`;
  // 15, not 14: `post_model_call` (the longest point name) is 15 characters,
  // and padEnd(14) left its arrow one column right of the other seven rows --
  // padEnd only pads up to its own argument, so a length shorter than the
  // longest real value under-aligns silently.
  return `  ${point.padEnd(15)} -> ${target}`;
}

function renderVerdictRow(verdict: string, rule: VerdictRule): string {
  // A non-empty `policy_references` is the only field that tells `warn`
  // apart from a clean `allow` on the wire, so a rendering of this row that
  // dropped `require_policy_references` would render `warn` and `allow`
  // identically.
  const qualifier = rule.require_policy_references === true ? " (non-empty policy_references required)" : "";
  return `  ${verdict.padEnd(9)} -> ${rule.decision}${qualifier}`;
}

/**
 * Renders mapping.yaml's own two declaration tables --
 * `intervention_points` (AGT point -> ACS v0.1.0 method) and `verdicts` (AGT
 * verdict -> ACS decision) -- as the mapping table. This is the conformance
 * runner's own declaration, not a measurement of it: `renderCoverageMatrix`
 * is what measures against the runtime, and the two are never the same
 * string.
 *
 * A pure function of the `mapping` argument alone: it never reads
 * mapping.yaml itself (only the object a caller already loaded from it), so
 * calling it twice on the same value renders the same string -- this file's
 * own PURE guarantee, asserted by render-mapping-table.test.ts rather than
 * only stated here.
 *
 * `field_synthesis` is deliberately not a third table here: it is the
 * synthesis rule for fields of one already-resolved decision (`reasoning`,
 * `reason_codes`, `policy_references`), not a second declared axis of "which
 * AGT thing maps to which ACS thing" the way `intervention_points` and
 * `verdicts` are.
 */
export function renderMappingTable(mapping: Mapping): MappingTable {
  const points = Object.entries(mapping.intervention_points)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([point, row]) => renderPointRow(point, row));

  const verdicts = Object.entries(mapping.verdicts)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([verdict, rule]) => renderVerdictRow(verdict, rule));

  return [
    "AGT intervention point -> ACS v0.1.0 method (mapping.yaml: intervention_points)",
    ...points,
    "",
    "AGT verdict -> ACS decision (mapping.yaml: verdicts)",
    ...verdicts,
  ].join("\n") as MappingTable;
}

/** One glyph per `CellStatus` (`cells.ts`) -- no member without one and no
 * default, so every cell renders something and `Record` makes a missing entry
 * a compile error rather than an unmarked cell. That is what makes a new
 * status impossible to add without deciding how the published table shows it:
 * a status the renderer did not show would be an invisible finding, which is
 * the same defect as a cell rendered blank. `‼` for `contract_violated`
 * rather than a second ✖-like mark, because a reader scanning the grid must
 * be able to see at a glance that it is not the same answer as `unexpressed`
 * beside it -- one is a gap ACS has, the other is this tree contradicting
 * itself. */
const STATUS_SYMBOL: Record<CellStatus, string> = {
  expressed: "✔",
  guardian_only: "◐",
  unexpressed: "✖",
  contract_violated: "‼",
};

/**
 * Only `guardian_only` is painted, and only that one, when colour is on.
 * `expressed`, `unexpressed` and `contract_violated` are deliberately left
 * plain even with `color: true` -- `cells.ts`'s own `CellStatus` doc records
 * why "green" was retracted as this matrix's success name (a matrix under
 * pressure to stay green is a matrix under pressure to redefine its claim),
 * and painting `expressed` green or either of the other two red here would
 * reintroduce exactly that framing one layer up, in the renderer, even though
 * the type itself never says either word. `contract_violated` is the one
 * status that fails the run, and it is still not painted red: the exit status
 * and the footnote are how a finding is reported, and a red cell would invite
 * reading the whole grid as a pass/fail colour field again. `guardian_only`
 * gets the same qualifier colour the Inspector uses for "policy fired"
 * (`packages/inspector/src/render.ts`) -- a cell that asks for a second look,
 * not a verdict on it.
 */
function statusColor(status: CellStatus): string | null {
  return status === "guardian_only" ? YELLOW : null;
}

function coordinateKey(point: string, verdict: string): string {
  return `${point} ${verdict}`;
}

/**
 * Renders the coverage matrix -- the 40 cells the other checks measure and
 * `mergeCells` resolves -- as one grid: an AGT intervention point (row)
 * against an AGT verdict (column), every cell exactly one of `cells.ts`'s
 * four statuses, never blank.
 *
 * `cells`' own `point`/`verdict` values are what the grid's rows and columns
 * are drawn from -- not a second, separately imported copy of AGT's
 * vocabulary. That is what keeps this file's only imports type-only (module
 * header, "EVERY FUNCTION HERE IS PURE"): `CoverageCell` and `CellStatus`
 * are erased at build, so nothing this function does can read a file, a
 * clock or a store. `cells` is expected to be `mergeCells`'s own output (one
 * entry per `everyCell()` coordinate); a coordinate the grid names but
 * `cells` does not carry is a caller error, thrown rather than rendered
 * blank -- and a coordinate `cells` carries TWICE is the same caller error
 * the other way round, thrown rather than letting whichever cell sorts last
 * silently win. That second case is what catches the natural misuse this
 * function cannot tell apart from correct input by shape alone:
 * `renderCoverageMatrix([...checkACells, ...checkBCells])` in place of
 * `renderCoverageMatrix(mergeCells(checkACells, checkBCells))` -- both are a
 * `CoverageCell[]`, but the first is four checks' raw output concatenated,
 * never merged, and would publish whichever check happened to come last at
 * each coordinate. If that check said `expressed`, the printed matrix would
 * be greener than anything actually measured, silently.
 *
 * THE SUBJECT THIS RENDERS: a cell is a claim about ACS v0.1.0's expressive
 * power against AGT's vocabulary, not a claim about which methods this
 * Guardian evaluates. Those are different questions -- the failure-domains
 * check resolves cells `expressed` at four points on the strength of a
 * fail-closed envelope-validation deny, at methods
 * `packages/guardian/src/handshake.ts`'s `METHODS_EVALUATED` never
 * dispatches. So the printed table states its own subject, above the grid,
 * in words a reader does not have to already know that fact to get right.
 *
 * No cell renders blank: every status has a symbol, and no reason is
 * truncated into a cell -- each DISTINCT reason gets one numbered footnote,
 * printed once beneath the grid, and every cell carrying it points at that
 * number.
 */
export function renderCoverageMatrix(cells: CoverageMatrix, options: RenderOptions = {}): string {
  const color = options.color ?? false;

  const lookup = new Map<string, CoverageCell>();
  for (const cell of cells) {
    const key = coordinateKey(cell.point, cell.verdict);
    if (lookup.has(key)) {
      throw new Error(
        `renderCoverageMatrix: two cells for (${JSON.stringify(cell.point)}, ${JSON.stringify(cell.verdict)}) -- ` +
          `pass mergeCells(...)'s output, not several checks' cell arrays concatenated, or whichever cell sorts ` +
          `last silently wins and this table can publish a status nothing merged`,
      );
    }
    lookup.set(key, cell);
  }

  const points = [...new Set(cells.map((c) => c.point))].sort();
  const verdicts = [...new Set(cells.map((c) => c.verdict))].sort();
  const rowLabelWidth = Math.max(0, ...points.map((p) => p.length));
  // Room for the longest verdict name plus a bracketed footnote number
  // beside the symbol ("transform" + "[12]" and change).
  const columnWidth = Math.max(0, ...verdicts.map((v) => v.length)) + 5;

  const footnoteNumbers = new Map<string, number>();
  function cellToken(cell: CoverageCell): string {
    const symbol = STATUS_SYMBOL[cell.status];
    if (cell.reason === undefined) {
      return symbol;
    }
    const existing = footnoteNumbers.get(cell.reason);
    const number = existing ?? footnoteNumbers.size + 1;
    if (existing === undefined) {
      footnoteNumbers.set(cell.reason, number);
    }
    return `${symbol}[${number}]`;
  }

  const gap = "  ";
  const header = `${"".padEnd(rowLabelWidth)}${gap}${verdicts.map((v) => v.padEnd(columnWidth)).join("")}`;

  const rows = points.map((point) => {
    const rendered = verdicts.map((verdict) => {
      const cell = lookup.get(coordinateKey(point, verdict));
      if (cell === undefined) {
        throw new Error(
          `renderCoverageMatrix: no cell for (${JSON.stringify(point)}, ${JSON.stringify(verdict)}) -- every ` +
            `coordinate this grid's own rows and columns name must be present in "cells"`,
        );
      }
      const padded = cellToken(cell).padEnd(columnWidth);
      return paint(padded, statusColor(cell.status), color);
    });
    return `${point.padEnd(rowLabelWidth)}${gap}${rendered.join("")}`;
  });

  // Numbered in the order `cellToken` assigned them -- the grid's own
  // reading order, row by row -- not re-sorted, so footnote [1] is always
  // the first reason a reader's eye reaches scanning top to bottom.
  const footnotes = [...footnoteNumbers.entries()]
    .sort(([, a], [, b]) => a - b)
    .map(([reason, number]) => `[${number}] ${reason}`);

  return [
    "AGT intervention point (rows) x AGT verdicts (columns)",
    "Each cell measures ACS v0.1.0's expressive power against AGT's vocabulary at that point x verdict -- it " +
      "is NOT a claim about which methods this Guardian evaluates. Which methods this Guardian evaluates is a " +
      "different question, answered by this Guardian's own ServerHello (its methods_evaluated field), never " +
      "by this table.",
    "",
    header,
    ...rows,
    "",
    `Legend: ${STATUS_SYMBOL.expressed} expressed   ${STATUS_SYMBOL.guardian_only} guardian_only   ` +
      `${STATUS_SYMBOL.unexpressed} unexpressed   ${STATUS_SYMBOL.contract_violated} contract_violated`,
    `${STATUS_SYMBOL.unexpressed} is an answer -- ACS v0.1.0 has no target here. ` +
      `${STATUS_SYMBOL.contract_violated} is a finding -- a declaration in this repository was checked and ` +
      `does not hold, and it is what makes this run exit non-zero.`,
    ...(footnotes.length > 0 ? ["", ...footnotes] : []),
  ].join("\n");
}

/**
 * Renders `checkTracePillar`'s `TraceRow[]` -- one line per required OTel
 * attribute, against its v0.1.0 wire source and whether a downstream
 * consumer of the ACS wire (not this Guardian) could emit it from that
 * source alone. A
 * trace row pairs an attribute with a wire source; a coverage cell pairs an
 * intervention point with an AGT verdict -- two different shapes, which is
 * why this shares no rendering code with `renderCoverageMatrix` above (no
 * `STATUS_SYMBOL`, no footnote table, no coordinate lookup): only the
 * module's shared colour plumbing (`RenderOptions`, `paint`, `YELLOW`) is
 * common to both, and that sharing is deliberate (`RenderOptions`'s own
 * comment, above).
 *
 * Reasons print INLINE, one per row, rather than as `renderCoverageMatrix`'s
 * numbered footnotes: that table de-duplicates because many cells often
 * share one reason (a whole column, say); a trace row's reason is specific
 * to its own attribute and site, so nothing here would be saved by
 * numbering it.
 *
 * `wireSource === null` (no property anywhere carries the attribute) is the
 * only case coloured, and only its symbol: YELLOW, the same hue
 * `statusColor` reserves for `guardian_only` above, on the same reasoning --
 * it marks the finding worth a second look, not "bad". A present-but-optional
 * row (`acs.capability`) is a smaller gap than an attribute with no wire
 * source at all, and the plain/coloured split is what keeps that
 * distinction visible at a glance rather than collapsing both into one
 * undifferentiated ✖. None of the checker's own 17 rows takes this branch
 * today (`trace-pillar.ts`'s own test suite asserts and explains why -- every
 * attribute currently in scope turned out to be a declared, merely optional
 * property, not an absent one), so this split is exercised by a synthetic
 * fixture rather than by `checkTracePillar()`'s real output; it stays
 * general-purpose code because `resolveField` can still resolve a future
 * attribute to genuinely absent, and this renderer should not stop telling
 * that apart from "present but optional" the day the real data happens not
 * to need the difference.
 *
 * Pure, like every renderer in this file: `rows` is the whole input, and
 * rendering it twice produces the same string.
 */
export function renderTraceRows(rows: TraceRow[], options: RenderOptions = {}): string {
  const color = options.color ?? false;

  const attributeWidth = Math.max(0, ...rows.map((row) => row.attribute.length));
  const spanWidth = Math.max(0, ...rows.map((row) => row.span.length));

  const lines = rows.map((row) => {
    const symbol = row.emittableByWireConsumer ? "✔" : "✖";
    const painted = paint(symbol, row.wireSource === null ? YELLOW : null, color);
    const source = row.wireSource ?? "(no wire source)";
    const suffix = row.reason !== undefined ? ` ${row.reason}` : "";
    return `  ${painted} ${row.attribute.padEnd(attributeWidth)} on ${row.span.padEnd(spanWidth)} <- ${source}${suffix}`;
  });

  return [
    "Trace pillar (trace/otel-mapping.json): each required OTel attribute against its v0.1.0 wire source, and " +
      "whether a downstream consumer of the ACS wire -- not this Guardian -- could emit it from that source " +
      "alone. This implementation does NOT claim the Trace pillar; this table is what that declaration is " +
      "measured against.",
    "",
    ...lines,
    "",
    "Legend: ✔ emittable by a wire consumer alone   ✖ not emittable (reason inline)",
  ].join("\n");
}
