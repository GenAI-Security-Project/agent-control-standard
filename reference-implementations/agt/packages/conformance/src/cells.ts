/**
 * The coverage matrix's axes -- 8 AGT intervention points by 5 AGT verdicts
 * -- come from a source the Guardian could not also be wrong about.
 *
 * The rows are AGT's `InterventionPoint` and the columns its `Decision` --
 * the `Readonly` consts the pinned SDK exports, so the axes are a fact this
 * repository reads off the SDK rather than a list it keeps in step by hand.
 * Reading them off `mapping.yaml` instead would have measured the
 * declaration against itself, and hardcoding them here would have measured
 * this file.
 */
import { Decision, InterventionPoint } from "agent-control-specification";

export const AGT_POINTS: readonly string[] = Object.values(InterventionPoint).sort();
export const AGT_VERDICTS: readonly string[] = Object.values(Decision).sort();

/**
 * What a cell resolved to. Deliberately not `green` / `red`: a matrix that
 * must be green is a matrix under pressure to redefine its own claim.
 *
 *   expressed      ACS v0.1.0 expresses AGT here.
 *   guardian_only  the Guardian can do it from process-local knowledge and a
 *                  wire consumer cannot. Three independent findings land on
 *                  this one -- the `warn` column, the Trace pillar's
 *                  attributes (declared on the wire but never required
 *                  there), and the finding that AGT's enforced identity binds
 *                  to the document it rewrote rather than to anything a wire
 *                  consumer can check.
 *   unexpressed    it cannot, and `reason` says why. An answer ABOUT THE
 *                  SPECIFICATION: a model-call point ACS v0.1.0 carries no
 *                  method for, a transform `mapping.yaml`'s own row declares
 *                  it has no target for. A gap the specification really has
 *                  is a resolved cell, not a fault.
 *   contract_violated
 *                  a declaration THIS TREE makes about this coordinate was
 *                  checked and does not hold -- a verdict that does not
 *                  survive its own round trip, a point whose declared ACS
 *                  method resolves back to a different point, a runtime that
 *                  threw where the declaration says it answers, a table
 *                  missing a row for a point AGT declares. Not a claim about
 *                  ACS's expressive power at all: a claim that this
 *                  repository is wrong.
 *
 * THE LAST TWO ARE KEPT APART BECAUSE THE INSTRUMENT'S OWN EXIT STATUS
 * DEPENDS ON THE DIFFERENCE. Filed under one name, `resolveExitCode`
 * (exit-code.ts) could not fail on a violated contract without also failing
 * on every honest gap -- and an instrument that fails on honest gaps is one
 * pressured to have none, which is the all-expressed matrix the `green` note
 * above refuses. So `unexpressed` exits 0, `contract_violated` does not, and
 * neither is a shade of the other.
 *
 * Four members and no default. `status` is required, so a cell cannot come
 * to read as expressed by having gone unmeasured -- the one way a resolved
 * matrix could quietly become a green one.
 */
export type CellStatus = "expressed" | "guardian_only" | "unexpressed" | "contract_violated";

export type CoverageCell = {
  point: string;
  verdict: string;
  status: CellStatus;
  reason?: string;
  /** Which checks contributed to this cell. A cell no check touched is a
   * defect the runner reports, not a cell that passed -- and this empty
   * array is what says so: `resolveExitCode` reads it, rather than the
   * sentence `mergeCells` writes into `reason` beside it, so the hole rule
   * cannot be broken by rewording a string. An `expressed` cell no check
   * claims fails the run for the same reason: an unattributed claim is not
   * a measurement. */
  measuredBy: string[];
};

/**
 * The merge's product, and the only thing that is one: 40 cells, one per
 * coordinate, no duplicates and no holes. A `CoverageCell[]` that has not
 * been through `mergeCells` is a check's own contribution, not the matrix --
 * the distinction `renderCoverageMatrix`'s duplicate-coordinate throw exists
 * to catch. Declared so the noun is occupied: `Mapping` is `mapping.yaml`'s
 * data, `MappingTable` is the rendered mapping table, and `CoverageMatrix`
 * is the coverage matrix's measurements, and none of the three can quietly
 * come to hold another's contents while all three names have owners.
 */
export type CoverageMatrix = readonly CoverageCell[];

declare const MAPPING_TABLE: unique symbol;

/**
 * The rendered artifact -- the mapping table as text.
 *
 * Branded rather than a bare `string` alias so the name is load-bearing and
 * not decorative: `renderMappingTable` is the only thing that can produce
 * one, so nothing can present an arbitrary string as the published table.
 * The brand costs callers nothing in the other direction -- a `MappingTable`
 * is a `string` and prints like one.
 */
export type MappingTable = string & { readonly [MAPPING_TABLE]: true };

/** Every (point, verdict) pair, in a stable order. Every check and
 * `mergeCells` iterate this, so none of them can disagree about what the
 * matrix's 40 coordinates are. `renderCoverageMatrix` does not: it derives
 * its rows and columns from the `point`/`verdict` values on the `cells` it
 * is handed, not from a second, separately imported copy of this list --
 * that is what keeps `render.ts`'s only imports type-only (its own module
 * header explains why). So the renderer's shape is only as complete, and as
 * free of duplicates, as its input: `mergeCells` is what guarantees the
 * input is always all 40 of these coordinates and no more, and
 * `renderCoverageMatrix` throws rather than silently narrowing or
 * overwriting if it is handed something that is not. */
export function everyCell(): { point: string; verdict: string }[] {
  return AGT_POINTS.flatMap((point) => AGT_VERDICTS.map((verdict) => ({ point, verdict })));
}
