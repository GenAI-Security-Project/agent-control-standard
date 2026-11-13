/**
 * For each of AGT's eight intervention points: does `mapping.yaml` give it
 * an ACS method, and does the runtime resolve that method back to this same
 * point?
 *
 * Both halves matter, and the second is the one worth having. The table could
 * name a method for every point and still be a declaration nobody checked.
 * So this calls `resolveInterventionPoint`, the runtime's own resolver,
 * rather than reading the table a second way here.
 *
 * A POINT-LEVEL QUESTION, ANSWERED AT POINT LEVEL. This check never reads a
 * verdict, so its product is one `PointRoundTrip` per point, not a cell of
 * the 8 x 5. That distinction is load-bearing rather than tidy: stamping a
 * resolved point `expressed` across all five of its columns would assert
 * something about `warn` and `transform` that this question does not ask,
 * and the published grid would only be honest because `mergeCells` later
 * hides those stamps behind a worse status from a check that did ask. Read
 * alone, the stamps were a measurement lie. Whether a verdict survives the
 * round trip at a resolved point is `checkVerdicts`'s answer, and it covers
 * all 40 coordinates.
 *
 * `coverageCellsFromInterventionPoints` therefore emits cells only where
 * this question does resolve the whole column set: a point with no usable
 * ACS method is unresolved for all five verdicts, because no wire message
 * reaches it at all, whichever verdict AGT would have returned. A resolver
 * THROW is such an answer too, not an escaping error: an ambiguous table is
 * a real answer about that point, and letting the throw out would take the
 * whole matrix with it.
 *
 * TWO KINDS OF UNRESOLVED, AND THE DIFFERENCE IS WHAT FAILS THE RUN.
 * `mapping.yaml` declaring `acs_method: null` is ACS v0.1.0 having nothing
 * to offer this point -- `unexpressed`, a resolved cell, exit 0. A row that
 * names a method which resolves back to a different point, a resolver that
 * threw, or a point AGT declares and this table has no row for at all is
 * this tree contradicting its own declaration -- `contract_violated`, which
 * `resolveExitCode` (exit-code.ts) fails on. Both used to be `unexpressed`,
 * which is precisely why breaking the table could not fail the instrument
 * that exists to measure it; `cells.ts`'s `CellStatus` carries the
 * distinction now.
 */
import { resolveInterventionPoint, type Mapping } from "guardian";
import { AGT_POINTS, AGT_VERDICTS, type CoverageCell } from "./cells.ts";

/**
 * One point's answer. `resolved` carries no reason: the round trip held, and
 * there is nothing about it a matrix cell could state that `checkVerdicts`
 * does not measure per verdict.
 */
export type PointRoundTrip =
  | { point: string; status: "resolved" }
  | { point: string; status: "unexpressed"; reason: string }
  | { point: string; status: "contract_violated"; reason: string };

export function checkInterventionPoints(mapping: Mapping): PointRoundTrip[] {
  return AGT_POINTS.map((point) => resolvePoint(point, mapping));
}

/**
 * The stage that turns point-level answers into matrix cells -- named for
 * being a projection rather than a second measurement.
 *
 * Only an unresolved point produces cells, and each produces all five,
 * carrying whichever unresolved status the point itself landed on -- never
 * flattened to one, or the exit rule this feeds would lose the difference the
 * check just made. A `resolved` point produces none: this check has nothing
 * to say about any individual column there.
 */
export function coverageCellsFromInterventionPoints(results: PointRoundTrip[]): CoverageCell[] {
  return results.flatMap((result) =>
    result.status === "resolved"
      ? []
      : AGT_VERDICTS.map((verdict) => ({
          point: result.point,
          verdict,
          status: result.status,
          reason: result.reason,
          measuredBy: ["intervention-point round trip"],
        })),
  );
}

function resolvePoint(point: string, mapping: Mapping): PointRoundTrip {
  const row = mapping.intervention_points[point];
  if (row === undefined) {
    // The eight points are read off AGT's own SDK (cells.ts), and this table
    // declares one row per point -- `acs_method: null` where ACS v0.1.0
    // cannot reach it. A point with no row is not a gap ACS has; it is this
    // table failing to answer for a point it exists to answer for.
    return {
      point,
      status: "contract_violated",
      reason: `mapping.yaml's intervention_points table has no row for AGT point "${point}"`,
    };
  }
  if (row.acs_method === null) {
    // The one honest unresolved answer: the declaration says ACS v0.1.0 has
    // nothing here, and the check agrees by having nothing to resolve.
    return {
      point,
      status: "unexpressed",
      reason: row.note ?? "mapping.yaml declares no ACS method for this point",
    };
  }
  try {
    const resolved = resolveInterventionPoint(row.acs_method, mapping);
    if (resolved !== point) {
      // The table named a method for this point and the runtime routes that
      // method somewhere else: whichever of the two rows is wrong, a wire
      // message would be governed by a policy neither row's reader expects.
      return {
        point,
        status: "contract_violated",
        reason: `mapping.yaml maps "${point}" to ${row.acs_method}, which resolves back to "${resolved}"`,
      };
    }
    return { point, status: "resolved" };
  } catch (error) {
    // Still caught rather than let out -- one unresolvable point must not
    // take the whole matrix with it -- but recorded as the finding it is: the
    // resolver refused a method this table declares it resolves.
    return {
      point,
      status: "contract_violated",
      reason: error instanceof Error ? error.message : String(error),
    };
  }
}
