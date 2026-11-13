/**
 * The conformance runner's exit-status rule, split out from main.ts so it is
 * independently testable without spinning up a Guardian or driving the real
 * bridge: `mergeCells()`'s own hole-filling behaviour is enough to produce
 * one of the two cases this function exists to catch, and a `mapping.yaml`
 * whose verdict table cannot round-trip is enough to produce the other.
 *
 * THE RULE: exit non-zero for a cell whose status is `contract_violated`, or
 * for a cell no check claims to have measured. Exit 0 otherwise -- and
 * `unexpressed` is otherwise. An `unexpressed` cell reports a gap the
 * specification really has (`cells.ts`'s own `CellStatus` doc draws that
 * line, at the sites that can decide it), and an exit code that failed on
 * one would put the matrix under exactly the pressure to be all-expressed
 * that the same doc explains why this project refuses.
 *
 * BOTH TESTS ARE STRUCTURAL, AND THAT IS THE WHOLE POINT. This rule used to
 * match `status === "unexpressed"` together with the exact reason string
 * `mergeCoordinate` (merge-cells.ts) writes for a coordinate no check
 * touched -- which meant the only thing that could ever fail this run was a
 * bug in the merge's own wiring. Every substantive finding a check could
 * report -- a verdict that does not survive its own round trip, an
 * intervention point whose declared ACS method resolves back to somewhere
 * else, a resolver that threw -- was `unexpressed` carrying a DIFFERENT
 * reason, and so counted as a resolved cell. `mapping.yaml` could break its
 * verdict round trip in production and `bun run conformance` would still
 * exit 0: an instrument that cannot fail on a real finding is not an
 * instrument.
 *
 * So the distinction moved to the producing sites, where it is decidable,
 * and is carried as `CellStatus` rather than as prose: `verdicts.ts` and
 * `intervention-points.ts` each resolve a checked-and-violated declaration
 * to `contract_violated` and a genuine specification gap to `unexpressed`,
 * and this file compares statuses. A second literal-string match here would
 * have rebuilt the same fragility one reason string further along. A hole is
 * read off `measuredBy` being empty -- `cells.ts` declares that field as
 * exactly this signal -- rather than off the sentence printed beside it, so
 * no rewording can silence it, and an `expressed` cell no check claims fails
 * the run too, because an unattributed claim is not a measurement.
 *
 * `red` and `green` are deliberately absent from this file's vocabulary.
 * `CellStatus` retired them, and an exit rule that still spoke them would
 * teach the axis the statuses replaced. `contract_violated` is not "red"
 * renamed: it says what was checked and what did not hold, and it is a
 * statement about this repository rather than about ACS.
 */
import type { CoverageMatrix } from "./cells.ts";

export function resolveExitCode(cells: CoverageMatrix): number {
  const hasFinding = cells.some((cell) => cell.status === "contract_violated" || cell.measuredBy.length === 0);
  return hasFinding ? 1 : 0;
}
