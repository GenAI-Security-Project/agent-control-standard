/**
 * The coverage matrix's merge step, split from rendering: the four
 * contributing checks each produce a `CoverageCell` for some or all of the
 * 40 (point, verdict) coordinates `everyCell()` enumerates, and this
 * combines however many of them touched each coordinate into the one cell
 * the matrix reports for it.
 *
 * THE RULE: the worst status wins -- `contract_violated` beats
 * `unexpressed` beats `guardian_only` beats `expressed` -- and every
 * contributing check is named in `measuredBy`, regardless of which status it
 * individually landed on. Two
 * checks that land on the SAME status -- the one the coordinate resolves to
 * -- have both their DISTINCT reasons carried, joined by `"; "`: one check's
 * account does not silence another's. Identical text from two checks is
 * deduped rather than joined against itself -- two checks reading the same
 * `mapping.yaml` note back verbatim is not a second account, and
 * `measuredBy` already names both of them regardless. A coordinate no check
 * touched resolves to
 * `unexpressed`, reason `"no check measured this cell"`, `measuredBy: []` --
 * the merge never marks a cell expressed by omission, which is the one way
 * this matrix could quietly turn green (`cells.ts`'s own `CellStatus` doc
 * names that failure mode and this is what closes it).
 *
 * `everyCell()` is what makes the return value always exactly 40 entries,
 * whether zero checks ran or all four did: the merge is driven by the full
 * coordinate space, not by whatever coordinates happened to arrive.
 */
import { everyCell, type CellStatus, type CoverageCell, type CoverageMatrix } from "./cells.ts";

/** Worst first, best last -- the ordering `worseOf` resolves ties by. Not
 * exported: this ranking is the merge's own business, and nothing outside
 * this file needs to compare two statuses against each other.
 *
 * `contract_violated` ranks worst rather than merely differently: it is the
 * one status that fails the run (exit-code.ts), so a coordinate where one
 * check found a broken declaration and another found nothing wrong must
 * resolve to the finding. Ranked anywhere else, a check asking an easier
 * question could bury one asking a harder one -- the failure this whole
 * ordering exists to prevent. */
const WORST_TO_BEST: readonly CellStatus[] = ["contract_violated", "unexpressed", "guardian_only", "expressed"];

function worseOf(a: CellStatus, b: CellStatus): CellStatus {
  return WORST_TO_BEST.indexOf(a) <= WORST_TO_BEST.indexOf(b) ? a : b;
}

function coordinateKey(point: string, verdict: string): string {
  return `${point} ${verdict}`;
}

/**
 * What this module reads off a contributing cell -- the same fields
 * `CoverageCell` declares, `measuredBy` widened to `readonly string[]`.
 * Every real check returns a plain `CoverageCell[]`, whose mutable
 * `measuredBy: string[]` satisfies this trivially. It also accepts the other
 * legitimate producer of a `CoverageCell`-shaped value: a `const` fixture
 * built with `as const` (this package's own merge-cells.test.ts does exactly
 * that), whose `measuredBy: [by]` becomes a READONLY tuple -- which a
 * parameter typed as the exact, mutable `CoverageCell[]` would reject, not
 * because anything here mutates it, but because TypeScript will not assign a
 * readonly array where a wider mutable `string[]` is declared. Nothing in
 * this module ever writes through `measuredBy`, so a type that only reads is
 * the correct type, not a loosened one.
 */
type Contribution = {
  readonly point: string;
  readonly verdict: string;
  readonly status: CellStatus;
  readonly reason?: string;
  readonly measuredBy: readonly string[];
};

/**
 * Combines every contributing check's cell for one (point, verdict)
 * coordinate into the single cell the matrix reports for it. `contributions`
 * is every cell any check produced at this coordinate, in the order the
 * checks were passed to `mergeCells` -- empty when no check touched it.
 */
function mergeCoordinate(point: string, verdict: string, contributions: Contribution[]): CoverageCell {
  if (contributions.length === 0) {
    return { point, verdict, status: "unexpressed", reason: "no check measured this cell", measuredBy: [] };
  }

  const status = contributions.reduce<CellStatus>((worst, contribution) => worseOf(worst, contribution.status), "expressed");
  // Only the reasons from contributions that actually landed on the status
  // the coordinate resolved to -- a check that reported a BETTER status than
  // the merge settled on lost the tie-break and does not get to explain a
  // result it did not produce. DEDUPED (`Set`, insertion order preserved)
  // before joining: "both reasons are carried" is about two checks giving
  // two DIFFERENT accounts of the same status, so one check's account is not
  // silenced by another's. Two checks landing on byte-identical text is not
  // that -- the intervention-point check and the verdict check both read
  // `mapping.yaml`'s own `note` for `pre_model_call`/`post_model_call` and
  // say the same sentence back --
  // and joining it against itself would have published a footnote that
  // repeats one account rather than carrying a second one, with
  // `measuredBy` already naming both checks regardless.
  const reasons = [
    ...new Set(
      contributions
        .filter((contribution) => contribution.status === status && contribution.reason !== undefined)
        .map((contribution) => contribution.reason!),
    ),
  ];
  const measuredBy = contributions.flatMap((contribution) => contribution.measuredBy);

  return {
    point,
    verdict,
    status,
    ...(reasons.length > 0 ? { reason: reasons.join("; ") } : {}),
    measuredBy,
  };
}

/**
 * Merges any number of checks' cell arrays into the 40 cells the matrix
 * reports, one per `everyCell()` coordinate. A check that returns fewer than
 * 40 cells (three of the four do -- see their own modules' headers)
 * contributes only to the coordinates it actually measured; every other
 * coordinate is merged from whatever the other checks contributed there, or
 * from nothing at all.
 *
 * This is the only producer of a `CoverageMatrix`. A check's own
 * `CoverageCell[]` is a contribution and is typed as one.
 */
export function mergeCells(...contributions: Contribution[][]): CoverageMatrix {
  const byCoordinate = new Map<string, Contribution[]>();
  for (const cells of contributions) {
    for (const cell of cells) {
      const key = coordinateKey(cell.point, cell.verdict);
      const existing = byCoordinate.get(key);
      if (existing === undefined) {
        byCoordinate.set(key, [cell]);
      } else {
        existing.push(cell);
      }
    }
  }

  return everyCell().map(({ point, verdict }) =>
    mergeCoordinate(point, verdict, byCoordinate.get(coordinateKey(point, verdict)) ?? []),
  );
}
