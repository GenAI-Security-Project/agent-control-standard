import type { SurfaceDiff } from "./diff-surfaces.ts";
import type { RenderOptions } from "./render.ts";

function show(value: unknown): string {
  return value === undefined ? "(absent)" : JSON.stringify(value);
}

/**
 * Renders what moved between the pinned ref and `main`, grouped by surface.
 *
 * A surface diff is not a coverage cell. A cell pairs an intervention point
 * with an AGT verdict and says whether ACS can express it; a row here names
 * a surface, a field, and what that field was against what it is now. They
 * are different claims, so they are rendered by different functions and land
 * in different places -- publishing an upstream diff as a column of the
 * coverage matrix would make the matrix answer "what did the harness notice"
 * under the name of "does ACS express AGT".
 */
export function renderUpstreamDiff(diffs: readonly SurfaceDiff[], options: RenderOptions = {}): string {
  // Accepted and unread, and the parameter stays: it is the signature every
  // renderer in this package shares (`renderCoverageMatrix`,
  // `renderTraceRows`), so a caller rendering all of them passes the same
  // options object to each. `RenderOptions` carries only `color`, and this
  // renderer's output is a markdown table published to a CI step summary,
  // which has nowhere to put an ANSI escape.
  void options;
  if (diffs.length === 0) {
    return "Upstream contract watch: no watched surface moved between the pinned ref and main.";
  }

  const bySurface = new Map<string, SurfaceDiff[]>();
  for (const diff of diffs) {
    const rows = bySurface.get(diff.surface) ?? [];
    rows.push(diff);
    bySurface.set(diff.surface, rows);
  }

  const lines: string[] = [
    `Upstream contract watch: ${diffs.length} fields moved between the pinned ref and main.`,
    "",
  ];
  for (const [surface, rows] of bySurface) {
    lines.push(`${surface}`);
    lines.push("| field | pinned | main |");
    lines.push("|---|---|---|");
    for (const row of rows) {
      lines.push(`| \`${row.field}\` | ${show(row.pinned)} | ${show(row.upstream)} |`);
    }
    lines.push("");
  }
  return lines.join("\n").trimEnd();
}
