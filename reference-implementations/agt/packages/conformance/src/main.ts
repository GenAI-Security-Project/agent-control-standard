/**
 * The conformance runner. Publishes the two artifacts this project names
 * as its published artifacts -- the mapping table and the coverage matrix
 * -- and beside them a third table: the trace-pillar rows, which this
 * package measures and renders separately. The README names only the
 * first two as published artifacts, so a reader comparing the two does
 * not mistake the trace-pillar rows for a discrepancy.
 *
 * This is a runner, not a test: its job is to drive every check this
 * package builds, merge their answers, render all three tables, and say
 * plainly which legs actually measured them -- not to assert anything about
 * the result itself. `bun run conformance` (scripts/run-conformance.sh) is
 * the one caller that runs it for real; `test/main.test.ts` is the other,
 * in-process, with the one leg that needs the network (below) left to
 * self-skip.
 *
 * FOUR CHECKS MERGED, AND A FIFTH BESIDE THEM: `checkInterventionPoints`,
 * `checkVerdicts`, `measureIdentity` (driven at both transform-capable
 * gates and merged -- it measures `pre_tool_call` as well as
 * `post_tool_call` because the two were found not to diverge, and a runner
 * calling it for one would narrow a measurement that was widened on
 * purpose; see identity.ts's own header), and `checkDenyFailsClosed`, fed to
 * `mergeCells` -- never concatenated, which is exactly the misuse
 * `renderCoverageMatrix`'s own duplicate-coordinate throw exists to catch
 * (render.ts's own header). `checkTracePillar` is separate: its
 * `TraceRow[]` has no (point, verdict) coordinate to merge into the matrix
 * at all, and is rendered on its own as the trace-pillar table.
 *
 * TWO OF THOSE ANSWER AT THEIR OWN GRAIN AND ARE PROJECTED HERE.
 * `checkInterventionPoints` answers per point and `measureIdentity` per
 * evaluation, so neither returns cells; `coverageCellsFromInterventionPoints`
 * and `coverageCellsFromIdentity` are the named stages that place what they
 * did measure onto the coordinates it actually covers. Neither stage
 * broadcasts an answer across an axis its check never read.
 *
 * THE SCHEMA LEG is orthogonal to the matrix: it asks whether the policy
 * input the Guardian actually constructs at `pre_tool_call` /
 * `post_tool_call` validates against AGT's own `policy-input.schema.json`,
 * which has no verdict axis to place a cell at (the same document
 * regardless of which verdict AGT eventually returns for it). It self-skips
 * without `PINNED_AGT_CLONE`, and the runner names -- on the output's own
 * face -- whether it ran, so a matrix published without it cannot be
 * mistaken for one that includes it.
 *
 * A GUARDIAN, STARTED AND CLOSED HERE, for the failure-domains check alone
 * (the only check that drives one over HTTP rather than in-process) --
 * `port: 0` so this runner never collides with a Guardian someone already
 * has listening on the runbook's default port, closed in a `finally` so a
 * check that throws (several of these do, deliberately, on a broken
 * invariant -- see e.g. failure-domains.ts's own header) never leaks the
 * listener.
 */
import { loadMapping, startGuardian, POLICY_TARGET_LEAF } from "guardian";
// The deployment subpath, not the barrel: the barrel is the governance verbs,
// and this is how the deployment builds a bridge. This runner MEASURES the
// shipped deployment, so it has to build the same bridge startGuardian builds
// -- assembling a replica here is how a harness comes to measure something
// that is no longer the thing it names.
import { createDeploymentBridge } from "guardian/deployment";
import type { InterventionSnapshot } from "agt-bridge";
import type { CoverageMatrix } from "./cells.ts";
import { checkInterventionPoints, coverageCellsFromInterventionPoints } from "./intervention-points.ts";
import { checkVerdicts } from "./verdicts.ts";
import { coverageCellsFromIdentity, measureIdentity } from "./identity.ts";
import { checkDenyFailsClosed } from "./failure-domains.ts";
import { checkTracePillar } from "./trace-pillar.ts";
import { mergeCells } from "./merge-cells.ts";
import { renderCoverageMatrix, renderMappingTable, renderTraceRows } from "./render.ts";
import { checkPolicyInputSchema } from "./policy-input-schema.ts";
import { resolveExitCode } from "./exit-code.ts";

const MANIFEST_PATH = "policy/manifest.yaml";
const MAPPING_PATH = "mapping.yaml";

/** The same REDACTABLE / REDACTABLE_COMMAND shapes `test/identity.test.ts`
 * drives -- a real transform at both transform-capable gates, so this
 * runner's own enforced-identity cells report the measured `guardian_only`
 * finding, not the no-rewrite case a benign fixture would report instead. */
const PRE_TOOL_CALL_SNAPSHOT: InterventionSnapshot = {
  envelope: { budgets: { tool_call_count: 0, token_count: 0, elapsed_seconds: 0, cost_usd: 0 } },
  tool_call: {
    name: "Bash",
    // POLICY_TARGET_LEAF is the leaf assemble-snapshot.ts copies a tool's own
    // policy-target argument to; policy/manifest.yaml's pre_tool_call point
    // targets that leaf, not `command` directly.
    args: { command: "echo ghp_ONLYINCOMMAND999", [POLICY_TARGET_LEAF]: "echo ghp_ONLYINCOMMAND999" },
    // The same point's `annotations.egress.from` names this member, and an
    // annotation's `from` is a liveness precondition: unresolved, AGT denies
    // the whole call on runtime_error:path_missing before the annotator is
    // dispatched. assemble-snapshot.ts writes it on every real snapshot.
    raw_command: "echo ghp_ONLYINCOMMAND999",
    id: "t1",
  },
  input: { ifc: { source_labels: ["public"] } },
};
const POST_TOOL_CALL_SNAPSHOT: InterventionSnapshot = {
  envelope: { budgets: { tool_call_count: 0, token_count: 0, elapsed_seconds: 0, cost_usd: 0 } },
  tool_call: { name: "Bash" },
  tool_result: { outputs: [{ value: "TOKEN=ghp_ONLYINOUTPUT999\n" }] },
  input: { ifc: { source_labels: ["public"] } },
};

export type ConformanceRun = {
  /** Everything this runner publishes, as one string -- the three tables plus
   * the legs report, in the order printed. This is the text the published
   * declaration of what this implementation claims, and
   * the v7 runbook of the standalone repository (github.com/afogel/ACS_reference_implementation,
   * docs/demos/v7-runbook.md), are written from, which is why the legs
   * report is part of it rather than a log line: a reader of the runbook must
   * be able to see which legs measured the tables above without running
   * anything. */
  output: string;
  /** The merged matrix `renderCoverageMatrix` rendered `output`'s coverage
   * section from -- exposed alongside the text so a caller (this file's own
   * test) can assert its shape precisely instead of pattern-matching text. */
  cells: CoverageMatrix;
  /** 0 for a fully resolved matrix, non-zero for a finding: a cell whose
   * declaration was checked and does not hold, or a coordinate no check
   * measured (exit-code.ts's own `resolveExitCode` -- see that file for the
   * rule this reads, and why an `unexpressed` cell is neither). */
  exitCode: number;
};

export async function main(): Promise<ConformanceRun> {
  const mapping = loadMapping(MAPPING_PATH);
  // One function builds both: `startGuardian` on the next line calls
  // `createDeploymentBridge` itself, so the bridge this runner measures
  // directly and the bridge behind the live Guardian below cannot drift apart.
  // Assembling the recipe here instead would have made every measurement
  // conditional on this file remembering it, and the failure is silent in the
  // worst direction -- a bridge missing this deployment's annotator denies
  // every call on `runtime_error:annotation_failed`, which a coverage matrix
  // would faithfully report as the implementation's own behaviour.
  const bridge = createDeploymentBridge(MANIFEST_PATH);
  const guardian = await startGuardian({ port: 0, manifestPath: MANIFEST_PATH });

  try {
    const n41 = coverageCellsFromInterventionPoints(checkInterventionPoints(mapping));
    const n42 = checkVerdicts(mapping);
    const [preFinding, postFinding] = await Promise.all([
      measureIdentity(bridge, "pre_tool_call", PRE_TOOL_CALL_SNAPSHOT),
      measureIdentity(bridge, "post_tool_call", POST_TOOL_CALL_SNAPSHOT),
    ]);
    const n43 = [...coverageCellsFromIdentity(preFinding), ...coverageCellsFromIdentity(postFinding)];
    const n44 = await checkDenyFailsClosed(guardian, mapping);

    const cells = mergeCells(n41, n42, n43, n44);
    const traceRows = checkTracePillar();
    const schemaLeg = await checkPolicyInputSchema(bridge);

    const schemaLegLine = schemaLeg.ran
      ? `policy-input schema (AGT's own policy-input.schema.json, at the pinned ref): RAN -- validated ${schemaLeg.points.join(", ")}`
      : `policy-input schema (AGT's own policy-input.schema.json, at the pinned ref): DID NOT RUN -- ${schemaLeg.reason}`;

    const output = [
      "=== Mapping table: what this implementation declares (from mapping.yaml) ===",
      renderMappingTable(mapping),
      "",
      "=== Coverage matrix: what was measured, 8 AGT intervention points x 5 AGT verdicts ===",
      renderCoverageMatrix(cells),
      "",
      "=== Trace pillar: measured as a non-claim, attribute by attribute ===",
      renderTraceRows(traceRows),
      "",
      "=== Which checks ran ===",
      "intervention-point round trip (through the Guardian's own resolver): RAN",
      schemaLegLine,
      "verdict round trip (through the Guardian's own verdict mapping): RAN",
      "action identity (recomputed at pre_tool_call and post_tool_call, merged): RAN",
      "deny fails closed (live Guardian, over the wire): RAN",
      "trace pillar: RAN",
    ].join("\n");

    return { output, cells, exitCode: resolveExitCode(cells) };
  } finally {
    await guardian.close();
  }
}

if (import.meta.main) {
  const run = await main();
  console.log(run.output);
  if (run.exitCode !== 0) {
    console.error(
      `\nconformance: exit ${run.exitCode} -- this matrix carries a finding. Either a cell reads ` +
        `contract_violated (a declaration this repository makes was checked and does not hold -- the grid's ` +
        `own legend and footnotes above say which), or a coordinate has no check named against it at all. An ` +
        `unexpressed cell is neither: it reports a gap ACS v0.1.0 really has, and never makes this exit ` +
        `non-zero`,
    );
  }
  process.exit(run.exitCode);
}
