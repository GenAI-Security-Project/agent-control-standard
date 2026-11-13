import { readFileSync } from "node:fs";
// The deployment subpath, not the barrel: the barrel is the governance verbs,
// and this is how the deployment builds a bridge. This watch validates the
// document the shipped deployment sends AGT, so it has to send the document
// the shipped bridge produces.
import { createDeploymentBridge } from "guardian/deployment";
import { diffSurfaces, type SurfaceDiff } from "./diff-surfaces.ts";
import { fetchUpstreamSurfaces, UPSTREAM_AGT_CLONE_ENV } from "./fetch-upstream.ts";
import { checkPolicyInputSchemaAt, PINNED_AGT_CLONE_ENV } from "./policy-input-schema.ts";
import { renderUpstreamDiff } from "./render-upstream-diff.ts";
import { asPinned, readSurfaces, type PinnedSurfaces, type UpstreamSurfaces } from "./surfaces.ts";
import { checkToolsAgainstRegistry, renderToolsRegistryReport } from "./tools-registry.ts";

const MANIFEST_PATH = "policy/manifest.yaml";

/** The two hookmaps this deployment ships, read the same cwd-relative way
 * `main.ts` reads `MANIFEST_PATH` -- both callers of this module run from
 * the repository root. */
const HOOKMAP_PATHS = ["hosts/claude-code/claude-code.hookmap.yaml", "hosts/opencode/opencode.hookmap.yaml"] as const;

/**
 * Reads a hookmap only as far as `checkToolsAgainstRegistry` needs: its own
 * path and each hook's `tools` entry. This does not call `loadHookmap`
 * (host-adapter/src/build-envelope.ts), which validates a great deal more
 * about a hookmap than its `tools` lists -- a hookmap that fails that wider
 * validation for a reason this section does not measure must not stop this
 * section from reporting on the other hookmap.
 *
 * A read or parse failure is rethrown naming THIS path. `Bun.YAML.parse`'s
 * own error on malformed YAML carries no file name at all (measured: "YAML
 * Parse error: Unexpected token"), so with three files read in this section
 * a caller cannot tell which one failed from the error alone -- naming the
 * path here, at the one point that still knows it, is what keeps the report
 * answerable.
 */
function readHookmapTools(path: string): { path: string; hooks: Record<string, { tools?: unknown }> } {
  try {
    const raw = Bun.YAML.parse(readFileSync(path, "utf8")) as { hooks?: Record<string, { tools?: unknown }> };
    return { path, hooks: raw.hooks ?? {} };
  } catch (error) {
    throw new Error(`${path}: ${(error as Error).message}`);
  }
}

/** The policy manifest's own tool registry: the keys of its top-level
 * `tools:` mapping, one entry per name a host actually dispatches.
 *
 * A read or parse failure is rethrown naming THIS path, for the identical
 * reason `readHookmapTools` does. */
function readManifestToolRegistry(path: string): string[] {
  try {
    const raw = Bun.YAML.parse(readFileSync(path, "utf8")) as { tools?: Record<string, unknown> };
    return Object.keys(raw.tools ?? {});
  } catch (error) {
    throw new Error(`${path}: ${(error as Error).message}`);
  }
}

/**
 * The third reported section, beside the surface-read failure and the
 * schema question above: reads the two shipped hookmaps and the policy
 * manifest's tool registry and renders what `checkToolsAgainstRegistry`
 * finds. A missing, unreadable or unparseable file is caught here and
 * rendered as a line naming what went wrong, never propagated -- this
 * function does not throw.
 *
 * `hookmapPaths` and `manifestPath` default to the two shipped hookmaps and
 * the real policy manifest, so the one real caller below needs to pass
 * neither. They are parameters rather than only the module's own constants
 * so a test can point this at a fixture that is missing or will not parse,
 * without touching a real file in this repository.
 */
export function renderToolsRegistrySection(
  hookmapPaths: readonly string[] = HOOKMAP_PATHS,
  manifestPath: string = MANIFEST_PATH,
): string {
  try {
    const hookmaps = hookmapPaths.map(readHookmapTools);
    const registry = readManifestToolRegistry(manifestPath);
    return renderToolsRegistryReport(checkToolsAgainstRegistry(hookmaps, registry));
  } catch (error) {
    return `Hookmap tools against the policy manifest: could not read -- ${(error as Error).message}`;
  }
}

/**
 * What re-asking the policy-input schema question of `main` answers, beside
 * the surface diff. A surface diff says a field moved; this says whether the
 * document the Guardian actually sends still validates against the schema
 * as it stands on `main` today -- a field can move without the document we
 * send ever touching it, and a field the diff never names can still be the
 * one a tightened `required` now rejects.
 *
 * `checked: false` only when the run itself did not happen -- one of the two
 * clones was missing or unreadable -- because there is then no clone of
 * `main` to ask the question against.
 */
export type SchemaAgainstMain =
  | { readonly checked: false }
  | { readonly checked: true; readonly ok: true; readonly points: readonly string[] }
  | { readonly checked: true; readonly ok: false; readonly reason: string };

type SchemaAgainstMainChecked = Extract<SchemaAgainstMain, { checked: true }>;

const NOT_CHECKED: SchemaAgainstMain = { checked: false };

export type UpstreamWatchRun = {
  readonly ran: boolean;
  readonly output: string;
  readonly diffs: readonly SurfaceDiff[];
  readonly schemaAgainstMain: SchemaAgainstMain;
};

function skipped(reason: string): UpstreamWatchRun {
  return { ran: false, diffs: [], schemaAgainstMain: NOT_CHECKED, output: reason };
}

function renderSchemaAgainstMain(result: SchemaAgainstMainChecked): string {
  return result.ok
    ? `Policy-input schema against main: the policy input we send still validates against main ` +
        `(checked at ${result.points.join(", ")}).`
    : `Policy-input schema against main: FAILURE -- ${result.reason}`;
}

/** Names the two commits `scripts/run-upstream-watch.sh` resolves with
 * `git -C "$dir" rev-parse HEAD` after making each clone -- the pinned ref's
 * side and main's. Read here, and printed in the degraded line below, so a
 * reader of the run's own output does not have to go and find the name in
 * this file to reproduce the resolution locally. */
export const PINNED_AGT_SHA_ENV = "PINNED_AGT_SHA";
export const UPSTREAM_AGT_SHA_ENV = "UPSTREAM_AGT_SHA";

/**
 * Names the two commits this run actually compared. "No watched surface
 * moved" reads identically whether the diff compared the right two refs or
 * the wrong ref against itself -- this line is what tells those apart.
 *
 * Both SHAs are resolved by the shell script, never here: nothing in this
 * module resolves a ref or shells out, for the same reason nothing in it
 * clones. `bun test` sets neither variable, so every test run takes the
 * `undefined` branch -- a fixed line saying the SHAs were not supplied,
 * never an empty string and never a fabricated commit.
 */
function renderComparedRefs(env: Record<string, string | undefined>): string {
  const pinnedSha = env[PINNED_AGT_SHA_ENV];
  const upstreamSha = env[UPSTREAM_AGT_SHA_ENV];
  if (pinnedSha === undefined || pinnedSha.length === 0 || upstreamSha === undefined || upstreamSha.length === 0) {
    return (
      `Compared refs: not supplied -- ${PINNED_AGT_SHA_ENV} and ${UPSTREAM_AGT_SHA_ENV} are only set by ` +
      `scripts/run-upstream-watch.sh.`
    );
  }
  return `Compared refs: pinned ${pinnedSha} against main ${upstreamSha}.`;
}

/**
 * Assembles the run: reads the pinned side, fetches the upstream side, hands
 * both to the differ, re-asks the policy-input schema question of the
 * upstream clone, checks this deployment's own hookmaps against its own
 * policy manifest, and renders what came back.
 *
 * The pinned side is read HERE rather than inside the differ, so the differ
 * has no store to reach for and no ref to resolve -- it is told two snapshots
 * and compares them. Both clones are made by the shell script, which is the
 * only place in this slice that touches the network.
 *
 * Both variables are checked for presence BEFORE either side is read. Reading
 * used to start with the upstream side regardless, so a malformed upstream
 * clone would throw even on a run that was only ever going to self-skip for
 * a missing pinned clone -- the wrong clone got blamed for a run that was
 * never going to happen.
 *
 * Reading itself is wrapped, because `readSurfaces` throws on a missing or
 * relocated surface -- correctly: a watch that reported an absent surface as
 * "unchanged" would be exactly the silent rot this exists to catch. Catching
 * it here is what makes that failure legible rather than merely fatal: the
 * scheduled workflow pipes this run's stdout into `$GITHUB_STEP_SUMMARY`, and
 * an uncaught throw writes nothing there -- the published summary comes out
 * empty and the real error is left in the raw log for someone to go and find.
 * So a read failure on either side is caught and turned into a report naming
 * which side and what went missing, and the run answers `ran: false` rather
 * than propagating. `ran: false` is not a swallowed error: it is what the
 * entry point at the bottom of this file turns into a non-zero exit status.
 *
 * The schema re-check is handled the same way for the same reason: it keeps
 * its own shipped behaviour of throwing on a genuine validation failure, and
 * that throw is caught here and rendered as a failure line rather than
 * allowed to escape.
 *
 * The hookmap tools-against-registry section is the third report of the same
 * kind, and it needs neither clone: it reads this deployment's own hookmaps
 * and its own policy manifest off the working directory, so it is computed
 * once the run has gotten this far rather than gated on either clone being
 * present. `renderToolsRegistrySection` catches its own read and parse
 * failures and never throws, for the identical reason the two checks above
 * it are caught rather than left to propagate.
 *
 * The compared-refs line is prepended to a successful run's output rendering
 * the two resolved commits `env` was handed, or a fixed line saying they
 * were not supplied when it was not -- so a clean diff is never mistaken for
 * a run that compared the wrong ref, or the same ref twice.
 *
 * This slice reports findings and never refuses them -- surface drift, a
 * schema rejection against main, a hookmap tool missing from the registry all
 * leave the build green, because each of those is a completed run with
 * something for a human to decide. A run that did not happen is the one thing
 * that does fail the job, and the entry point below is where that line is
 * drawn.
 */
export async function runUpstreamWatch(
  env: Record<string, string | undefined> = process.env,
): Promise<UpstreamWatchRun> {
  const pinnedClone = env[PINNED_AGT_CLONE_ENV];
  const upstreamClone = env[UPSTREAM_AGT_CLONE_ENV];
  const bothPresent =
    pinnedClone !== undefined && pinnedClone.length > 0 && upstreamClone !== undefined && upstreamClone.length > 0;
  if (!bothPresent) {
    return skipped(
      `Upstream contract watch: skipped. Both ${PINNED_AGT_CLONE_ENV} and ${UPSTREAM_AGT_CLONE_ENV} must name ` +
        `an AGT clone; run it through scripts/run-upstream-watch.sh, which makes both.`,
    );
  }

  let pinned: PinnedSurfaces;
  try {
    pinned = asPinned(readSurfaces(pinnedClone));
  } catch (error) {
    return skipped(
      `Upstream contract watch: could not read the pinned ref's surfaces -- ${(error as Error).message}`,
    );
  }

  let upstream: UpstreamSurfaces;
  try {
    // fetchUpstreamSurfaces only answers undefined when its own variable is
    // absent, and that was already ruled out by `bothPresent` above.
    upstream = fetchUpstreamSurfaces(env)!;
  } catch (error) {
    return skipped(`Upstream contract watch: could not read main's surfaces -- ${(error as Error).message}`);
  }

  const diffs = diffSurfaces(pinned, upstream);

  let schemaAgainstMain: SchemaAgainstMainChecked;
  try {
    // A bridge without this deployment's annotator would send AGT a policy
    // input whose `annotations` never arrived, and take a deny on
    // runtime_error:annotation_failed -- measured. What this leg validates
    // against upstream's schema would then be a document the deployment never
    // sends.
    const bridge = createDeploymentBridge(MANIFEST_PATH);
    const result = await checkPolicyInputSchemaAt(bridge, upstreamClone);
    schemaAgainstMain = result.ran
      ? { checked: true, ok: true, points: result.points }
      : { checked: true, ok: false, reason: result.reason };
  } catch (error) {
    schemaAgainstMain = { checked: true, ok: false, reason: (error as Error).message };
  }

  const output = [
    renderComparedRefs(env),
    "",
    renderUpstreamDiff(diffs),
    "",
    renderSchemaAgainstMain(schemaAgainstMain),
    "",
    renderToolsRegistrySection(),
  ].join("\n");
  return { ran: true, diffs, schemaAgainstMain, output };
}

/**
 * The process's answer to "did the watch run?", which is a different question
 * from "did anything move?".
 *
 * Drift found upstream is this job's product, not its failure: a moved AGT
 * surface is reported and still exits 0, because the remedy is a human
 * deciding whether to move the pin, not a red job on a Monday morning. Every
 * other finding this run can report -- a schema rejection against main, a
 * hookmap tool missing from the policy manifest -- is the same shape and
 * exits 0 for the same reason. A watch that could not RUN is the opposite: a
 * clone that was never made, a surface relocated out from under
 * `readSurfaces`, a fetch that never landed. Publishing that as a green run
 * with an empty diff is precisely the silent rot this slice exists to catch,
 * committed by the harness built to catch it -- so `ran: false` is the one
 * answer that leaves the process non-zero.
 *
 * `ran` already draws that line inside the process. This carries it out to
 * the only reader living outside, CI, which can see nothing but a status.
 *
 * `process.exitCode` rather than `process.exit`, because the workflow reads
 * this run through a pipe into `$GITHUB_STEP_SUMMARY` and `process.exit` can
 * tear the process down with that write still buffered. Letting the process
 * end on its own flushes stdout first; a truncated step summary is the same
 * class of defect as a status that could never go red.
 */
if (import.meta.main) {
  const run = await runUpstreamWatch();
  console.log(run.output);
  process.exitCode = run.ran ? 0 : 1;
}
