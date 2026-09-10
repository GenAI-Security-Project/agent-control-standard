import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * The eight AGT contract surfaces this watch reads, and no others. Coupling
 * is to what AGT declares -- its wire schemas, its two enums, its reserved
 * reasons and the config keys its default policy reads -- never to SDK
 * internals or private APIs.
 *
 * Eight surfaces are not eight files. Five are documents; two are enums that
 * live inside documents already read here; one exists only as Rego source.
 */
export type SurfaceName =
  | "manifest.schema.json"
  | "policy-input.schema.json"
  | "verdict.schema.json"
  | "snapshot.schema.json"
  | "intervention-point enum"
  | "verdict enum"
  | "reserved-reasons.json"
  | "data.agt.defaults.config keys";

export const SURFACE_NAMES: readonly SurfaceName[] = [
  "manifest.schema.json",
  "policy-input.schema.json",
  "verdict.schema.json",
  "snapshot.schema.json",
  "intervention-point enum",
  "verdict enum",
  "reserved-reasons.json",
  "data.agt.defaults.config keys",
];

export type SurfaceSnapshot = Readonly<Record<SurfaceName, unknown>>;

/**
 * The same eight surfaces read at the ref `agt.lock` records, and the same
 * eight read at `main`. One shape, two sources, and the name says which --
 * a single type serving both is the shape in which a run that read the
 * pinned side twice still reports a clean diff.
 */
export type PinnedSurfaces = SurfaceSnapshot & { readonly __side: "pinned" };
export type UpstreamSurfaces = SurfaceSnapshot & { readonly __side: "upstream" };

export const asPinned = (s: SurfaceSnapshot): PinnedSurfaces => s as PinnedSurfaces;
export const asUpstream = (s: SurfaceSnapshot): UpstreamSurfaces => s as UpstreamSurfaces;

const SPEC = "policy-engine/spec";
const PATHS = {
  manifest: `${SPEC}/schema/manifest.schema.json`,
  policyInput: `${SPEC}/schema/wire/policy-input.schema.json`,
  verdict: `${SPEC}/schema/wire/verdict.schema.json`,
  snapshot: `${SPEC}/schema/wire/snapshot.schema.json`,
  reservedReasons: `${SPEC}/reserved-reasons.json`,
  defaultsRego: "policy-engine/policy/lib/agt_default.rego",
} as const;

/**
 * Reads and parses one JSON surface. Both steps are inside the one try: a
 * read failure and a parse failure are different problems, but only the read
 * failure named `relative` before this was written -- `JSON.parse`'s own
 * error carries no file name at all (measured: "JSON Parse error: Expected
 * '}'"), so a malformed document used to surface as an anonymous parse error
 * with no way to tell which of the five JSON surfaces it came from. Naming
 * `relative` in both branches is what keeps the report answerable, the same
 * fix `readHookmapTools` (upstream-watch.ts) already makes for a malformed
 * hookmap.
 */
function readJson(cloneDir: string, relative: string): unknown {
  const full = join(cloneDir, relative);
  try {
    const raw = readFileSync(full, "utf8");
    return JSON.parse(raw);
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error(
        `readSurfaces: expected an AGT surface at ${relative}, and it did not parse as JSON -- ${error.message}`,
      );
    }
    throw new Error(`readSurfaces: expected an AGT surface at ${relative}, and the clone has no such file`);
  }
}

/**
 * Every `cfg.<key>` the default policy reads, deduped and sorted. This
 * surface has no document to fetch: the keys exist only as reads in Rego
 * source, so a moved key shows up here as a name appearing or disappearing.
 */
function defaultsConfigKeys(cloneDir: string): string[] {
  const full = join(cloneDir, PATHS.defaultsRego);
  let source: string;
  try {
    source = readFileSync(full, "utf8");
  } catch {
    throw new Error(`readSurfaces: expected AGT's default policy at ${PATHS.defaultsRego}, and the clone has no such file`);
  }
  const keys = new Set<string>();
  for (const match of source.matchAll(/\bcfg\.([a-z_]+(?:\.[a-z_]+)?)/g)) {
    keys.add(match[1] as string);
  }
  return [...keys].sort();
}

function enumAt(document: unknown, path: readonly string[], surface: string): unknown {
  let cursor: unknown = document;
  for (const segment of path) {
    if (typeof cursor !== "object" || cursor === null) {
      throw new Error(`readSurfaces: ${surface} is not where it was: ${path.join("/")} left the document early at "${segment}"`);
    }
    cursor = (cursor as Record<string, unknown>)[segment];
  }
  if (!Array.isArray(cursor)) {
    throw new Error(`readSurfaces: ${surface} is not an array at ${path.join("/")}`);
  }
  return cursor;
}

/** Reads all eight surfaces out of one AGT clone. Throws on a missing or
 * relocated surface: a watch that reports an absent surface as "unchanged"
 * is the silent rot this slice exists to catch. */
export function readSurfaces(cloneDir: string): SurfaceSnapshot {
  const manifest = readJson(cloneDir, PATHS.manifest);
  const verdict = readJson(cloneDir, PATHS.verdict);
  return {
    "manifest.schema.json": manifest,
    "policy-input.schema.json": readJson(cloneDir, PATHS.policyInput),
    "verdict.schema.json": verdict,
    "snapshot.schema.json": readJson(cloneDir, PATHS.snapshot),
    "intervention-point enum": enumAt(
      manifest,
      ["properties", "intervention_points", "propertyNames", "enum"],
      "the intervention-point enum",
    ),
    "verdict enum": enumAt(verdict, ["properties", "decision", "enum"], "the verdict enum"),
    "reserved-reasons.json": readJson(cloneDir, PATHS.reservedReasons),
    "data.agt.defaults.config keys": defaultsConfigKeys(cloneDir),
  };
}
