import { SURFACE_NAMES, type PinnedSurfaces, type SurfaceName, type UpstreamSurfaces } from "./surfaces.ts";

/**
 * One field that moved, in AGT's own terms: which surface, which field, and
 * what it was against what it is now. `undefined` on either side means the
 * field is absent there, which is how an added or removed field reads.
 */
export type SurfaceDiff = {
  readonly surface: SurfaceName;
  readonly field: string;
  readonly pinned: unknown;
  readonly upstream: unknown;
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function walk(surface: SurfaceName, pointer: string, pinned: unknown, upstream: unknown, out: SurfaceDiff[]): void {
  if (Array.isArray(pinned) && Array.isArray(upstream)) {
    const longest = Math.max(pinned.length, upstream.length);
    for (let i = 0; i < longest; i += 1) {
      walk(surface, `${pointer}/${i}`, pinned[i], upstream[i], out);
    }
    return;
  }
  if (isObject(pinned) && isObject(upstream)) {
    for (const key of new Set([...Object.keys(pinned), ...Object.keys(upstream)])) {
      walk(surface, `${pointer}/${key}`, pinned[key], upstream[key], out);
    }
    return;
  }
  if (JSON.stringify(pinned) !== JSON.stringify(upstream)) {
    out.push({ surface, field: pointer, pinned, upstream });
  }
}

/**
 * Diffs the eight surfaces read at the pinned ref against the eight read at
 * `main`, and answers one row per field that moved.
 *
 * Told both snapshots and reads neither store. It does not open `agt.lock`,
 * does not resolve a git ref, and does not reach the network -- fetching is
 * the fetcher's job, and reading the pinned side belongs to whatever
 * assembles the run. The parameter order is the diff's own direction:
 * pinned first, because that is the side this repository is built against.
 *
 * Reports rather than judges. An added optional field is a row like any
 * other, so a non-breaking upstream release produces output and no failure.
 */
export function diffSurfaces(pinned: PinnedSurfaces, upstream: UpstreamSurfaces): SurfaceDiff[] {
  const out: SurfaceDiff[] = [];
  for (const surface of SURFACE_NAMES) {
    walk(surface, "", pinned[surface], upstream[surface], out);
  }
  return out;
}
