import { asUpstream, readSurfaces, type UpstreamSurfaces } from "./surfaces.ts";

/**
 * The clone of AGT at `main` this watch reads. A shell script makes the
 * clone and passes its path here, for the same reason the policy-input
 * schema check takes its pinned clone that way: fetching needs the network,
 * and keeping the network in one shell script means every TypeScript module
 * stays runnable under `bun test` with no network at all.
 *
 * Deliberately not the pinned clone's variable. The pinned ref and `main`
 * are the two sides of the diff, and a differ told the same side twice
 * reports a clean run against a contract that moved.
 */
export const UPSTREAM_AGT_CLONE_ENV = "UPSTREAM_AGT_CLONE";

/**
 * Reads AGT's eight surfaces at `main` out of the clone the environment
 * names, or answers `undefined` when there is no clone to read.
 *
 * Absent variable and unreadable clone are different answers on purpose.
 * `bun test` never sets the variable, so the watch self-skips there and the
 * rest of the suite stays covered without a network. A variable that IS set
 * and names a directory with no AGT in it is a broken run, and `readSurfaces`
 * throws rather than reporting eight surfaces that were never read.
 */
export function fetchUpstreamSurfaces(
  env: Record<string, string | undefined> = process.env,
): UpstreamSurfaces | undefined {
  const cloneDir = env[UPSTREAM_AGT_CLONE_ENV];
  if (cloneDir === undefined || cloneDir.length === 0) {
    return undefined;
  }
  return asUpstream(readSurfaces(cloneDir));
}
