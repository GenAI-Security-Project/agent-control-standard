import { readFileSync } from "node:fs";
import { posix } from "node:path";

/**
 * Returns why a manifest's `bundle:` value breaks policy, or `undefined` when
 * the value is safe.
 *
 * Measured through `createBridge`, with `rm -rf /` as the step, on integration
 * at db457a8:
 *
 *   denied as expected:  `lib`, `lib/`, `sub/lib`, an absolute path
 *   allowed, no reason:  `./lib`, `lib/.`, `./lib/`, `lib/./`, `lib/../lib`,
 *                        `sub/../lib`, `../policy/lib`, `.//lib`, `lib//`,
 *                        `sub//lib`
 *   every step denied:   `.`, `lib/..`
 *                        (runtime_error:policy_invocation_failed)
 *
 * The bridge starts without an error on every value in the second group. AGT
 * already refuses an empty value.
 *
 * The rule: no `.` or `..` segment, and no path that `posix.normalize` would
 * change. A trailing slash and an absolute path pass.
 */
export function bundlePathProblem(bundle: string): string | undefined {
  const segments = bundle.split("/");
  if (segments.includes(".") || segments.includes("..")) {
    return 'it has a "." or ".." path segment';
  }
  if (posix.normalize(bundle) !== bundle) {
    return "it is not a normalized path";
  }
  return undefined;
}

/**
 * Throws when a policy in the manifest has a `bundle` value that
 * `bundlePathProblem` rejects. Runs before AGT reads the manifest, so such a
 * manifest gets no bridge.
 *
 * A manifest that does not exist is left to AGT, which throws
 * `runtime_error:manifest_invalid`. A manifest this check cannot parse is
 * refused here, so a parse error cannot skip the check.
 */
export function assertManifestBundlesSafe(manifestPath: string): void {
  let text: string;
  try {
    text = readFileSync(manifestPath, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }

  let manifest: unknown;
  try {
    manifest = Bun.YAML.parse(text);
  } catch (error) {
    throw new Error(`${manifestPath}: could not read the manifest to check its bundle paths: ${(error as Error).message}`);
  }

  const policies = (manifest as { policies?: unknown } | null)?.policies;
  if (policies === null || typeof policies !== "object") return;

  for (const [id, policy] of Object.entries(policies)) {
    const bundle = (policy as { bundle?: unknown } | null)?.bundle;
    if (typeof bundle !== "string") continue;
    const problem = bundlePathProblem(bundle);
    if (problem !== undefined) {
      throw new Error(
        `${manifestPath}: policy "${id}" has bundle "${bundle}", and ${problem}. With a value like this AGT either ` +
          `allows steps the policy should deny or denies every step. Write the bundle as a plain relative path ` +
          `such as "lib".`,
      );
    }
  }
}
