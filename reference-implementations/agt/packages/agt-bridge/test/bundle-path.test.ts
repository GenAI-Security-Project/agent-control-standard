import { describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assertManifestBundlesSafe, bundlePathProblem } from "../src/bundle-path.ts";
import { createBridge } from "../src/index.ts";

// Measured through `createBridge` against the shipped bundle, with `rm -rf /`
// as the step. Each value returned `allow` with no reason and no startup
// error. See src/bundle-path.ts.
const ALLOWED_BY_MISTAKE = [
  "./lib",
  "lib/.",
  "./lib/",
  "lib/./",
  "lib/../lib",
  "sub/../lib",
  "../policy/lib",
  ".//lib",
  "lib//",
  "sub//lib",
];

// Measured: the bridge starts, then denies every step with
// runtime_error:policy_invocation_failed.
const DENIES_EVERY_STEP = [".", "lib/.."];

// Measured: `rm -rf /` is denied as destructive_shell_command_blocked.
const SAFE = ["lib", "lib/", "sub/lib", "/var/tmp/policy/lib"];

const SHIPPED_MANIFEST = "policy/manifest.yaml";

/** A copy of the shipped manifest with its one `bundle:` line replaced. The
 * bundle directory is not copied, because the guard refuses before AGT reads it. */
function manifestWithBundle(bundle: string): { path: string; cleanup(): void } {
  const dir = mkdtempSync(join(tmpdir(), "acs-bundle-guard-"));
  const path = join(dir, "manifest.yaml");
  const source = readFileSync(SHIPPED_MANIFEST, "utf8");
  const edited = source.replace(/^ {4}bundle: lib$/m, `    bundle: ${bundle}`);
  if (edited === source) throw new Error("the shipped manifest no longer has a `bundle: lib` line to replace");
  writeFileSync(path, edited);
  return {
    path,
    cleanup() {
      unlinkSync(path);
      rmdirSync(dir);
    },
  };
}

describe("bundlePathProblem", () => {
  for (const bundle of ALLOWED_BY_MISTAKE) {
    it(`refuses ${JSON.stringify(bundle)}, which AGT allowed for a destructive step`, () => {
      expect(bundlePathProblem(bundle)).toBeDefined();
    });
  }

  for (const bundle of DENIES_EVERY_STEP) {
    it(`refuses ${JSON.stringify(bundle)}, which denies every step`, () => {
      expect(bundlePathProblem(bundle)).toBeDefined();
    });
  }

  for (const bundle of SAFE) {
    it(`accepts ${JSON.stringify(bundle)}`, () => {
      expect(bundlePathProblem(bundle)).toBeUndefined();
    });
  }

  it("refuses an empty value, which AGT also refuses at construction", () => {
    expect(bundlePathProblem("")).toBeDefined();
  });
});

describe("createBridge refuses a manifest whose bundle breaks policy", () => {
  for (const bundle of [...ALLOWED_BY_MISTAKE, ...DENIES_EVERY_STEP]) {
    it(`refuses to start on bundle: ${bundle}`, () => {
      const manifest = manifestWithBundle(bundle);
      try {
        expect(() => createBridge(manifest.path, { annotator: () => ({}) })).toThrow(/has bundle/);
      } finally {
        manifest.cleanup();
      }
    });
  }

  it("names the policy and the value it refused", () => {
    const manifest = manifestWithBundle("./lib");
    try {
      expect(() => assertManifestBundlesSafe(manifest.path)).toThrow(/policy "agt_stock" has bundle "\.\/lib"/);
    } finally {
      manifest.cleanup();
    }
  });

  it("starts on the shipped manifest, which writes `bundle: lib`", () => {
    expect(() => assertManifestBundlesSafe(SHIPPED_MANIFEST)).not.toThrow();
    expect(() => createBridge(SHIPPED_MANIFEST, { annotator: () => ({}) })).not.toThrow();
  });

  it("leaves a missing manifest to AGT, which throws manifest_invalid", () => {
    const missing = join(tmpdir(), "acs-no-such-manifest.yaml");
    expect(() => assertManifestBundlesSafe(missing)).not.toThrow();
    expect(() => createBridge(missing, { annotator: () => ({}) })).toThrow(/manifest_invalid/);
  });

  it("refuses a manifest it cannot parse, so a parse error cannot skip the check", () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-bundle-guard-"));
    const path = join(dir, "manifest.yaml");
    writeFileSync(path, "policies: [unclosed\n  bundle: ./lib: : :");
    try {
      expect(() => assertManifestBundlesSafe(path)).toThrow(/could not read the manifest to check its bundle paths/);
    } finally {
      unlinkSync(path);
      rmdirSync(dir);
    }
  });
});
