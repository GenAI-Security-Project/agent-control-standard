/**
 * Test-only fixture helper for covering every AGT verdict. AGT's priority
 * chain (deny > escalate > transform > warn > allow) means a single
 * `data.agt.defaults.config` document cannot reach every verdict at once --
 * with `approval.required: true`, every non-denied step escalates, making
 * `allow`/`transform`/`warn` unreachable in that same config. Covering all
 * five verdicts therefore means varying the config across separate runs,
 * and config lives in the bundle directory (loaded from its `data.json`),
 * not pushed by the SDK at call time -- so varying config means varying the
 * bundle directory. This builds one such directory per call.
 *
 * The central risk this helper exists to close: a fixture bundle that
 * silently forks `policy/lib/*.rego` would let every test above pass while
 * quietly invalidating this project's central claim that AGT's engine runs
 * unforked at a pinned commit. `buildConfigBundle` copies each `.rego` file
 * and reads both the source and the just-written copy back off disk,
 * comparing them byte-for-byte, so a copy that silently corrupts or
 * truncates a file fails loudly, immediately, naming the file -- not
 * "coverage passed while the pin quietly broke."
 */
import { mkdtempSync, readFileSync, readdirSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** This file lives at test/helpers/, two directories under the repo root,
 * the same relationship policy/lib itself has to the root -- so this is
 * always the real, pinned bundle this project vendors, never a path that
 * could silently drift if this file moved. */
const POLICY_LIB_DIR = fileURLToPath(new URL("../../policy/lib/", import.meta.url));

export type ConfigBundle = { dir: string; cleanup(): void };

/**
 * Copies every `policy/lib/*.rego` file into a fresh temp directory
 * alongside a generated `data.json` holding
 * `{ agt: { defaults: { config } } }`, and asserts each copy is
 * byte-identical to its source. Deliberately copies only `*.rego` --
 * never `run_tests.sh` (an upstream test runner this project's own
 * `policy/lib` directory happens to carry but a fixture bundle has no use
 * for) and never the tracked `data.json` (this helper generates its own).
 *
 * `cleanup()` removes exactly what exists in the directory at the moment
 * it is called, by name, then removes the now-empty directory -- never a
 * recursive delete. Reading the directory fresh (rather than remembering
 * the file list built at construction time) is deliberate: `buildManifest`
 * below writes its manifest into this same directory, and this way
 * `cleanup()` does not need to know about that decision to still get rid
 * of it.
 */
export function buildConfigBundle(config: unknown): ConfigBundle {
  const dir = mkdtempSync(join(tmpdir(), "acs-config-bundle-"));

  // The copy below is deliberately flat -- `*.rego` in this one directory,
  // nothing recursive -- which is correct for the bundle this project vendors
  // and would silently under-copy the day it gained a nested rego file. So the
  // assumption is asserted rather than explained: a subdirectory here fails
  // loudly now instead of producing a quietly incomplete fixture bundle later.
  const entries = readdirSync(POLICY_LIB_DIR, { withFileTypes: true });
  const subdirectories = entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name);
  if (subdirectories.length > 0) {
    throw new Error(
      `buildConfigBundle: ${POLICY_LIB_DIR} has subdirectories (${subdirectories.join(", ")}), but this helper ` +
        "copies *.rego from the top level only -- make the copy recursive before adding a nested rego file",
    );
  }

  const regoFiles = entries.filter((entry) => entry.isFile() && entry.name.endsWith(".rego")).map((entry) => entry.name);
  for (const file of regoFiles) {
    const source = readFileSync(join(POLICY_LIB_DIR, file));
    writeFileSync(join(dir, file), source);
    const copy = readFileSync(join(dir, file));
    if (!source.equals(copy)) {
      throw new Error(
        `buildConfigBundle: ${file} was not copied byte-identically from ${POLICY_LIB_DIR} -- ` +
          `a fixture bundle must never silently fork the pinned bundle`,
      );
    }
  }

  writeFileSync(join(dir, "data.json"), JSON.stringify({ agt: { defaults: { config } } }, null, 2));

  return {
    dir,
    cleanup() {
      for (const entry of readdirSync(dir)) {
        unlinkSync(join(dir, entry));
      }
      rmdirSync(dir);
    },
  };
}

export type BuildManifestOptions = {
  bundleDir: string;
  /** When true, declares a `drift_score` classifier annotator and wires it
   * to `pre_tool_call` via `annotations.drift_score.from`, matching
   * `policy/manifest.drift.yaml`'s own two blocks (see that file's header
   * for why a host-supplied score, not one derived from the ACS envelope,
   * is what AGT's own drift gate expects). Omitted/false emits the plain
   * manifest with no annotator at all. */
  annotator?: boolean;
};

/**
 * Writes a manifest into `bundleDir` itself, pointing its `bundle:` field
 * back at that same directory -- so the manifest and the bundle it
 * declares are always co-located, and `buildConfigBundle`'s `cleanup()`
 * (which re-reads the directory rather than a remembered file list) picks
 * this file up too. Returns the manifest's path.
 *
 * `bundle:` is written as `bundleDir`'s own absolute path, not `"."`. A
 * relative `"."` resolves to an empty bundle directory, and with no rules
 * loaded, the Rego library's own `default verdict := {"decision": "allow"}`
 * is the only rule left to apply -- so evaluation returns `allow` and
 * nothing is wrong from the engine's point of view. That is Rego's
 * default-rule semantics doing exactly what they say, not a defect: the
 * risk lives entirely in the bundle path, which is why this writes an
 * absolute one.
 */
export function buildManifest({ bundleDir, annotator = false }: BuildManifestOptions): string {
  const manifestPath = join(bundleDir, "manifest.yaml");

  const annotatorsBlock = annotator ? "annotators:\n  drift_score:\n    type: classifier\n" : "";
  const annotationsBlock = annotator
    ? '    annotations:\n      drift_score:\n        from: "$.tool_call.args.command"\n'
    : "";

  const manifest =
    'agent_control_specification_version: "0.3.1-beta"\n' +
    "metadata:\n" +
    '  name: "acs-dispositions-fixture"\n' +
    "policies:\n" +
    "  agt_stock:\n" +
    "    type: rego\n" +
    `    bundle: "${bundleDir}"\n` +
    "    query: data.agt.defaults.verdict\n" +
    annotatorsBlock +
    "intervention_points:\n" +
    "  pre_tool_call:\n" +
    '    policy_target: "$.tool_call.args.command"\n' +
    "    policy_target_kind: tool_args\n" +
    '    tool_name_from: "$.tool_call.name"\n' +
    annotationsBlock +
    "    policy:\n" +
    "      id: agt_stock\n" +
    "tools:\n" +
    // Both names, matching policy/manifest.yaml: "run_shell" is AGT's own
    // stock example name (packages/agt-bridge/test/bridge.test.ts's fixture
    // snapshots use it), "Bash" is Claude Code's real tool name for shell
    // execution (test/dispositions.test.ts's snapshots use that one).
    "  run_shell:\n" +
    "    type: Tool\n" +
    "    id: run_shell\n" +
    "    security_labels: [shell]\n" +
    "  Bash:\n" +
    "    type: Tool\n" +
    "    id: Bash\n" +
    "    security_labels: [shell]\n";

  writeFileSync(manifestPath, manifest);
  return manifestPath;
}
