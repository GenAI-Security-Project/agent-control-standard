// packages/conformance/test/upstream-watch.test.ts
import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  PINNED_AGT_SHA_ENV,
  UPSTREAM_AGT_SHA_ENV,
  renderToolsRegistrySection,
  runUpstreamWatch,
} from "../src/upstream-watch.ts";
import { UPSTREAM_AGT_CLONE_ENV } from "../src/fetch-upstream.ts";
import { PINNED_AGT_CLONE_ENV } from "../src/policy-input-schema.ts";

const createdDirs: string[] = [];

/** trash every fixture directory this file's tests create -- never rm -rf. */
async function trashDir(dir: string): Promise<void> {
  await Bun.$`trash ${dir}`.quiet();
}

// policyInputSchema defaults to a permissive schema that accepts any
// document, so callers not testing the schema question themselves don't
// have to think about it.
function clone(verdicts: string[], policyInputSchema = "{}"): string {
  const dir = mkdtempSync(join(tmpdir(), "watch-"));
  createdDirs.push(dir);
  const write = (rel: string, body: string) => {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, body);
  };
  write("policy-engine/spec/schema/manifest.schema.json", JSON.stringify({ properties: { intervention_points: { propertyNames: { enum: ["input"] } } } }));
  write("policy-engine/spec/schema/wire/policy-input.schema.json", policyInputSchema);
  write("policy-engine/spec/schema/wire/verdict.schema.json", JSON.stringify({ properties: { decision: { enum: verdicts } } }));
  write("policy-engine/spec/schema/wire/snapshot.schema.json", "{}");
  write("policy-engine/spec/reserved-reasons.json", "{}");
  write("policy-engine/policy/lib/agt_default.rego", "a := cfg.patterns\n");
  return dir;
}

describe("runUpstreamWatch -- the pinned side is read here, not inside the differ", () => {
  afterEach(async () => {
    while (createdDirs.length > 0) {
      await trashDir(createdDirs.pop() as string);
    }
  });

  it("self-skips when either clone is missing", async () => {
    expect((await runUpstreamWatch({})).ran).toBe(false);
    expect((await runUpstreamWatch({ [UPSTREAM_AGT_CLONE_ENV]: clone(["allow"]) })).ran).toBe(false);
  });

  it("reports a clean run when both sides agree", async () => {
    const env = { [PINNED_AGT_CLONE_ENV]: clone(["allow"]), [UPSTREAM_AGT_CLONE_ENV]: clone(["allow"]) };
    const run = await runUpstreamWatch(env);

    expect(run.ran).toBe(true);
    expect(run.diffs).toEqual([]);
    expect(run.output).toContain("no watched surface moved");
  });

  // Two rows, not one: the verdict enum is extracted from
  // verdict.schema.json, a document this watch also reads whole, so a moved
  // enum value is reported once against the document and once against the
  // extracted enum. Eight surfaces are not eight files, and this is what that
  // costs -- the enum row is the one that names the moved value in AGT's own
  // terms, and the document row is the same movement seen from outside.
  it("names a changed enum value, which is the demo", async () => {
    const env = {
      [PINNED_AGT_CLONE_ENV]: clone(["allow", "deny"]),
      [UPSTREAM_AGT_CLONE_ENV]: clone(["allow", "quarantine"]),
    };
    const run = await runUpstreamWatch(env);

    expect(run.diffs).toEqual([
      {
        surface: "verdict.schema.json",
        field: "/properties/decision/enum/1",
        pinned: "deny",
        upstream: "quarantine",
      },
      { surface: "verdict enum", field: "/1", pinned: "deny", upstream: "quarantine" },
    ]);
    expect(run.output).toContain("quarantine");
  });

  // AGT relocating or removing a watched surface is the single loudest thing
  // this watch exists to notice. readSurfaces throws on a missing or moved
  // surface -- correctly, since reporting an absent surface as "unchanged"
  // would be silent rot -- but a thrown error is not a REPORT: the scheduled
  // workflow pipes this run's stdout into the step summary, so an escaping
  // throw publishes an empty summary and leaves the reason in the raw log.
  // So the run must catch it and answer with a report naming what went
  // missing. That the answer also has to reach CI as a non-zero status is a
  // separate question, pinned at the bottom of this file.
  it("reports a failure instead of throwing when a clone is missing an AGT surface", async () => {
    const emptyDir = mkdtempSync(join(tmpdir(), "watch-empty-"));
    createdDirs.push(emptyDir);
    const env = { [PINNED_AGT_CLONE_ENV]: emptyDir, [UPSTREAM_AGT_CLONE_ENV]: clone(["allow"]) };

    const run = await runUpstreamWatch(env);

    expect(run.ran).toBe(false);
    expect(run.output).toContain("manifest.schema.json");
  });

  // The pinned side isn't the only one that can be missing a surface -- main
  // moves, so an AGT release that renames or drops a watched file is a real
  // way for the upstream side to fail the same read. Each side names itself
  // in the failure it reports, so this pins the other half of that pair.
  it("reports a failure instead of throwing when the upstream clone is missing an AGT surface", async () => {
    const emptyDir = mkdtempSync(join(tmpdir(), "watch-empty-"));
    createdDirs.push(emptyDir);
    const env = { [PINNED_AGT_CLONE_ENV]: clone(["allow"]), [UPSTREAM_AGT_CLONE_ENV]: emptyDir };

    const run = await runUpstreamWatch(env);

    expect(run.ran).toBe(false);
    expect(run.output).toContain("could not read main's surfaces");
    expect(run.output).toContain("manifest.schema.json");
  });

  // A read failure and a schema rejection are different answers -- the first
  // means the run itself did not complete, the second means it completed and
  // came back negative -- and this is what tells them apart: a clone that
  // reads fine but whose policy-input.schema.json now requires a field the
  // Guardian does not send. The catch inside runUpstreamWatch turns that
  // rejection into a reported line rather than letting it propagate, and the
  // surface diff above it still has to be there -- a schema failure is not a
  // reason to stop reporting what moved.
  it("reports a schema rejection as a failure line, alongside the surface diff, instead of throwing", async () => {
    const tightened = JSON.stringify({ type: "object", required: ["a_field_agt_does_not_send_today"] });
    const env = {
      [PINNED_AGT_CLONE_ENV]: clone(["allow", "deny"]),
      [UPSTREAM_AGT_CLONE_ENV]: clone(["allow", "quarantine"], tightened),
    };

    const run = await runUpstreamWatch(env);

    expect(run.ran).toBe(true);
    expect(run.schemaAgainstMain.checked).toBe(true);
    expect(run.schemaAgainstMain).toMatchObject({ ok: false });
    expect(run.output).toContain("quarantine");
    expect(run.output).toContain("FAILURE");
    expect(run.output).toContain("policy-input.schema.json");
  });

  // A weekly summary reading "no watched surface moved" cannot be told apart
  // from a run that compared the wrong ref, or the same ref twice, unless
  // the two commits actually compared are in the output themselves.
  it("prints both resolved commit SHAs when the script supplies them", async () => {
    const env = {
      [PINNED_AGT_CLONE_ENV]: clone(["allow"]),
      [UPSTREAM_AGT_CLONE_ENV]: clone(["allow"]),
      [PINNED_AGT_SHA_ENV]: "1111111111111111111111111111111111111111",
      [UPSTREAM_AGT_SHA_ENV]: "2222222222222222222222222222222222222222",
    };

    const run = await runUpstreamWatch(env);

    expect(run.output).toContain("1111111111111111111111111111111111111111");
    expect(run.output).toContain("2222222222222222222222222222222222222222");
  });

  // Every `bun test` run is this case: the script that resolves the two SHAs
  // never runs, so neither variable is set. The output must say so rather
  // than printing an empty value or inventing one.
  it("degrades cleanly, naming neither an empty nor a fake SHA, when the SHAs are not supplied", async () => {
    const env = { [PINNED_AGT_CLONE_ENV]: clone(["allow"]), [UPSTREAM_AGT_CLONE_ENV]: clone(["allow"]) };

    const run = await runUpstreamWatch(env);

    expect(run.output).toContain("Compared refs: not supplied");
    expect(run.output).not.toContain("Compared refs: pinned  against");
  });
});

// A missing file and a malformed file fail this section differently: a
// missing file's own read error happens to name its path, but a YAML parse
// error does not (measured: "YAML Parse error: Unexpected token", no file
// name in it at all) -- so naming the file has to be this section's own job,
// not something it can leave to whichever underlying error it catches.
describe("renderToolsRegistrySection -- a hookmap or the manifest is missing or will not parse", () => {
  afterEach(async () => {
    while (createdDirs.length > 0) {
      await trashDir(createdDirs.pop() as string);
    }
  });

  function tempManifest(): string {
    const dir = mkdtempSync(join(tmpdir(), "tools-registry-manifest-"));
    createdDirs.push(dir);
    const path = join(dir, "manifest.yaml");
    writeFileSync(path, "tools:\n  bash:\n    type: Tool\n");
    return path;
  }

  it("names a hookmap path that names no file, and still reports rather than throwing", () => {
    const missingDir = mkdtempSync(join(tmpdir(), "tools-registry-missing-"));
    createdDirs.push(missingDir);
    const missing = join(missingDir, "no-such.hookmap.yaml");

    let line = "";
    expect(() => {
      line = renderToolsRegistrySection([missing], tempManifest());
    }).not.toThrow();
    expect(line).toContain(missing);
  });

  it("names a hookmap that exists but does not parse as YAML, and still reports rather than throwing", () => {
    const dir = mkdtempSync(join(tmpdir(), "tools-registry-bad-"));
    createdDirs.push(dir);
    const unparseable = join(dir, "broken.hookmap.yaml");
    writeFileSync(unparseable, "hooks: [this is not: valid: yaml");

    let line = "";
    expect(() => {
      line = renderToolsRegistrySection([unparseable], tempManifest());
    }).not.toThrow();
    expect(line).toContain(unparseable);
  });
});

const MODULE = fileURLToPath(new URL("../src/upstream-watch.ts", import.meta.url));
const REPO_ROOT = fileURLToPath(new URL("../../../", import.meta.url));

/**
 * Runs the module the way the scheduled workflow runs it -- as a process,
 * through its `import.meta.main` entry point -- and reports what CI would
 * see.
 *
 * A subprocess necessarily: the entry point's entire product is a process
 * exit status, and there is nothing about it an in-process call to
 * `runUpstreamWatch` can observe. `cwd` is pinned to the repository root
 * rather than inherited, because the tools-against-registry section reads
 * this deployment's own hookmaps and policy manifest by cwd-relative path.
 *
 * Both clone variables are deleted before `overrides` is applied, so the
 * no-clone case gets a genuinely empty pair whether or not the ambient
 * environment happens to have them set.
 */
async function runAsProcess(
  overrides: Record<string, string>,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const env = { ...process.env } as Record<string, string | undefined>;
  delete env[PINNED_AGT_CLONE_ENV];
  delete env[UPSTREAM_AGT_CLONE_ENV];
  const proc = Bun.spawn(["bun", "run", MODULE], {
    cwd: REPO_ROOT,
    env: { ...env, ...overrides } as Record<string, string>,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
  return { exitCode: await proc.exited, stdout, stderr };
}

// Every test above this line reads `ran` off the returned object. CI cannot:
// it sees a process exit status and nothing else. The entry point used to
// print and exit 0 unconditionally, which made "the watcher could not run"
// and "the watcher ran and found no drift" the same answer at the only
// boundary that matters, and left the scheduled job green either way.
//
// Both halves are pinned here, because getting it wrong in the other
// direction would be its own defect: drift that turned the build red would
// be a gate nobody can leave green, and the pressure would be to delete it.
describe("the entry point's exit status -- a run that did not happen must not read as a clean run", () => {
  afterEach(async () => {
    while (createdDirs.length > 0) {
      await trashDir(createdDirs.pop() as string);
    }
  });

  it("exits non-zero when neither clone was supplied, so the watch never ran", async () => {
    const { exitCode, stdout } = await runAsProcess({});

    expect(exitCode).not.toBe(0);
    expect(stdout).toContain("skipped");
  });

  // The other way a run does not happen, and the one that actually threatens
  // upstream: both clones are there, but a watched surface is not where it
  // used to be.
  it("exits non-zero when a clone is present but a watched surface is missing", async () => {
    const emptyDir = mkdtempSync(join(tmpdir(), "watch-empty-"));
    createdDirs.push(emptyDir);

    const { exitCode, stdout } = await runAsProcess({
      [PINNED_AGT_CLONE_ENV]: emptyDir,
      [UPSTREAM_AGT_CLONE_ENV]: clone(["allow"]),
    });

    expect(exitCode).not.toBe(0);
    expect(stdout).toContain("could not read the pinned ref's surfaces");
  });

  it("exits zero when the watch ran and found drift, which is a finding and not a failure", async () => {
    const { exitCode, stdout } = await runAsProcess({
      [PINNED_AGT_CLONE_ENV]: clone(["allow", "deny"]),
      [UPSTREAM_AGT_CLONE_ENV]: clone(["allow", "quarantine"]),
    });

    expect(exitCode).toBe(0);
    expect(stdout).toContain("quarantine");
  });
});
