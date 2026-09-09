// packages/conformance/test/surfaces.test.ts
import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { readSurfaces, asPinned, asUpstream, SURFACE_NAMES } from "../src/surfaces.ts";

const createdDirs: string[] = [];

/** trash every fixture directory this file's tests create -- never rm -rf. */
async function trashDir(dir: string): Promise<void> {
  await Bun.$`trash ${dir}`.quiet();
}

function fakeClone(): string {
  const dir = mkdtempSync(join(tmpdir(), "surfaces-"));
  createdDirs.push(dir);
  const write = (rel: string, body: string) => {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, body);
  };
  write(
    "policy-engine/spec/schema/manifest.schema.json",
    JSON.stringify({ properties: { intervention_points: { propertyNames: { enum: ["pre_tool_call", "output"] } } } }),
  );
  write("policy-engine/spec/schema/wire/policy-input.schema.json", JSON.stringify({ title: "policy input" }));
  write("policy-engine/spec/schema/wire/verdict.schema.json", JSON.stringify({ properties: { decision: { enum: ["allow", "deny"] } } }));
  write("policy-engine/spec/schema/wire/snapshot.schema.json", JSON.stringify({ title: "snapshot" }));
  write("policy-engine/spec/reserved-reasons.json", JSON.stringify({ reasons: ["tool_unknown"] }));
  write("policy-engine/policy/lib/agt_default.rego", "x := cfg.drift.warn_threshold\ny := cfg.patterns\nz := cfg.drift.warn_threshold\n");
  return dir;
}

describe("readSurfaces -- the eight declared surfaces, and nothing else", () => {
  afterEach(async () => {
    while (createdDirs.length > 0) {
      await trashDir(createdDirs.pop() as string);
    }
  });

  it("names exactly eight surfaces", () => {
    expect(SURFACE_NAMES).toHaveLength(8);
  });

  it("reads the four wire documents whole", () => {
    const s = readSurfaces(fakeClone());
    expect(s["policy-input.schema.json"]).toEqual({ title: "policy input" });
    expect(s["snapshot.schema.json"]).toEqual({ title: "snapshot" });
  });

  it("extracts the intervention-point enum from inside manifest.schema.json", () => {
    expect(readSurfaces(fakeClone())["intervention-point enum"]).toEqual(["pre_tool_call", "output"]);
  });

  it("extracts the verdict enum from inside verdict.schema.json", () => {
    expect(readSurfaces(fakeClone())["verdict enum"]).toEqual(["allow", "deny"]);
  });

  it("derives the defaults config keys from the rego source, deduped and sorted", () => {
    expect(readSurfaces(fakeClone())["data.agt.defaults.config keys"]).toEqual(["drift.warn_threshold", "patterns"]);
  });

  it("throws when a surface is missing rather than reporting it as empty", () => {
    const dir = mkdtempSync(join(tmpdir(), "surfaces-empty-"));
    createdDirs.push(dir);
    expect(() => readSurfaces(dir)).toThrow(/manifest.schema.json/);
  });

  it("brands a snapshot as pinned or upstream without changing it", () => {
    const s = readSurfaces(fakeClone());
    expect(s).toEqual(asPinned(s));
    expect(s).toEqual(asUpstream(s));
  });

  // The identical defect this repository already reasoned about and closed
  // for a malformed hookmap (`readHookmapTools`, upstream-watch.ts): a read
  // failure and a parse failure must both name the surface, so a malformed
  // watched document is answerable rather than an anonymous JSON.parse error
  // with no way to tell which of the five JSON surfaces it came from.
  it("names the surface, not just an anonymous parse error, when a watched document exists but does not parse", () => {
    const dir = mkdtempSync(join(tmpdir(), "surfaces-malformed-"));
    createdDirs.push(dir);
    const write = (rel: string, body: string) => {
      const full = join(dir, rel);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, body);
    };
    write("policy-engine/spec/schema/manifest.schema.json", JSON.stringify({ properties: { intervention_points: { propertyNames: { enum: ["input"] } } } }));
    write("policy-engine/spec/schema/wire/policy-input.schema.json", "{}");
    write("policy-engine/spec/schema/wire/verdict.schema.json", "{ not valid json");
    write("policy-engine/spec/schema/wire/snapshot.schema.json", "{}");
    write("policy-engine/spec/reserved-reasons.json", "{}");
    write("policy-engine/policy/lib/agt_default.rego", "a := cfg.patterns\n");

    expect(() => readSurfaces(dir)).toThrow(/verdict\.schema\.json/);
  });
});
