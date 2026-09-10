import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fetchUpstreamSurfaces, UPSTREAM_AGT_CLONE_ENV } from "../src/fetch-upstream.ts";

const createdDirs: string[] = [];

/** trash every fixture directory this file's tests create -- never rm -rf. */
async function trashDir(dir: string): Promise<void> {
  await Bun.$`trash ${dir}`.quiet();
}

function fakeClone(): string {
  const dir = mkdtempSync(join(tmpdir(), "upstream-"));
  createdDirs.push(dir);
  const write = (rel: string, body: string) => {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, body);
  };
  write("policy-engine/spec/schema/manifest.schema.json", JSON.stringify({ properties: { intervention_points: { propertyNames: { enum: ["input"] } } } }));
  write("policy-engine/spec/schema/wire/policy-input.schema.json", "{}");
  write("policy-engine/spec/schema/wire/verdict.schema.json", JSON.stringify({ properties: { decision: { enum: ["allow"] } } }));
  write("policy-engine/spec/schema/wire/snapshot.schema.json", "{}");
  write("policy-engine/spec/reserved-reasons.json", "{}");
  write("policy-engine/policy/lib/agt_default.rego", "a := cfg.patterns\n");
  return dir;
}

describe("fetchUpstreamSurfaces -- reads the clone the script made, never the network", () => {
  afterEach(async () => {
    while (createdDirs.length > 0) {
      await trashDir(createdDirs.pop() as string);
    }
  });

  it("self-skips when the upstream clone variable is unset, exactly as the schema leg does", () => {
    expect(fetchUpstreamSurfaces({})).toBeUndefined();
  });

  it("reads the eight surfaces out of the clone the variable names", () => {
    const surfaces = fetchUpstreamSurfaces({ [UPSTREAM_AGT_CLONE_ENV]: fakeClone() });
    expect(surfaces?.["verdict enum"]).toEqual(["allow"]);
  });

  it("names its own variable, never the pinned one", () => {
    expect(UPSTREAM_AGT_CLONE_ENV).toBe("UPSTREAM_AGT_CLONE");
  });

  it("throws rather than self-skipping when the variable names a directory with no AGT in it", () => {
    const empty = mkdtempSync(join(tmpdir(), "upstream-empty-"));
    createdDirs.push(empty);
    expect(() => fetchUpstreamSurfaces({ [UPSTREAM_AGT_CLONE_ENV]: empty })).toThrow(/manifest.schema.json/);
  });
});
