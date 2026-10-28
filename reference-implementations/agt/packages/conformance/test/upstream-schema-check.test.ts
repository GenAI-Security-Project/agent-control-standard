// packages/conformance/test/upstream-schema-check.test.ts
import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve, sep } from "node:path";
import { checkPolicyInputSchemaAt } from "../src/policy-input-schema.ts";
// The deployment subpath, not the barrel: the barrel is the governance verbs,
// and this is how the deployment builds a bridge. Same as src/main.ts and
// src/upstream-watch.ts -- the document this leg validates is only the shipped
// deployment's document if the bridge is the shipped one.
import { createDeploymentBridge } from "guardian/deployment";

const SCHEMA_REL = "policy-engine/spec/schema/wire/policy-input.schema.json";

const createdDirs: string[] = [];

/** trash every fixture directory this file's tests create, falling back to
 * tmpdir-scoped rmSync when the external trash binary is absent (#73). */
async function trashDir(dir: string): Promise<void> {
  if (Bun.which("trash") !== null) {
    await Bun.$`trash ${dir}`.quiet();
    return;
  }
  const root = resolve(tmpdir());
  const target = resolve(dir);
  if (!target.startsWith(`${root}${sep}`)) {
    throw new Error(`refusing to remove path outside tmpdir(): ${target}`);
  }
  rmSync(target, { recursive: true, force: true });
}

function cloneWithSchema(schema: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "upstream-schema-"));
  createdDirs.push(dir);
  const full = join(dir, SCHEMA_REL);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, JSON.stringify(schema));
  return dir;
}

describe("checkPolicyInputSchemaAt -- the document we send, against the schema at a given clone", () => {
  afterEach(async () => {
    while (createdDirs.length > 0) {
      await trashDir(createdDirs.pop() as string);
    }
  });

  it("validates against a permissive schema", async () => {
    const bridge = createDeploymentBridge("policy/manifest.yaml");
    const result = await checkPolicyInputSchemaAt(bridge, cloneWithSchema({ type: "object" }));

    expect(result.ran).toBe(true);
  });

  it("reports a FAILURE, not a skip, when the schema at that clone rejects what we send", async () => {
    const bridge = createDeploymentBridge("policy/manifest.yaml");
    const tightened = { type: "object", required: ["a_field_agt_does_not_send_today"] };

    await expect(checkPolicyInputSchemaAt(bridge, cloneWithSchema(tightened))).rejects.toThrow(
      /policy-input\.schema\.json/,
    );
  });
});
