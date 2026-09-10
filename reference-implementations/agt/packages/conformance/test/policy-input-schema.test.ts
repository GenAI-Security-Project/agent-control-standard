import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AgtEvidence, EvidenceBridge } from "agt-bridge";
import { checkPolicyInputSchema, PINNED_AGT_CLONE_ENV } from "../src/policy-input-schema.ts";

/** trash the fixture directory this describe block builds -- never rm -rf. */
async function trashDir(dir: string): Promise<void> {
  await Bun.$`trash ${dir}`.quiet();
}

/** This check depends on `EvidenceBridge` alone, so the stand-in implements
 * that one message and nothing else. */
const evidenceFor = (policyInput: unknown): EvidenceBridge => ({
  async evaluateWithEvidence(): Promise<AgtEvidence> {
    return {
      verdict: { decision: "allow" },
      policyInput,
      inputIdentity: `sha256:${"0".repeat(64)}`,
      enforcedIdentity: `sha256:${"0".repeat(64)}`,
    };
  },
});

describe("the schema leg -- self-skips without the clone, validates against it when present", () => {
  const originalEnv = process.env[PINNED_AGT_CLONE_ENV];
  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env[PINNED_AGT_CLONE_ENV];
    } else {
      process.env[PINNED_AGT_CLONE_ENV] = originalEnv;
    }
  });

  it(`does not run when ${PINNED_AGT_CLONE_ENV} is unset, and says so`, async () => {
    delete process.env[PINNED_AGT_CLONE_ENV];

    const result = await checkPolicyInputSchema(evidenceFor({ marker: "ok" }));

    expect(result.ran).toBe(false);
    if (!result.ran) {
      expect(result.reason).toContain(PINNED_AGT_CLONE_ENV);
    }
  });

  describe("with a fixture clone standing in for the pinned AGT repo", () => {
    // A throwaway fixture schema, not a copy of AGT's real one -- this
    // describe block tests that the module reads the schema file at the
    // right path inside the clone and reports Ajv's own verdict on it
    // accurately, not that AGT's real contract has any particular shape.
    let clone: string;
    beforeEach(() => {
      clone = mkdtempSync(join(tmpdir(), "policy-input-schema-fixture-"));
      const schemaDir = join(clone, "policy-engine/spec/schema/wire");
      mkdirSync(schemaDir, { recursive: true });
      writeFileSync(
        join(schemaDir, "policy-input.schema.json"),
        JSON.stringify({
          $schema: "https://json-schema.org/draft/2020-12/schema",
          type: "object",
          required: ["marker"],
          properties: { marker: { const: "ok" } },
        }),
      );
      process.env[PINNED_AGT_CLONE_ENV] = clone;
    });
    afterEach(async () => {
      await trashDir(clone);
    });

    it("reports both probe points as validated", async () => {
      const result = await checkPolicyInputSchema(evidenceFor({ marker: "ok" }));

      expect(result.ran).toBe(true);
      if (result.ran) {
        expect(result.points.sort()).toEqual(["post_tool_call", "pre_tool_call"]);
      }
    });

    it("throws, naming the point and AGT's own schema, when a constructed policy input fails validation", async () => {
      await expect(checkPolicyInputSchema(evidenceFor({ marker: "not ok" }))).rejects.toThrow(
        /pre_tool_call.*policy-input\.schema\.json/s,
      );
    });
  });
});
