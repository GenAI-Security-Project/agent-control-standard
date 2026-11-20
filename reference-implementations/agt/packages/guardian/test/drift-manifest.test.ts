import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { startGuardian } from "../src/index.ts";
import { toolCallEnvelope } from "./helpers/envelopes.ts";

// The README and the header of policy/manifest.drift.yaml say this manifest
// does not reach `warn` today. These tests are what keeps that true. Whoever
// gives the Guardian a `drift_score` annotator and sets a threshold in
// policy/lib/data.json fails here first, and updates both texts with it.

async function decide(manifestPath: string, command: string): Promise<Record<string, unknown>> {
  const guardian = await startGuardian({ port: 0, manifestPath });
  try {
    const res = await fetch(guardian.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(toolCallEnvelope(command)),
    });
    const body = (await res.json()) as { result?: Record<string, unknown> };
    return body.result as Record<string, unknown>;
  } finally {
    await guardian.close();
  }
}

describe("policy/manifest.drift.yaml with this Guardian", () => {
  it("denies every call on annotation_failed, a benign one and a destructive one alike", async () => {
    for (const command of ["ls", "rm -rf /"]) {
      const decision = await decide("policy/manifest.drift.yaml", command);
      expect(decision.decision).toBe("deny");
      expect(decision.reason_codes).toEqual(["runtime_error:annotation_failed"]);
    }
  });

  it("is the manifest that does it: the shipped manifest allows the same benign call", async () => {
    const decision = await decide("policy/manifest.yaml", "ls");
    expect(decision.decision).toBe("allow");
  });

  it("has no drift threshold in policy/lib/data.json, so a score alone would not warn", () => {
    const data = JSON.parse(readFileSync(new URL("../../../policy/lib/data.json", import.meta.url), "utf8")) as {
      agt: { defaults: { config: Record<string, unknown> } };
    };
    expect(data.agt.defaults.config.drift).toBeUndefined();
  });
});
