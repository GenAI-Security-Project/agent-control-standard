import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { loadMapping, startGuardian, type Mapping, type StartedGuardian } from "guardian";
import { checkDenyFailsClosed } from "../src/failure-domains.ts";

const mapping: Mapping = loadMapping("mapping.yaml");

let guardian: StartedGuardian;
beforeAll(async () => {
  guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
});
afterAll(async () => {
  await guardian.close();
});

describe("the two failure domains stay apart", () => {
  it("resolves the deny column expressed, by name, at exactly the six points mapping.yaml gives an ACS method to", async () => {
    // Asserting only "every deny cell that came back is expressed" would
    // pass identically whether the check measured one point or six -- it
    // could not tell a correct six-point measurement apart from an
    // unmeasured one. This asserts exactly which points are covered, by
    // name, matching mapping.yaml's six acs_method-bearing rows
    // (pre_model_call / post_model_call excluded -- the intervention-point
    // check's cell, not this check's).
    const cells = await checkDenyFailsClosed(guardian, mapping);
    const deny = cells.filter((c) => c.verdict === "deny");

    expect(deny.map((c) => c.point).sort()).toEqual([
      "agent_shutdown",
      "agent_startup",
      "input",
      "output",
      "post_tool_call",
      "pre_tool_call",
    ]);
    for (const cell of deny) {
      expect(cell.status).toBe("expressed");
      expect(cell.measuredBy).toContain("deny fails closed");
    }
  });

  it("gets a decision rather than a JSON-RPC error when the envelope cannot be validated", async () => {
    const response = await fetch(guardian.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "rpc-deny-probe",
        method: "steps/toolCallRequest",
        params: {
          acs_version: "0.1.0",
          // A real UUID, not a readable placeholder: request_id is echoed
          // into the deny response's own result.request_id, which
          // response-envelope.json constrains to format "uuid" -- a
          // placeholder would make the response itself fail schema
          // validation and log a console.error unrelated to what this test
          // means to exercise.
          request_id: crypto.randomUUID(),
          metadata: { session_id: "sess-deny-probe" },
          payload: {},
        },
      }),
    });
    const body = (await response.json()) as { result?: { decision?: string }; error?: unknown };

    expect(body.error).toBeUndefined();
    expect(body.result?.decision).toBe("deny");
  });
});
