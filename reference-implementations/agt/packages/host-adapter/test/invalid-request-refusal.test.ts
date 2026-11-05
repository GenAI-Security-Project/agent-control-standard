import { afterAll, beforeAll, describe, expect, it } from "bun:test";
// Test-only import, the same arrangement as client.test.ts: a real Guardian
// mints the code, so this fails if the Guardian and the host stop agreeing.
import { startGuardian, type StartedGuardian } from "guardian";
import { applyFailurePosture, classifyDeliveryFailure } from "../src/failure-posture.ts";

// In its own file because PR #229 replaces the refusal set, and a rebase that
// takes its side of the conflict loses -32600 with no failing test.
describe("a real Guardian's -32600 blocks the step under proceed (#130, #163)", () => {
  let guardian: StartedGuardian;

  beforeAll(async () => {
    guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
  });

  afterAll(async () => {
    await guardian.close();
  });

  it.each([
    ["a batch", [{ jsonrpc: "2.0", id: 1, method: "steps/toolCallRequest", params: {} }]],
    ["a wrong jsonrpc version", { jsonrpc: "1.0", id: 1, method: "steps/toolCallRequest", params: {} }],
  ])("%s", async (_label, body) => {
    const res = await fetch(guardian.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const { error } = (await res.json()) as { error: { code: number; message: string } };

    expect(error.code).toBe(-32600);
    expect(classifyDeliveryFailure(error).kind).toBe("refused");
    expect(
      applyFailurePosture({
        failure: error,
        session: {
          config: {
            negotiated_version: "0.1.0",
            methods_evaluated: ["steps/toolCallRequest"],
            selected_transport: "http",
            timeout_config: { default_ms: 5000 },
            on_decision_failure: "proceed",
          },
          failure: undefined,
        },
        sessionId: "sess-1",
        method: "steps/toolCallRequest",
        rpcId: "req-1",
        audit: { path: "test", write: () => true },
      }).decision,
    ).toBe("deny");
  });
});
