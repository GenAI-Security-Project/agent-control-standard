import { describe, expect, it } from "bun:test";
import type { PolicyBridge } from "agt-bridge";
import { startGuardian, type GuardianSnapshot } from "../src/index.ts";
import { toolCallEnvelope } from "./helpers/envelopes.ts";

/** Behaves like AGT's IFC gate: returns the labels it was given, plus
 * `secret` for a step that reads secret data. A `slow` step holds the
 * evaluation open, which is where two steps could overlap. */
function ifcLikeBridge(seen: string[][]): PolicyBridge<GuardianSnapshot> {
  return {
    async evaluate(_point, snapshot) {
      const input = [...((snapshot as { input?: { ifc?: { source_labels?: string[] } } }).input?.ifc?.source_labels ?? [])];
      const text = JSON.stringify(snapshot);
      seen.push(input);
      if (text.includes("slow")) await Bun.sleep(200);
      const labels = text.includes("read-secret") ? [...new Set([...input, "secret"])] : input;
      return { decision: "allow", result_labels: labels };
    },
  } as PolicyBridge<GuardianSnapshot>;
}

async function post(url: string, body: unknown): Promise<unknown> {
  const response = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return response.json();
}

describe("steps in one session (#310)", () => {
  it("keeps a label a concurrent step added", async () => {
    const seen: string[][] = [];
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml", bridge: ifcLikeBridge(seen) });
    try {
      const sessionId = crypto.randomUUID();
      const slow = post(guardian.url, toolCallEnvelope("echo slow", { id: 1, sessionId }));
      await Bun.sleep(50);
      await post(guardian.url, toolCallEnvelope("cat read-secret", { id: 2, sessionId }));
      await slow;
      await post(guardian.url, toolCallEnvelope("echo after", { id: 3, sessionId }));

      expect(seen.at(-1)).toContain("secret");
    } finally {
      await guardian.close();
    }
  });

  it("does not hold one session's step behind another session's", async () => {
    const seen: string[][] = [];
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml", bridge: ifcLikeBridge(seen) });
    try {
      const order: string[] = [];
      const slow = post(guardian.url, toolCallEnvelope("echo slow", { id: 1, sessionId: crypto.randomUUID() })).then(() => order.push("slow"));
      await Bun.sleep(50);
      await post(guardian.url, toolCallEnvelope("echo fast", { id: 2, sessionId: crypto.randomUUID() })).then(() => order.push("fast"));
      await slow;

      expect(order).toEqual(["fast", "slow"]);
    } finally {
      await guardian.close();
    }
  });
});
