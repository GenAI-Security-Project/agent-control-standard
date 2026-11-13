import { describe, expect, it } from "bun:test";
import { unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { startGuardian, type Mapping } from "../src/index.ts";
import { loadMapping } from "../src/map-verdict.ts";
import type { AcsFinalResult } from "../src/acs-result.ts";

const FIXTURES = fileURLToPath(new URL("./fixtures/", import.meta.url));
type Target = Mapping["intervention_points"][string]["policy_target_argument"];
const configurations: { name: string; target: Target }[] = [
  { name: "null default", target: { default: null } },
  { name: "absent table", target: undefined },
  { name: "unlisted tool and no default", target: { by_tool: { Bash: "command" } } },
  { name: "null per-tool override", target: { default: "command", by_tool: { list_reservations: null } } },
];

async function withGuardian(
  target: Target,
  policy: "allow" | "transform",
  body: (url: string) => Promise<void>,
): Promise<void> {
  const mapping = loadMapping("mapping.yaml");
  if (target === undefined) {
    delete mapping.intervention_points.pre_tool_call!.policy_target_argument;
  } else {
    mapping.intervention_points.pre_tool_call!.policy_target_argument = target;
  }
  const mappingPath = join(FIXTURES, `mapping.no-arg-${crypto.randomUUID()}.yaml`);
  writeFileSync(mappingPath, Bun.YAML.stringify(mapping));
  let guardian: Awaited<ReturnType<typeof startGuardian>> | undefined;
  try {
    guardian = await startGuardian({
      port: 0,
      manifestPath: join(FIXTURES, `manifest.no-arg-${policy}.yaml`),
      mappingPath,
    });
    await body(guardian.url);
  } finally {
    await guardian?.close();
    unlinkSync(mappingPath);
  }
}

async function callTool(url: string, name = "list_reservations"): Promise<AcsFinalResult> {
  const requestId = crypto.randomUUID();
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "steps/toolCallRequest",
      params: {
        acs_version: "0.1.0",
        request_id: requestId,
        timestamp: new Date().toISOString(),
        metadata: { agent_id: "agent-1", session_id: crypto.randomUUID() },
        payload: { tool: { name }, arguments: {} },
      },
    }),
  });
  const result = await response.json() as { id: number; error?: unknown; result: AcsFinalResult };
  expect(result.error).toBeUndefined();
  expect(result.id).toBe(1);
  expect(result.result.request_id).toBe(requestId);
  return result.result;
}

describe("tools without a mapped target argument (real AGT policy)", () => {
  for (const { name, target } of configurations) {
    it(`evaluates and allows list_reservations with ${name}`, async () => {
      await withGuardian(target, "allow", async (url) => {
        const result = await callTool(url);
        expect(result.decision).toBe("allow");
        expect(result.reason_codes).toEqual(["tool_name_allowed"]);
        expect(result.modifications).toBeUndefined();
      });
    });

    it(`denies a target rewrite with ${name}`, async () => {
      await withGuardian(target, "transform", async (url) => {
        const result = await callTool(url);
        expect(result.decision).toBe("deny");
        expect(result.reason_codes).toEqual(["evaluation_failed"]);
        expect(result.reasoning).toContain("no argument for the rewrite");
        expect(result.modifications).toBeUndefined();
      });
    });
  }

  it("still honors a policy denial based on the tool name", async () => {
    await withGuardian({ default: null }, "allow", async (url) => {
      const result = await callTool(url, "delete_reservations");
      expect(result.decision).toBe("deny");
      expect(result.reason_codes).toEqual(["tool_name_denied"]);
    });
  });
});
