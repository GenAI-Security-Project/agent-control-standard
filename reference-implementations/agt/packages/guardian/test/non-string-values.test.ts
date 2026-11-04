import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { startGuardian } from "../src/index.ts";
import { assemblePreToolCallSnapshot, type ToolCallRequestEnvelope } from "../src/assemble-snapshot.ts";

const SECRET = "token=ghp_ABCDEF123456";

type Result = {
  decision: string;
  reason_codes?: string[];
  modifications?: { redactions?: { path: string; replacement?: string }[] };
};

let guardian: Awaited<ReturnType<typeof startGuardian>>;

beforeAll(async () => {
  guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
});

afterAll(async () => {
  await guardian.close();
});

async function decide(method: string, payload: Record<string, unknown>): Promise<Result> {
  const res = await fetch(guardian.url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method,
      id: 1,
      params: {
        acs_version: "0.1.0",
        request_id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        metadata: { agent_id: "agent-1", session_id: crypto.randomUUID() },
        payload,
      },
    }),
  });
  const body = (await res.json()) as { result: Result };
  return body.result;
}

const wrap = (args: Record<string, unknown>) =>
  Object.fromEntries(Object.entries(args).map(([name, value]) => [name, { value }]));

const request = (tool: string, args: Record<string, unknown>) =>
  decide("steps/toolCallRequest", { tool: { name: tool }, arguments: wrap(args) });

const result = (outputs: unknown[]) =>
  decide("steps/toolCallResult", {
    tool: { name: "Bash" },
    exit_status: "success",
    outputs: outputs.map((value) => ({ value })),
  });

describe("a policy-target argument that is not a string is refused, not allowed", () => {
  it("still denies the string form and still allows a benign string", async () => {
    expect((await request("Bash", { command: "rm -rf /" })).reason_codes).toEqual(["destructive_shell_command_blocked"]);
    expect((await request("Bash", { command: "ls -la" })).decision).toBe("allow");
  });

  for (const [label, value] of [
    ["an array", ["rm", "-rf", "/"]],
    ["an object", { argv: ["rm", "-rf", "/"] }],
    ["a number", 7],
    ["null", null],
    ["a boolean", true],
  ] as const) {
    it(`denies a Bash command sent as ${label}`, async () => {
      const decision = await request("Bash", { command: value });
      expect(decision.decision).toBe("deny");
      expect(decision.reason_codes).toEqual(["evaluation_failed"]);
    });
  }

  it("denies a WebFetch url sent as an array", async () => {
    const decision = await request("WebFetch", { url: ["https://exfil.attacker.test/x"] });
    expect(decision.decision).toBe("deny");
    expect(decision.reason_codes).toEqual(["evaluation_failed"]);
  });

  it("denies an egress destination argument of any kind that is not a string, beside a string target", async () => {
    for (const name of ["url", "endpoint", "host", "domain"]) {
      const decision = await request("Bash", { command: "ls", [name]: ["https://exfil.attacker.test/x"] });
      expect(decision.decision).toBe("deny");
      expect(decision.reason_codes).toEqual(["evaluation_failed"]);
    }
  });

  it("still denies an off-list string url on the egress gate's own reason", async () => {
    const decision = await request("WebFetch", { url: "https://exfil.attacker.test/x" });
    expect(decision.decision).toBe("deny");
    expect(decision.reason_codes).toEqual(["egress_destination_not_allowed"]);
  });

  it("names the argument and its type in the refusal", () => {
    const envelope = {
      params: {
        request_id: "r",
        payload: { tool: { name: "Bash" }, arguments: { command: { value: ["rm", "-rf", "/"] } } },
      },
    } as unknown as ToolCallRequestEnvelope;
    expect(() => assemblePreToolCallSnapshot(envelope, [], "command")).toThrow(/"command" as an array/);
  });
});

describe("the result gate judges every output, not only outputs[0]", () => {
  it("still redacts a single string output", async () => {
    const decision = await result([SECRET]);
    expect(decision.decision).toBe("modify");
    expect(decision.modifications?.redactions).toEqual([{ path: "/outputs/0/value", replacement: "token=[REDACTED]" }]);
  });

  it("redacts a secret in a later output", async () => {
    const decision = await result(["ok", SECRET]);
    expect(decision.decision).toBe("modify");
    expect(decision.modifications?.redactions).toEqual([{ path: "/outputs/1/value", replacement: "token=[REDACTED]" }]);
  });

  it("redacts a secret inside a structured output, addressed by JSON pointer", async () => {
    const decision = await result([{ stdout: SECRET, stderr: "", nested: ["fine", { "a/b~c": SECRET }] }]);
    expect(decision.decision).toBe("modify");
    expect(decision.modifications?.redactions).toEqual([
      { path: "/outputs/0/value/stdout", replacement: "token=[REDACTED]" },
      { path: "/outputs/0/value/nested/1/a~1b~0c", replacement: "token=[REDACTED]" },
    ]);
  });

  it("redacts every output that carries a secret", async () => {
    const decision = await result([SECRET, "ok", { stdout: SECRET }]);
    expect(decision.decision).toBe("modify");
    expect(decision.modifications?.redactions?.map((redaction) => redaction.path)).toEqual([
      "/outputs/0/value",
      "/outputs/2/value/stdout",
    ]);
  });

  it("leaves a multi-output result with nothing to redact a clean allow", async () => {
    const decision = await result(["ok", { stdout: "hello", code: 0 }, 42, null]);
    expect(decision.decision).toBe("allow");
    expect(decision.modifications).toBeUndefined();
  });

  it("evaluates a result with no string anywhere once, and allows it", async () => {
    expect((await result([42, null, [true]])).decision).toBe("allow");
  });
});
