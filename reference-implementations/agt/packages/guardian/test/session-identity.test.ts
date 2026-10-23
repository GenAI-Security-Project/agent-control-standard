import { describe, expect, it } from "bun:test";
import { startGuardian, createMemorySessionContextStore, loadSessionContext } from "../src/index.ts";
import { sessionIdentityDigest } from "../src/session-identity.ts";
import type { AcsRequestParams } from "../src/validate-envelope.ts";

// Regression coverage for issue #166.
// A controlled policy bridge isolates session handling from policy decisions.
describe("session identity binding over loopback HTTP", () => {
  for (const method of ["steps/toolCallRequest", "steps/toolCallResult"]) {
  for (const scenario of ["same-agent", "different-agent", "changed-user", "changed-roles", "changed-auth", "changed-tenant", "separate-session"] as const) {
    it(`${method}: ${scenario}`, async () => {
      const store = createMemorySessionContextStore();
      let evaluations = 0;
      const guardian = await startGuardian({
        port: 0, manifestPath: "policy/manifest.yaml", sessionContextStore: store,
        bridge: { async evaluate() { evaluations++; return { decision: "allow" }; } },
      });
      const session = crypto.randomUUID();
      const otherSession = scenario === "separate-session" ? crypto.randomUUID() : session;
      const ids: string[] = [];
      async function send(agent: string, sid: string, user: string, expected: "allow" | "deny" = "allow") {
        const requestId = crypto.randomUUID();
        ids.push(requestId);
        const response = await fetch(guardian.url, {
          method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: ids.length, method,
            params: { acs_version: "0.1.0", request_id: requestId, timestamp: new Date().toISOString(),
              tenant_id: ids.length === 2 && scenario === "changed-tenant" ? "other" : "tenant-a",
              metadata: { agent_id: agent, session_id: sid,
                user_context: { user_id: user, roles: ids.length === 2 && scenario === "changed-roles" ? ["admin"] : ["reader"], authentication_method: ids.length === 2 && scenario === "changed-auth" ? "other" : "test" } },
              payload: method === "steps/toolCallResult"
                ? { tool: { name: "run_shell" }, exit_status: "success", outputs: [{ value: "synthetic" }] }
                : { tool: { name: "run_shell" }, arguments: { command: { value: "echo synthetic" } } },
            },
          }),
        });
        expect(response.status).toBe(200);
        const body = await response.json() as { result?: { decision?: string } };
        expect(body.result?.decision).toBe(expected);
      }
      try {
        await send("agent-a", session, "user-a");
        await send(scenario === "different-agent" ? "agent-b" : "agent-a", otherSession,
          scenario === "changed-user" ? "user-b" : "user-a",
          scenario === "same-agent" || scenario === "separate-session" ? "allow" : "deny");
        const rejected = scenario !== "same-agent" && scenario !== "separate-session";
        expect(evaluations).toBe(rejected ? 1 : 2);
        const original = loadSessionContext(store, session).entries;
        expect(original.map(e => e.request_id)).toEqual(scenario === "separate-session" || rejected ? [ids[0]!] : ids);
        if (scenario === "separate-session") {
          expect(loadSessionContext(store, otherSession).entries.map(e => e.request_id)).toEqual([ids[1]!]);
        } else if (!rejected) {
          expect(original[1]!.prev_hash).toBe(original[0]!.hash);
        }
      } finally { await guardian.close(); }
    });
  }
  }
});

describe("identity binding lifetime", () => {
  it("survives audit-chain eviction and fails closed at identity capacity", () => {
    const store = createMemorySessionContextStore({ maxSessions: 1, maxIdentityBindings: 2, onEvict() {} });
    store.bindIdentity("a", "identity-a");
    store.append("a", { method: "steps/toolCallRequest", request_id: "a", tool_name: "x" });
    store.bindIdentity("b", "identity-b");
    store.append("b", { method: "steps/toolCallRequest", request_id: "b", tool_name: "x" });
    expect(store.context("a").entries).toHaveLength(0);
    expect(() => store.bindIdentity("a", "other")).toThrow("does not match");
    expect(() => store.bindIdentity("c", "identity-c")).toThrow("store is full");
    expect(() => store.bindIdentity("a", "identity-a")).not.toThrow();
  });

  it("refuses to adopt pre-existing state with an unknown identity", () => {
    const store = createMemorySessionContextStore();
    store.append("a", { method: "steps/toolCallRequest", request_id: "a", tool_name: "x" });
    expect(() => store.bindIdentity("a", "identity-a")).toThrow("no identity binding");
  });

  it("normalizes role sets while retaining identity absence", () => {
    const params = { metadata: { agent_id: "a", session_id: "s", user_context: { roles: ["b", "a", "a"] } } } as AcsRequestParams;
    const digest = sessionIdentityDigest(params);
    params.metadata.user_context!.roles = ["a", "b"];
    expect(sessionIdentityDigest(params)).toBe(digest);
    params.metadata.user_context!.user_id = "";
    expect(sessionIdentityDigest(params)).not.toBe(digest);
  });

  it("rejects a competing identity while the first evaluation awaits", async () => {
    const store = createMemorySessionContextStore();
    let entered!: () => void;
    let release!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const pending = new Promise<void>(resolve => { release = resolve; });
    let evaluations = 0;
    const guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml", sessionContextStore: store,
      bridge: { async evaluate() { evaluations++; entered(); await pending; return { decision: "allow" }; } },
    });
    const session = crypto.randomUUID();
    const send = (agent: string, method = "steps/toolCallRequest") => fetch(guardian.url, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: agent, method, params: {
        acs_version: "0.1.0", request_id: crypto.randomUUID(), timestamp: new Date().toISOString(),
        metadata: { agent_id: agent, session_id: session },
        payload: method === "handshake/hello" ? {} : { tool: { name: "run_shell" }, arguments: { command: { value: "echo synthetic" } } },
      } }),
    }).then(response => response.json()) as Promise<any>;
    try {
      expect((await send("a", "handshake/hello")).result).toBeDefined();
      const first = send("a");
      await started;
      const competing = await send("b");
      expect(competing.result.reason_codes).toEqual(["session_identity_mismatch"]);
      expect((await send("b", "handshake/hello")).error).toBeDefined();
      expect(evaluations).toBe(1);
      expect(store.context(session).entries).toHaveLength(1);
      release();
      expect((await first).result.decision).toBe("allow");
    } finally { release(); await guardian.close(); }
  });
});
