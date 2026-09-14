import { afterAll, beforeAll, describe, expect, it } from "bun:test";
// Test-only import: stands up a real Guardian so these tests prove the
// wire contract for real, not against a hand-copied shape. Never imported
// by packages/host-adapter/src, which must not depend on the Guardian --
// see build-envelope.test.ts for the same arrangement.
import { startGuardian, type StartedGuardian } from "guardian";
import type { AuditEvent } from "../src/audit-sink.ts";
import { buildEnvelope, loadHookmap, type Hookmap } from "../src/build-envelope.ts";
import { applyFailurePosture, classifyDeliveryFailure } from "../src/failure-posture.ts";
import {
  createGuardianClient,
  GuardianResponseMismatchError,
  GuardianResultCorrelationError,
  GuardianTimeoutError,
} from "../src/guardian-client.ts";
import {
  negotiateSessionConfig,
  resolveSessionConfig,
  ServerHelloInvalidError,
  SessionConfigNotStoredError,
} from "../src/handshake.ts";
import { renderDecision } from "../src/render-decision.ts";
import { createMemorySessionConfigStore } from "../src/session-config.ts";

const hookmap: Hookmap = loadHookmap("hosts/claude-code/claude-code.hookmap.yaml");

function preToolUsePayload(command: string): Record<string, unknown> {
  return {
    session_id: "abc123",
    transcript_path: "/path/to/transcript.jsonl",
    cwd: "/current/dir",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command },
  };
}

let guardian: StartedGuardian;

beforeAll(async () => {
  guardian = await startGuardian({ port: 0, manifestPath: "policy/manifest.yaml" });
});

afterAll(async () => {
  await guardian.close();
});

describe("GuardianClient.post", () => {
  it("posts the envelope as well-formed JSON-RPC 2.0 (jsonrpc, method, id, params) over HTTP", async () => {
    let capturedBody: Record<string, unknown> | undefined;
    let capturedContentType: string | null = null;
    const mock = Bun.serve({
      port: 0,
      async fetch(req) {
        capturedContentType = req.headers.get("content-type");
        capturedBody = (await req.json()) as Record<string, unknown>;
        return Response.json({ jsonrpc: "2.0", id: (capturedBody as { id: unknown }).id, result: { decision: "allow" } });
      },
    });

    try {
      const envelope = buildEnvelope("PreToolUse", preToolUsePayload("ls -la"), hookmap);
      const response = await createGuardianClient(`http://localhost:${mock.port}/acs`).post(envelope);

      expect(capturedBody).toEqual(envelope as unknown as Record<string, unknown>);
      if (capturedContentType === null) {
        throw new Error("mock server captured no content-type header");
      }
      // Rebind to a plain (non-closure-mutated) const: `capturedContentType`
      // is reassigned inside the fetch handler above, and TS's generic
      // inference for expect<T>() doesn't pick up the flow-narrowing on a
      // variable a closure can still write to, even though the narrowing
      // itself is sound here (the closure has already run by this point).
      const contentType: string = capturedContentType;
      expect(contentType).toContain("application/json");
      expect(response.result?.decision).toBe("allow");
    } finally {
      mock.stop(true);
    }
  });

  it("correlates the response to the request by JSON-RPC id -- buildEnvelope's id equals params.request_id, and that round-trips fine", async () => {
    const envelope = buildEnvelope("PreToolUse", preToolUsePayload("ls -la"), hookmap);

    const response = await createGuardianClient(guardian.url).post(envelope);

    expect(response.id).toBe(envelope.id);
    expect(envelope.id).toBe(envelope.params.request_id);
  });

  it("throws when the response id does not correlate with the request id", async () => {
    const mock = Bun.serve({
      port: 0,
      fetch() {
        return Response.json({ jsonrpc: "2.0", id: "not-the-request-id", result: { decision: "allow" } });
      },
    });

    try {
      const envelope = buildEnvelope("PreToolUse", preToolUsePayload("ls -la"), hookmap);
      await expect(createGuardianClient(`http://localhost:${mock.port}/acs`).post(envelope)).rejects.toThrow();
    } finally {
      mock.stop(true);
    }
  });

  it("throws when the transport id correlates but result.request_id names another request", async () => {
    // The one a transport-only check cannot catch: `id` is echoed faithfully,
    // so `fetch`'s own pairing and the JSON-RPC id check both pass, and what
    // comes back is a real, well-formed decision -- about a different step.
    // Answering this tool call with it is answering a question nobody asked.
    const mock = Bun.serve({
      port: 0,
      async fetch(req) {
        const body = (await req.json()) as { id: string | number };
        return Response.json({
          jsonrpc: "2.0",
          id: body.id,
          result: { decision: "allow", request_id: crypto.randomUUID() },
        });
      },
    });

    try {
      const envelope = buildEnvelope("PreToolUse", preToolUsePayload("rm -rf /"), hookmap);
      await expect(createGuardianClient(`http://localhost:${mock.port}/acs`).post(envelope)).rejects.toThrow(
        GuardianResultCorrelationError,
      );
    } finally {
      mock.stop(true);
    }
  });

  // The one response whose id can never correlate is also the only one that
  // says why the Guardian would not read the envelope. Throwing on it replaced
  // the refusal code with a mismatch error -- which classifies as a plain
  // delivery failure, so a `-32700` could never reach the classifier at all,
  // and under the shipped default posture the step ran.
  it("returns an error the Guardian could not address (id: null) instead of failing correlation on it", async () => {
    const mock = Bun.serve({
      port: 0,
      fetch() {
        return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
      },
    });

    try {
      const envelope = buildEnvelope("PreToolUse", preToolUsePayload("ls -la"), hookmap);
      const response = await createGuardianClient(`http://localhost:${mock.port}/acs`).post(envelope);
      expect(response.error?.code).toBe(-32700);
    } finally {
      mock.stop(true);
    }
  });

  // The exemption is for an error, not for a null id. A null id on a RESULT is
  // a Guardian answering a decision it cannot say whose it is -- the exact
  // case the correlation check exists for -- and widening the branch to every
  // null id would let that through as an honoured decision.
  it("still throws on a null id carrying a result, which is a real correlation failure", async () => {
    const mock = Bun.serve({
      port: 0,
      fetch() {
        return Response.json({ jsonrpc: "2.0", id: null, result: { decision: "allow" } });
      },
    });

    try {
      const envelope = buildEnvelope("PreToolUse", preToolUsePayload("ls -la"), hookmap);
      await expect(createGuardianClient(`http://localhost:${mock.port}/acs`).post(envelope)).rejects.toThrow(
        GuardianResponseMismatchError,
      );
    } finally {
      mock.stop(true);
    }
  });

  it("leaves a ServerHello alone -- a result carrying no request_id is not an uncorrelated one", async () => {
    // The check must not fire on the handshake, whose result is a ServerHello
    // and has no request_id at all: `undefined` there means "this result is
    // not about a step", not "this result is about someone else's step".
    const mock = Bun.serve({
      port: 0,
      async fetch(req) {
        const body = (await req.json()) as { id: string | number };
        return Response.json({ jsonrpc: "2.0", id: body.id, result: { negotiated_version: "0.1.0" } });
      },
    });

    try {
      const envelope = buildEnvelope("PreToolUse", preToolUsePayload("ls -la"), hookmap);
      const response = await createGuardianClient(`http://localhost:${mock.port}/acs`).post(envelope);

      expect(response.result?.negotiated_version).toBe("0.1.0");
    } finally {
      mock.stop(true);
    }
  });

  it("against a real Guardian: steps/toolCallRequest for ls -la allows, echoing the request id", async () => {
    const envelope = buildEnvelope("PreToolUse", preToolUsePayload("ls -la"), hookmap);

    const response = await createGuardianClient(guardian.url).post(envelope);

    expect(response.error).toBeUndefined();
    expect(response.result?.decision).toBe("allow");
  });
});

// requestDecision owns every branch a shim would otherwise have to work out
// for itself by inspecting a raw JSON-RPC response -- and the last of them
// is the one a copy of that inspection would get wrong.
describe("GuardianClient.requestDecision", () => {
  it("answers with the decision when one arrives", async () => {
    const envelope = buildEnvelope("PreToolUse", preToolUsePayload("ls -la"), hookmap);

    const outcome = await createGuardianClient(guardian.url).requestDecision(envelope);

    expect(outcome.decisionArrived).toBe(true);
    expect(outcome.decisionArrived && outcome.decision.decision).toBe("allow");
  });

  it("answers 'no decision' with the Guardian's own JSON-RPC error as the failure, rather than throwing", async () => {
    // A method this Guardian dispatches no handler for.
    const envelope = buildEnvelope("PreToolUse", preToolUsePayload("ls -la"), hookmap);
    const unknownMethod = { ...envelope, method: "steps/sessionStart" };

    const outcome = await createGuardianClient(guardian.url).requestDecision(unknownMethod);

    expect(outcome.decisionArrived).toBe(false);
    expect((outcome.decisionArrived === false ? outcome.failure : undefined) as { code?: number }).toHaveProperty(
      "code",
    );
  });

  // Against the REAL Guardian, because the refusal set in failure-posture.ts
  // is a hand-written list of four integers and the only thing that makes it
  // a fact rather than a belief is driving the route that produces one. This
  // is `-32011`, the arguable member: a host only sends methods its own
  // hookmap maps, so a Guardian refusing to dispatch one is a disagreement
  // between this deployment's hookmap and its Guardian -- not a permission.
  it("hands the error through so a refusal is classified as one, not as a delivery failure", async () => {
    const envelope = buildEnvelope("PreToolUse", preToolUsePayload("ls -la"), hookmap);
    const unknownMethod = { ...envelope, method: "steps/sessionStart" };

    const outcome = await createGuardianClient(guardian.url).requestDecision(unknownMethod);

    expect(outcome.decisionArrived).toBe(false);
    const classified = classifyDeliveryFailure(outcome.decisionArrived === false ? outcome.failure : undefined);
    expect(classified.kind).toBe("refused");
    expect(classified.message).toContain("-32011");
  });

  // The other end of the same route, end to end through the posture: the
  // Guardian is up, this one envelope is refused, and the step is denied even
  // though the deployment declared `proceed`. Under `deny` this would pass
  // against the unfixed code, which is why the posture here is `proceed`.
  it("denies a refused step under a proceed posture, with the guardian up", async () => {
    const envelope = buildEnvelope("PreToolUse", preToolUsePayload("rm -rf /"), hookmap);
    const unknownMethod = { ...envelope, method: "steps/sessionStart" };

    const outcome = await createGuardianClient(guardian.url).requestDecision(unknownMethod);
    expect(outcome.decisionArrived).toBe(false);

    const events: AuditEvent[] = [];
    const decision = applyFailurePosture({
      failure: outcome.decisionArrived === false ? outcome.failure : undefined,
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
      method: unknownMethod.method,
      rpcId: unknownMethod.id,
      audit: { path: "test", write: (e) => (events.push(e), true) },
    });

    expect(decision.decision).toBe("deny");
    expect(decision.reason_codes).toEqual(["guardian_refused"]);
    expect(events[0]).toMatchObject({ posture: "proceed", outcome: "blocked", failure: { kind: "refused" } });
  });

  it("answers 'no decision' when the transport itself fails, rather than throwing", async () => {
    const envelope = buildEnvelope("PreToolUse", preToolUsePayload("ls -la"), hookmap);

    // Port 1 with nothing listening: a refused connection, not a slow one.
    const outcome = await createGuardianClient("http://localhost:1/acs").requestDecision(envelope);

    expect(outcome.decisionArrived).toBe(false);
  });

  it("honours a decision that arrives alongside a malformed `error`, never letting the failure outrank it", async () => {
    // A response carrying both is malformed per JSON-RPC, but a decision is in
    // it -- and a caller that checked `error` first would answer a real deny
    // with a delivery-failure path instead of honouring it.
    const mock = Bun.serve({
      port: 0,
      async fetch(req) {
        const body = (await req.json()) as { id: string | number };
        return Response.json({
          jsonrpc: "2.0",
          id: body.id,
          result: { decision: "deny", reasoning: "blocked" },
          error: { code: -32020, message: "something also went wrong" },
        });
      },
    });

    try {
      const envelope = buildEnvelope("PreToolUse", preToolUsePayload("rm -rf /"), hookmap);
      const outcome = await createGuardianClient(`http://localhost:${mock.port}/acs`).requestDecision(envelope);

      expect(outcome.decisionArrived).toBe(true);
      expect(outcome.decisionArrived && outcome.decision.decision).toBe("deny");
    } finally {
      mock.stop(true);
    }
  });

  it("answers 'no decision' for a result naming none, rather than passing an undecided bag on to be rendered", async () => {
    const mock = Bun.serve({
      port: 0,
      async fetch(req) {
        const body = (await req.json()) as { id: string | number };
        return Response.json({ jsonrpc: "2.0", id: body.id, result: { type: "final" } });
      },
    });

    try {
      const envelope = buildEnvelope("PreToolUse", preToolUsePayload("ls -la"), hookmap);
      const outcome = await createGuardianClient(`http://localhost:${mock.port}/acs`).requestDecision(envelope);

      expect(outcome.decisionArrived).toBe(false);
    } finally {
      mock.stop(true);
    }
  });

  it("answers 'no decision' for another request's decision, however well-formed it is", async () => {
    // A decision that names a foreign request_id is not this step's decision,
    // and the dangerous shape of it is `allow`: honouring it would let a
    // benign step's verdict stand in for one this Guardian never ruled on.
    // The throw from post lands in the same "no decision" answer as a dead
    // transport, so the caller's posture path resolves it and nothing here
    // has to invent a taxonomy for it.
    const mock = Bun.serve({
      port: 0,
      async fetch(req) {
        const body = (await req.json()) as { id: string | number };
        return Response.json({
          jsonrpc: "2.0",
          id: body.id,
          result: { decision: "allow", request_id: crypto.randomUUID() },
        });
      },
    });

    try {
      const envelope = buildEnvelope("PreToolUse", preToolUsePayload("rm -rf /"), hookmap);
      const outcome = await createGuardianClient(`http://localhost:${mock.port}/acs`).requestDecision(envelope);

      expect(outcome.decisionArrived).toBe(false);
    } finally {
      mock.stop(true);
    }
  });
});

describe("GuardianClient.post — the negotiated timeout (§6.4)", () => {
  it("throws GuardianTimeoutError when no response arrives in time", async () => {
    const server = Bun.serve({
      port: 0,
      async fetch(req) {
        // Tied to the request's own signal, not a bare setTimeout: once the
        // client times out and this test's `finally` force-stops the server,
        // Bun aborts the in-flight request and this listener clears the
        // 5-second timer. Without it, the timer would keep the process's
        // event loop alive and the suite would hang for 5 extra seconds on
        // every run of this test.
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, 5_000);
          req.signal.addEventListener("abort", () => {
            clearTimeout(timer);
            resolve();
          });
        });
        return Response.json({ jsonrpc: "2.0", id: "1", result: {} });
      },
    });
    try {
      const url = `http://localhost:${server.port}/acs`;
      const envelope = { jsonrpc: "2.0" as const, method: "steps/toolCallRequest", id: "1", params: {} };
      await expect(createGuardianClient(url).post(envelope, { timeoutMs: 25 })).rejects.toThrow(GuardianTimeoutError);
    } finally {
      await server.stop(true);
    }
  });

  it("returns normally when the response beats the timeout", async () => {
    const server = Bun.serve({
      port: 0,
      fetch: () => Response.json({ jsonrpc: "2.0", id: "1", result: { decision: "allow" } }),
    });
    try {
      const url = `http://localhost:${server.port}/acs`;
      const envelope = { jsonrpc: "2.0" as const, method: "steps/toolCallRequest", id: "1", params: {} };
      const response = await createGuardianClient(url).post(envelope, { timeoutMs: 5000 });
      expect(response.result).toEqual({ decision: "allow" });
    } finally {
      await server.stop(true);
    }
  });

  it("still works with no timeout given", async () => {
    const server = Bun.serve({
      port: 0,
      fetch: () => Response.json({ jsonrpc: "2.0", id: "1", result: { decision: "allow" } }),
    });
    try {
      const url = `http://localhost:${server.port}/acs`;
      const envelope = { jsonrpc: "2.0" as const, method: "steps/toolCallRequest", id: "1", params: {} };
      expect((await createGuardianClient(url).post(envelope)).result).toEqual({ decision: "allow" });
    } finally {
      await server.stop(true);
    }
  });

  // `await res.json()` sits inside the try that maps a TimeoutError onto
  // GuardianTimeoutError, so a Guardian whose headers beat the timeout while
  // its body does not is still classified as `timeout`, not
  // `error_without_decision`. §6.4 defines a decision failure by the
  // absence of a usable decision within the negotiated timeout; a body that
  // never arrives is exactly that.
  it("throws GuardianTimeoutError when the headers arrive but the body never does", async () => {
    const server = Bun.serve({
      port: 0,
      fetch(req) {
        // Headers go out immediately; the body stream stays open. Tied to the
        // request's own signal for the same reason as the test above -- an
        // interval outliving the aborted request would hold the event loop.
        const body = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('{"jsonrpc":"2.0",'));
            req.signal.addEventListener(
              "abort",
              () => {
                try {
                  controller.close();
                } catch {
                  // Already closed by the abort itself; nothing to do.
                }
              },
              { once: true },
            );
          },
        });
        return new Response(body, { headers: { "content-type": "application/json" } });
      },
    });
    try {
      const url = `http://localhost:${server.port}/acs`;
      const envelope = { jsonrpc: "2.0" as const, method: "steps/toolCallRequest", id: "1", params: {} };
      await expect(createGuardianClient(url).post(envelope, { timeoutMs: 40 })).rejects.toThrow(GuardianTimeoutError);
    } finally {
      await server.stop(true);
    }
  });
});

describe("negotiateSessionConfig", () => {
  it("sends handshake/hello and stores timeout_config and on_decision_failure into the session config store", async () => {
    const store = createMemorySessionConfigStore();
    expect(store.get()).toBeUndefined();

    const sessionConfig = await negotiateSessionConfig(
      { guardian: createGuardianClient(guardian.url), agentId: "claude-code", sessionId: crypto.randomUUID() },
      store,
    );

    expect(sessionConfig.on_decision_failure).toBe("proceed");
    expect(sessionConfig.timeout_config.default_ms).toBeGreaterThan(0);

    const stored = store.get();
    expect(stored).toBeDefined();
    expect(stored?.timeout_config).toEqual(sessionConfig.timeout_config);
    expect(stored?.on_decision_failure).toBe("proceed");
  });

  // The ServerHello becomes a SessionConfig by being checked, not by
  // `as unknown as SessionConfig` -- so a Guardian emitting the wrong shape
  // fails at the handshake instead of writing an unusable config that every
  // later read silently rejects.
  it("refuses a ServerHello that is not a usable session config, rather than casting it into one", async () => {
    const mock = Bun.serve({
      port: 0,
      async fetch(req) {
        const body = (await req.json()) as { id: string | number };
        return Response.json({ jsonrpc: "2.0", id: body.id, result: { negotiated_version: "0.1.0" } });
      },
    });

    try {
      const store = createMemorySessionConfigStore();

      await expect(
        negotiateSessionConfig(
          {
            guardian: createGuardianClient(`http://localhost:${mock.port}/acs`),
            agentId: "claude-code",
            sessionId: crypto.randomUUID(),
          },
          store,
        ),
      ).rejects.toThrow(/not a usable session config/);

      expect(store.get()).toBeUndefined();
    } finally {
      mock.stop(true);
    }
  });
});

// Storing an unusable ServerHello without checking it would be harmless for
// reads -- `get()` re-validates, so a junk file returns undefined -- but the
// consequence nothing would surface is that every `get()` afterwards returns
// undefined, so every hook re-handshakes, forever, while the deployment runs
// on the ACS default rather than the posture its Guardian keeps declaring.
// Silently.
describe("handshake — a ServerHello that is not a usable session config", () => {
  /** A stub answering `handshake/hello` with whatever `result` it is given. */
  async function handshakeAgainst(result: unknown, store = createMemorySessionConfigStore()) {
    const server = Bun.serve({
      port: 0,
      async fetch(req) {
        const body = (await req.json()) as { id: string | number };
        return Response.json({ jsonrpc: "2.0", id: body.id, result });
      },
    });
    try {
      const url = `http://localhost:${server.port}/acs`;
      const thrown = await negotiateSessionConfig(
        { guardian: createGuardianClient(url), agentId: "claude-code", sessionId: crypto.randomUUID() },
        store,
      ).then(
        () => undefined,
        (error: unknown) => error,
      );
      return { thrown, store };
    } finally {
      await server.stop(true);
    }
  }

  const unusable = [
    ["an empty object", {}],
    ["a posture that is neither value", { on_decision_failure: "maybe", timeout_config: { default_ms: 5000 } }],
    ["no timeout_config at all", { on_decision_failure: "deny" }],
    ["a non-numeric default_ms", { on_decision_failure: "deny", timeout_config: { default_ms: "5000" } }],
  ] as const;

  for (const [label, result] of unusable) {
    it(`rejects ${label} rather than storing it`, async () => {
      const { thrown, store } = await handshakeAgainst(result);
      expect(thrown).toBeInstanceOf(SessionConfigNotStoredError);
      expect((thrown as SessionConfigNotStoredError).kind).toBe("server_hello_invalid");
      // Nothing was stored, so nothing has to be un-stored -- and the caller
      // gets undefined from the error's `config` too, because a hello this
      // shape negotiated no posture to apply to the current step either.
      expect(store.get()).toBeUndefined();
      expect((thrown as SessionConfigNotStoredError).config).toBeUndefined();
    });
  }

  it("stores a usable ServerHello unchanged, extra fields and all", async () => {
    const hello = {
      negotiated_version: "0.1.0",
      methods_evaluated: ["steps/toolCallRequest"],
      selected_transport: "http",
      timeout_config: { default_ms: 1234 },
      on_decision_failure: "deny" as const,
      // A field this module never names: the store round-trips it, and
      // validation must not drop it.
      profiles_accepted: ["ACS-Core"],
    };
    const { thrown, store } = await handshakeAgainst(hello);
    expect(thrown).toBeUndefined();
    expect(store.get()).toEqual(hello);
  });
});

describe("handshake — the negotiated timeout (§6.4)", () => {
  it("throws GuardianTimeoutError when the Guardian accepts the connection and never answers, and stores nothing", async () => {
    const server = Bun.serve({
      port: 0,
      async fetch(req) {
        // Tied to the request's own signal, not a bare setTimeout -- see
        // guardianClient.post's own timeout test above for why: without
        // this, the timer outlives the client's abort and this test's
        // `finally` force-stop, keeping the event loop alive for 5 extra
        // seconds on every run.
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, 5_000);
          req.signal.addEventListener("abort", () => {
            clearTimeout(timer);
            resolve();
          });
        });
        return Response.json({ jsonrpc: "2.0", id: "1", result: {} });
      },
    });
    try {
      const store = createMemorySessionConfigStore();
      const url = `http://localhost:${server.port}/acs`;
      await expect(
        negotiateSessionConfig(
          {
            guardian: createGuardianClient(url),
            agentId: "claude-code",
            sessionId: crypto.randomUUID(),
            timeoutMs: 25,
          },
          store,
        ),
      ).rejects.toThrow(GuardianTimeoutError);
      expect(store.get()).toBeUndefined();
    } finally {
      await server.stop(true);
    }
  });
});

// `resolveSessionConfig` is what a host shim actually calls, and it exists so
// that no shim repeats this interrogation itself: run the negotiation,
// catch, test `instanceof`, read `.config` off the error to discover whether a
// posture had been negotiated after all. These properties are pinned
// directly here, at the unit level, not only end to end through a
// subprocess (hosts/claude-code/test/posture.test.ts) -- which is exactly
// the coverage shape that would let a reimplementation in a second host go
// wrong quietly.
describe("resolveSessionConfig — the session, as a message rather than a throw", () => {
  const HELLO = {
    negotiated_version: "0.1.0",
    methods_evaluated: ["steps/toolCallRequest"],
    selected_transport: "http",
    timeout_config: { default_ms: 1234 },
    on_decision_failure: "deny" as const,
  };

  /** A stub answering `handshake/hello` with `result`. */
  async function against<T>(result: unknown, run: (url: string) => Promise<T>): Promise<T> {
    const server = Bun.serve({
      port: 0,
      async fetch(req) {
        const { id } = (await req.json()) as { id: string | number };
        return Response.json({ jsonrpc: "2.0", id, result });
      },
    });
    try {
      return await run(`http://localhost:${server.port}/acs`);
    } finally {
      await server.stop(true);
    }
  }

  function resolveVia(url: string, store: ReturnType<typeof createMemorySessionConfigStore>) {
    return resolveSessionConfig(
      { guardian: createGuardianClient(url), agentId: "claude-code", sessionId: crypto.randomUUID() },
      store,
    );
  }

  it("negotiates when the store is empty, and reports no failure", async () => {
    const store = createMemorySessionConfigStore();
    const resolved = await against(HELLO, (url) => resolveVia(url, store));
    expect(resolved).toEqual({ config: HELLO, failure: undefined });
  });

  it("does not negotiate at all when the store already holds a config", async () => {
    const store = createMemorySessionConfigStore();
    store.set(HELLO);
    // An unreachable Guardian, so a handshake attempt would surface as a
    // failure rather than passing silently.
    const resolved = await resolveVia("http://127.0.0.1:1/acs", store);
    expect(resolved).toEqual({ config: HELLO, failure: undefined });
  });

  // `set()` throws, `get()` stays undefined, and the posture the
  // Guardian just declared has to reach this step anyway -- otherwise a
  // deployment that asked to fail closed fails open on the very step whose
  // posture it negotiated, and does so on every hook, forever.
  it("applies a config it could not store to the step that negotiated it, and still reports the failure", async () => {
    const unwritable = {
      get: () => undefined,
      set: () => {
        throw new Error("ENOTDIR: not a directory");
      },
    };
    const resolved = await against(HELLO, (url) => resolveVia(url, unwritable));
    expect(resolved.config).toEqual(HELLO);
    expect(resolved.failure).toBeInstanceOf(SessionConfigNotStoredError);
    expect((resolved.failure as SessionConfigNotStoredError).kind).toBe("session_config_unstored");
  });

  // The other member of the family, and the reason it has a name of its own:
  // nothing was negotiated, so unlike the case above there is nothing to apply
  // to this step either, and `config` must stay undefined so the ACS default
  // governs.
  it("reports an unusable ServerHello with no config to apply", async () => {
    const store = createMemorySessionConfigStore();
    const resolved = await against({ on_decision_failure: "maybe" }, (url) => resolveVia(url, store));
    expect(resolved.config).toBeUndefined();
    expect(resolved.failure).toBeInstanceOf(ServerHelloInvalidError);
    expect((resolved.failure as ServerHelloInvalidError).kind).toBe("server_hello_invalid");
    expect((resolved.failure as ServerHelloInvalidError).config).toBeUndefined();
  });

  it("answers rather than throwing when the Guardian was never reachable", async () => {
    const store = createMemorySessionConfigStore();
    const resolved = await resolveVia("http://127.0.0.1:1/acs", store);
    expect(resolved.config).toBeUndefined();
    expect(resolved.failure).toBeInstanceOf(Error);
    // Not a member of the not-stored family: nothing arrived, so nothing was
    // negotiated, and `classifySessionFailure` files it as `handshake_failed`.
    expect(resolved.failure).not.toBeInstanceOf(SessionConfigNotStoredError);
  });
});

describe("host -> wire -> policy -> host, end to end", () => {
  it("a real rm -rf / tool call denies through the real Guardian, and renders with the reasoning in permissionDecisionReason", async () => {
    const envelope = buildEnvelope("PreToolUse", preToolUsePayload("rm -rf /"), hookmap);

    const response = await createGuardianClient(guardian.url).post(envelope);
    expect(response.error).toBeUndefined();

    const { hookSpecificOutput } = renderDecision(
      "PreToolUse",
      response.result as { decision: string } & Record<string, unknown>,
      hookmap,
    ) as { hookSpecificOutput: Record<string, unknown> };

    expect(hookSpecificOutput.permissionDecision).toBe("deny");
    expect(typeof hookSpecificOutput.permissionDecisionReason).toBe("string");
    expect((hookSpecificOutput.permissionDecisionReason as string).length).toBeGreaterThan(0);
  });

  it("a real ls -la tool call allows through the real Guardian, and renders as a plain allow", async () => {
    const envelope = buildEnvelope("PreToolUse", preToolUsePayload("ls -la"), hookmap);

    const response = await createGuardianClient(guardian.url).post(envelope);
    expect(response.error).toBeUndefined();

    const { hookSpecificOutput } = renderDecision(
      "PreToolUse",
      response.result as { decision: string } & Record<string, unknown>,
      hookmap,
    ) as { hookSpecificOutput: Record<string, unknown> };

    // No `hookEventName` here: it is not a function of the decision, so the
    // shim adds it as it wraps. What a Claude Code
    // process actually reads back, with that field in place, is pinned in
    // hosts/claude-code/test/wire-shape.test.ts against the real shim.
    expect(hookSpecificOutput).toEqual({ permissionDecision: "allow" });
  });
});
