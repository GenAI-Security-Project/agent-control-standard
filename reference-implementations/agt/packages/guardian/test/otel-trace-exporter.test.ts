import { describe, expect, it, spyOn } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SpanStatusCode } from "@opentelemetry/api";
import { InMemorySpanExporter, type ReadableSpan, type SpanExporter } from "@opentelemetry/sdk-trace-base";
import { startGuardian } from "../src/index.ts";
import { METHODS_EVALUATED } from "../src/handshake.ts";
import {
  createOtelTraceExporter,
  loadOtelMapping,
  NULL_OTEL_TRACE_EXPORTER,
  OTEL_SERVICE_NAME,
  type CreateOtelTraceExporterOptions,
  type OtelTraceExporter,
} from "../src/otel-trace-exporter.ts";

/** The live mapping, read the same way the exporter reads it, so every
 * expected name below comes from the file and not from a literal that could
 * drift from it. */
const MAPPING = loadOtelMapping();
const TOOL_CALL_SPAN = MAPPING.stepToSpan["steps/toolCallRequest"]!;

function makeEnvelope(
  method: string,
  payload: Record<string, unknown>,
  overrides: { id?: number | null; requestId?: string; sessionId?: string } = {},
): Record<string, unknown> {
  const { id = 1, requestId = crypto.randomUUID(), sessionId = crypto.randomUUID() } = overrides;
  return {
    jsonrpc: "2.0",
    method,
    ...(id === null ? {} : { id }),
    params: {
      acs_version: "0.1.0",
      request_id: requestId,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "agent-1", session_id: sessionId },
      payload,
    },
  };
}

/** Carries `capability`, which hooks/tool-call-request.json declares
 * optional and the mapping requires on the span -- so a span built from this
 * envelope has every required attribute the mapping names. */
function toolCallEnvelope(command: string, overrides: { id?: number | null; requestId?: string; sessionId?: string } = {}) {
  return makeEnvelope(
    "steps/toolCallRequest",
    { tool: { name: "run_shell" }, capability: "process.exec", arguments: { command: { value: command } } },
    overrides,
  );
}

function decisionResponse(id: number, result: Record<string, unknown>): Record<string, unknown> {
  return { jsonrpc: "2.0", id, result: { type: "final", acs_version: "0.1.0", request_id: "r-1", ...result } };
}

const DENY = {
  decision: "deny",
  reasoning: "blocked",
  reason_codes: ["dangerous_command"],
  policy_references: [{ policy_id: "agt_stock", rule_id: "deny-rm-rf" }],
};

function memoryExporter(options: Partial<CreateOtelTraceExporterOptions> = {}): {
  exporter: OtelTraceExporter;
  spans(): ReadableSpan[];
} {
  const memory = new InMemorySpanExporter();
  const exporter = createOtelTraceExporter({ spanExporter: memory, methodsEvaluated: METHODS_EVALUATED, ...options });
  return { exporter, spans: () => memory.getFinishedSpans() };
}

/** A span exporter that fails on every export, the way an unwritable file or
 * an unreachable collector would. */
function throwingSpanExporter(): SpanExporter {
  return {
    export(): void {
      throw new Error("exporter threw");
    },
    async shutdown(): Promise<void> {},
  };
}

async function postRaw(url: string, body: unknown): Promise<Record<string, unknown>> {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return (await res.json()) as Record<string, unknown>;
}

const baseOptions = { port: 0, manifestPath: "policy/manifest.yaml" } as const;

describe("createOtelTraceExporter -- what one exchange becomes", () => {
  it("names the span from the live mapping and carries every required attribute the wire supplied", async () => {
    const { exporter, spans } = memoryExporter();
    const sessionId = crypto.randomUUID();
    const requestId = crypto.randomUUID();
    const request = toolCallEnvelope("rm -rf /", { id: 7, requestId, sessionId });

    const step = exporter.start(request, "steps/toolCallRequest");
    exporter.end(step, decisionResponse(7, DENY));
    await exporter.flush();

    const [span] = spans();
    expect(spans()).toHaveLength(1);
    expect(span?.name).toBe(TOOL_CALL_SPAN.span_name);
    for (const attribute of TOOL_CALL_SPAN.required_attributes) {
      expect({ attribute, present: span?.attributes[attribute] !== undefined }).toEqual({ attribute, present: true });
    }
    expect(span?.attributes["gen_ai.tool.name"]).toBe("run_shell");
    expect(span?.attributes["acs.session.id"]).toBe(sessionId);
    expect(span?.attributes["acs.request_id"]).toBe(requestId);
    expect(span?.resource.attributes["service.name"]).toBe(OTEL_SERVICE_NAME);
  });

  it("records the decision as the mapping's event on that span, with acs.decision and acs.evaluator", async () => {
    const { exporter, spans } = memoryExporter();
    exporter.end(exporter.start(toolCallEnvelope("rm -rf /", { id: 7 }), "steps/toolCallRequest"), decisionResponse(7, DENY));
    await exporter.flush();

    const [event] = spans()[0]?.events ?? [];
    expect(event?.name).toBe(MAPPING.decisionEventName);
    expect(event?.attributes?.["acs.decision"]).toBe("deny");
    expect(event?.attributes?.["acs.evaluator"]).toBe("deterministic");
    expect(event?.attributes?.["acs.reasoning"]).toBe("blocked");
    expect(event?.attributes?.["acs.reason_codes"]).toEqual(["dangerous_command"]);
    expect(event?.attributes?.["acs.policy.ids"]).toEqual(["agt_stock"]);
    expect(event?.attributes?.["acs.policy.rule_ids"]).toEqual(["deny-rm-rf"]);
    // No reference carried a version, so no column is invented for it.
    expect(event?.attributes?.["acs.policy.versions"]).toBeUndefined();
  });

  it("takes acs.evaluator from the response when it carries one", async () => {
    const { exporter, spans } = memoryExporter();
    exporter.end(
      exporter.start(toolCallEnvelope("ls", { id: 7 }), "steps/toolCallRequest"),
      decisionResponse(7, { decision: "allow", metadata: { evaluator: "agent", model_id: "m-1" } }),
    );
    await exporter.flush();

    const attributes = spans()[0]?.events[0]?.attributes;
    expect(attributes?.["acs.evaluator"]).toBe("agent");
    expect(attributes?.["acs.model_id"]).toBe("m-1");
  });

  it("lines up policy columns in wire order, and drops a column any reference lacks", async () => {
    const { exporter, spans } = memoryExporter();
    exporter.end(
      exporter.start(toolCallEnvelope("ls", { id: 7 }), "steps/toolCallRequest"),
      decisionResponse(7, {
        decision: "deny",
        reasoning: "x",
        policy_references: [
          { policy_id: "p1", policy_version: "v1", rule_id: "r1" },
          { policy_id: "p2", rule_id: "r2" },
        ],
      }),
    );
    await exporter.flush();

    const attributes = spans()[0]?.events[0]?.attributes;
    expect(attributes?.["acs.policy.ids"]).toEqual(["p1", "p2"]);
    expect(attributes?.["acs.policy.rule_ids"]).toEqual(["r1", "r2"]);
    expect(attributes?.["acs.policy.versions"]).toBeUndefined();
  });

  it("carries acs.chain_hash only when the response does", async () => {
    const { exporter, spans } = memoryExporter();
    exporter.end(exporter.start(toolCallEnvelope("ls", { id: 1 }), "steps/toolCallRequest"), decisionResponse(1, { decision: "allow", chain_hash: "a".repeat(64) }));
    exporter.end(exporter.start(toolCallEnvelope("ls", { id: 2 }), "steps/toolCallRequest"), decisionResponse(2, { decision: "allow" }));
    await exporter.flush();

    const [withHash, withoutHash] = spans();
    expect(withHash?.events[0]?.attributes?.["acs.chain_hash"]).toBe("a".repeat(64));
    expect(withoutHash?.events[0]?.attributes?.["acs.chain_hash"]).toBeUndefined();
  });

  it("emits no span for a method the mapping does not name, nor for one this Guardian does not dispatch", async () => {
    const { exporter, spans } = memoryExporter();
    // handshake/hello has no step_to_span entry. steps/sessionStart has one,
    // and is not in the ServerHello's methods_evaluated.
    const hello = exporter.start(makeEnvelope("handshake/hello", {}, { id: 1 }), "handshake/hello");
    const sessionStart = exporter.start(makeEnvelope("steps/sessionStart", {}, { id: 2 }), "steps/sessionStart");
    expect(hello).toBeNull();
    expect(sessionStart).toBeNull();
    exporter.end(hello, { jsonrpc: "2.0", id: 1, result: { negotiated_version: "0.1.0" } });
    exporter.end(sessionStart, { jsonrpc: "2.0", id: 2, error: { code: -32011, message: "not dispatched" } });
    await exporter.flush();

    expect(spans()).toHaveLength(0);
  });

  it("ends a span answered with a JSON-RPC error in error status, with no decision event", async () => {
    const { exporter, spans } = memoryExporter();
    exporter.end(
      exporter.start(toolCallEnvelope("ls", { id: 9 }), "steps/toolCallRequest"),
      { jsonrpc: "2.0", id: 9, error: { code: -32020, message: "evaluation failed" } },
    );
    await exporter.flush();

    const [span] = spans();
    expect(span?.status.code).toBe(SpanStatusCode.ERROR);
    expect(span?.status.message).toBe("evaluation failed");
    expect(span?.events).toHaveLength(0);
  });

  // The pairing is the handle, not the id: an envelope with no JSON-RPC id
  // at all still gets its span, closed by its own response.
  it("pairs request and response by handle, so a request with no JSON-RPC id still gets its span", async () => {
    const { exporter, spans } = memoryExporter();
    const step = exporter.start(toolCallEnvelope("ls", { id: null }), "steps/toolCallRequest");
    expect(step).not.toBeNull();
    exporter.end(step, { jsonrpc: "2.0", id: null, error: { code: -32010, message: "invalid" } });
    await exporter.flush();

    expect(spans()).toHaveLength(1);
    expect(spans()[0]?.status.code).toBe(SpanStatusCode.ERROR);
  });

  // The whole reason the exporter is total: a broken output must cost
  // observability, never a decision.
  it("never throws when the span exporter throws, reports once, and goes quiet", async () => {
    const errors: unknown[] = [];
    const exporter = createOtelTraceExporter({
      spanExporter: throwingSpanExporter(),
      methodsEvaluated: METHODS_EVALUATED,
      onError: (error) => errors.push(error),
    });

    const step = exporter.start(toolCallEnvelope("ls", { id: 1 }), "steps/toolCallRequest");
    expect(() => exporter.end(step, decisionResponse(1, DENY))).not.toThrow();
    await exporter.flush();
    expect(() => exporter.start(toolCallEnvelope("ls", { id: 2 }), "steps/toolCallRequest")).not.toThrow();
    await exporter.flush();
    await exporter.shutdown();

    expect(errors).toHaveLength(1);
  });

  it("never throws when the file path is unwritable, and reports once", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-otel-broken-"));
    const blocker = join(dir, "blocker");
    await Bun.write(blocker, "");
    const errors: unknown[] = [];
    try {
      // A path *through* a regular file: mkdirSync fails with ENOTDIR,
      // deterministically, on every platform.
      const exporter = createOtelTraceExporter({
        filePath: join(blocker, "nested", "traces.jsonl"),
        methodsEvaluated: METHODS_EVALUATED,
        onError: (error) => errors.push(error),
      });
      expect(exporter.start(toolCallEnvelope("ls", { id: 1 }), "steps/toolCallRequest")).toBeNull();
      await exporter.shutdown();
      expect(errors).toHaveLength(1);
    } finally {
      unlinkSync(blocker);
      rmdirSync(dir);
    }
  });

  it("NULL_OTEL_TRACE_EXPORTER writes nothing and never throws", async () => {
    expect(NULL_OTEL_TRACE_EXPORTER.start(toolCallEnvelope("ls"), "steps/toolCallRequest")).toBeNull();
    expect(() => NULL_OTEL_TRACE_EXPORTER.end(null, decisionResponse(1, DENY))).not.toThrow();
    await NULL_OTEL_TRACE_EXPORTER.flush();
    await NULL_OTEL_TRACE_EXPORTER.shutdown();
  });
});

describe("Guardian trace export wiring", () => {
  it("emits one span per decided step, carrying the session and the decision event", async () => {
    const { exporter, spans } = memoryExporter();
    const guardian = await startGuardian({ ...baseOptions, traceExporter: exporter });
    const sessionId = crypto.randomUUID();
    const requestId = crypto.randomUUID();
    try {
      await postRaw(guardian.url, toolCallEnvelope("rm -rf /", { id: 11, requestId, sessionId }));
      await exporter.flush();

      const [span] = spans();
      expect(spans()).toHaveLength(1);
      expect(span?.name).toBe(TOOL_CALL_SPAN.span_name);
      expect(span?.attributes["acs.session.id"]).toBe(sessionId);
      expect(span?.attributes["acs.request_id"]).toBe(requestId);
      expect(span?.attributes["gen_ai.tool.name"]).toBe("run_shell");
      const [event] = span?.events ?? [];
      expect(event?.name).toBe(MAPPING.decisionEventName);
      expect(event?.attributes?.["acs.decision"]).toBe("deny");
      expect(event?.attributes?.["acs.evaluator"]).toBe("deterministic");
      expect(typeof event?.attributes?.["acs.reasoning"]).toBe("string");
      expect(Array.isArray(event?.attributes?.["acs.reason_codes"])).toBe(true);
      expect(Array.isArray(event?.attributes?.["acs.policy.ids"])).toBe(true);
    } finally {
      await guardian.close();
    }
  });

  // Hosts run hooks in parallel and number their requests independently, so
  // two sessions can be in flight with the same JSON-RPC id. Each must end
  // its own span with its own decision: the deny for the destructive call,
  // the allow for the benign one.
  it("keeps two concurrent sessions apart when they reuse one JSON-RPC id", async () => {
    const { exporter, spans } = memoryExporter();
    const guardian = await startGuardian({ ...baseOptions, traceExporter: exporter });
    const denied = { requestId: crypto.randomUUID(), sessionId: crypto.randomUUID() };
    const allowed = { requestId: crypto.randomUUID(), sessionId: crypto.randomUUID() };
    try {
      await Promise.all([
        postRaw(guardian.url, toolCallEnvelope("rm -rf /", { id: 1, ...denied })),
        postRaw(guardian.url, toolCallEnvelope("ls -la", { id: 1, ...allowed })),
      ]);
      await exporter.flush();

      expect(spans()).toHaveLength(2);
      const bySession = new Map(spans().map((span) => [span.attributes["acs.session.id"], span]));
      const deniedSpan = bySession.get(denied.sessionId);
      const allowedSpan = bySession.get(allowed.sessionId);
      expect(deniedSpan?.attributes["acs.request_id"]).toBe(denied.requestId);
      expect(allowedSpan?.attributes["acs.request_id"]).toBe(allowed.requestId);
      expect(deniedSpan?.events).toHaveLength(1);
      expect(allowedSpan?.events).toHaveLength(1);
      expect(deniedSpan?.events[0]?.attributes?.["acs.decision"]).toBe("deny");
      expect(allowedSpan?.events[0]?.attributes?.["acs.decision"]).toBe("allow");
    } finally {
      await guardian.close();
    }
  });

  it("emits no span for handshake/hello or for a method this Guardian does not dispatch", async () => {
    const { exporter, spans } = memoryExporter();
    const guardian = await startGuardian({ ...baseOptions, traceExporter: exporter });
    try {
      await postRaw(guardian.url, makeEnvelope("handshake/hello", {}, { id: 42 }));
      await postRaw(guardian.url, makeEnvelope("steps/sessionStart", {}, { id: 43 }));
      await exporter.flush();

      expect(spans()).toHaveLength(0);
    } finally {
      await guardian.close();
    }
  });

  // The span opens before validation, so the envelope that fails the schema
  // is visible in the trace too -- as a deny, and with no chain hash, because
  // the step never reached the chain.
  it("gives a schema-invalid steps/* envelope a span with a deny event and no acs.chain_hash", async () => {
    const { exporter, spans } = memoryExporter();
    const guardian = await startGuardian({ ...baseOptions, traceExporter: exporter });
    try {
      const bad = toolCallEnvelope("rm -rf /", { id: 12 });
      delete (bad.params as Record<string, unknown>).acs_version;
      await postRaw(guardian.url, bad);
      await exporter.flush();

      const [span] = spans();
      expect(spans()).toHaveLength(1);
      const attributes = span?.events[0]?.attributes;
      expect(attributes?.["acs.decision"]).toBe("deny");
      expect(attributes?.["acs.reason_codes"]).toEqual(["envelope_invalid"]);
      expect(attributes?.["acs.chain_hash"]).toBeUndefined();
    } finally {
      await guardian.close();
    }
  });

  // End to end: the exporter is on the decision path, so this is the test
  // that says a broken exporter cannot change what the host receives.
  it("answers identically with a failing exporter and with export off, and reports once", async () => {
    const errorSpy = spyOn(console, "error").mockImplementation(() => {});
    const exporter = createOtelTraceExporter({ spanExporter: throwingSpanExporter(), methodsEvaluated: METHODS_EVALUATED });
    const exporting = await startGuardian({ ...baseOptions, traceExporter: exporter });
    const silent = await startGuardian(baseOptions);
    try {
      const requestId = crypto.randomUUID();
      const sessionId = crypto.randomUUID();
      const envelope = toolCallEnvelope("rm -rf /", { id: 5, requestId, sessionId });

      const withExporter = await postRaw(exporting.url, envelope);
      await exporter.flush();
      const withoutExporter = await postRaw(silent.url, envelope);

      expect(withExporter).toEqual(withoutExporter);
      expect((withExporter.result as { decision?: string }).decision).toBe("deny");
      expect(errorSpy).toHaveBeenCalledTimes(1);
    } finally {
      errorSpy.mockRestore();
      await exporting.close();
      await silent.close();
    }
  });

  it("writes nothing when neither output is configured", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-otel-off-"));
    const path = join(dir, "traces.jsonl");
    const guardian = await startGuardian(baseOptions);
    try {
      await postRaw(guardian.url, toolCallEnvelope("ls -la"));
      expect(existsSync(path)).toBe(false);
    } finally {
      await guardian.close();
      rmdirSync(dir);
    }
  });

  it("flushes the file on close: every line is OTLP/JSON holding the expected spans", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-otel-file-"));
    const path = join(dir, "traces.jsonl");
    const guardian = await startGuardian({ ...baseOptions, otelTraceFile: path });
    try {
      await postRaw(guardian.url, toolCallEnvelope("rm -rf /", { id: 21 }));
      await postRaw(guardian.url, toolCallEnvelope("ls -la", { id: 22 }));
    } finally {
      // The spans are batched; close is what flushes them.
      await guardian.close();
    }
    try {
      expect(existsSync(path)).toBe(true);
      const lines = readFileSync(path, "utf8").split("\n").filter((line) => line.trim() !== "");
      expect(lines.length).toBeGreaterThan(0);

      type OtlpAttribute = { key: string; value: { stringValue?: string } };
      type OtlpRequest = {
        resourceSpans: {
          resource: { attributes: OtlpAttribute[] };
          scopeSpans: { spans: { name: string; events?: { name: string }[] }[] }[];
        }[];
      };
      const requests = lines.map((line) => JSON.parse(line) as OtlpRequest);
      const spans = requests.flatMap((r) => r.resourceSpans.flatMap((rs) => rs.scopeSpans.flatMap((ss) => ss.spans)));
      expect(spans.map((s) => s.name)).toEqual([TOOL_CALL_SPAN.span_name, TOOL_CALL_SPAN.span_name]);
      expect(spans.every((s) => s.events?.some((e) => e.name === MAPPING.decisionEventName))).toBe(true);
      const serviceName = requests[0]?.resourceSpans[0]?.resource.attributes.find((a) => a.key === "service.name");
      expect(serviceName?.value.stringValue).toBe(OTEL_SERVICE_NAME);
    } finally {
      unlinkSync(path);
      rmdirSync(dir);
    }
  });
});
