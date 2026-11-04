import { afterEach, describe, expect, it, spyOn } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmdirSync, rmSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SpanStatusCode } from "@opentelemetry/api";
import { InMemorySpanExporter, type ReadableSpan, type SpanExporter } from "@opentelemetry/sdk-trace-base";
import type { PolicyBridge } from "agt-bridge";
import { startGuardian, type GuardianSnapshot } from "../src/index.ts";
import { FAILURE_DETAIL_BY_KIND } from "../src/audit-to-otlp.ts";
import { buildServerHello } from "../src/handshake.ts";
import { makeEnvelope, toolCallEnvelope } from "./helpers/envelopes.ts";
import {
  createFileSpanExporter,
  keepLoopbackOffProxy,
  createOtelTraceExporter,
  DECISION_ATTRIBUTE_SOURCES,
  loadOtelMapping,
  loopbackProxyWarning,
  METHODS_WITHOUT_SPAN,
  NULL_OTEL_TRACE_EXPORTER,
  OTEL_SERVICE_NAME,
  REJECTED_SPAN_NAME,
  STEP_ATTRIBUTE_SOURCES,
  type CreateOtelTraceExporterOptions,
  type OtelTraceExporter,
} from "../src/otel-trace-exporter.ts";

/** What the Guardian tells `start` about a request it accepted. */
const TRUSTED = { trusted: true } as const;

/** The live mapping, read the same way the exporter reads it, so every
 * expected name below comes from the file and not from a literal that could
 * drift from it. */
const MAPPING = loadOtelMapping();
/** The methods this Guardian evaluates, from the ServerHello it sends --
 * the same source server.ts builds the exporter from. */
const METHODS_EVALUATED = buildServerHello().methods_evaluated;
const TOOL_CALL_SPAN = MAPPING.stepToSpan["steps/toolCallRequest"]!;

/** A Provenance object as provenance.json defines it: `provenance_id` and
 * `origin` required, everything else optional. */
function provenance(origin: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { provenance_id: crypto.randomUUID(), origin, ...extra };
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

/** The OTLP/JSON `ExportTraceServiceRequest` shape, as far as these tests
 * read it: resource attributes, and span names and events. */
type OtlpAttribute = { key: string; value: { stringValue?: string; intValue?: string | number } };
type OtlpEvent = { name: string; attributes?: OtlpAttribute[] };
type OtlpSpan = { name: string; attributes?: OtlpAttribute[]; events?: OtlpEvent[]; status?: { code?: number } };
type OtlpRequest = {
  resourceSpans: {
    resource: { attributes: OtlpAttribute[] };
    scopeSpans: { spans: OtlpSpan[] }[];
  }[];
};

function otlpSpans(requests: OtlpRequest[]): OtlpSpan[] {
  return requests.flatMap((r) => r.resourceSpans.flatMap((rs) => rs.scopeSpans.flatMap((ss) => ss.spans)));
}

/** One string attribute off an OTLP/JSON span or event, or undefined. */
function otlpAttribute(carrier: OtlpSpan | OtlpEvent | undefined, key: string): string | undefined {
  return carrier?.attributes?.find((attribute) => attribute.key === key)?.value.stringValue;
}

/** Every line of an OTLP/JSON file, parsed. */
function otlpFile(path: string): OtlpRequest[] {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line) as OtlpRequest);
}

describe("createOtelTraceExporter -- what one exchange becomes", () => {
  it("names the span from the live mapping and carries every required attribute the wire supplied", async () => {
    const { exporter, spans } = memoryExporter();
    const sessionId = crypto.randomUUID();
    const requestId = crypto.randomUUID();
    const request = toolCallEnvelope("rm -rf /", { id: 7, requestId, sessionId });

    const step = exporter.start(request, "steps/toolCallRequest", TRUSTED);
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

  it("records the decision as the mapping's event on that span, with acs.decision and no evaluator the response did not send", async () => {
    const { exporter, spans } = memoryExporter();
    exporter.end(exporter.start(toolCallEnvelope("rm -rf /", { id: 7 }), "steps/toolCallRequest", TRUSTED), decisionResponse(7, DENY));
    await exporter.flush();

    const [event] = spans()[0]?.events ?? [];
    expect(event?.name).toBe(MAPPING.decisionEventName);
    expect(event?.attributes?.["acs.decision"]).toBe("deny");
    // The response carried no metadata.evaluator, so the event carries no
    // acs.evaluator: the trace never says what the wire did not.
    expect(event?.attributes?.["acs.evaluator"]).toBeUndefined();
    expect(event?.attributes?.["acs.reasoning"]).toBe("blocked");
    expect(event?.attributes?.["acs.reason_codes"]).toEqual(["dangerous_command"]);
    expect(event?.attributes?.["acs.policy.ids"]).toEqual(["agt_stock"]);
    expect(event?.attributes?.["acs.policy.rule_ids"]).toEqual(["deny-rm-rf"]);
    // The reference carried no version: the column is still there, one ""
    // per reference, so the three columns always line up (#228).
    expect(event?.attributes?.["acs.policy.versions"]).toEqual([""]);
  });

  it("takes acs.evaluator from the response when it carries one", async () => {
    const { exporter, spans } = memoryExporter();
    exporter.end(
      exporter.start(toolCallEnvelope("ls", { id: 7 }), "steps/toolCallRequest", TRUSTED),
      decisionResponse(7, { decision: "allow", metadata: { evaluator: "agent", model_id: "m-1" } }),
    );
    await exporter.flush();

    const attributes = spans()[0]?.events[0]?.attributes;
    expect(attributes?.["acs.evaluator"]).toBe("agent");
    expect(attributes?.["acs.model_id"]).toBe("m-1");
  });

  it("lines up policy columns in wire order, with \"\" where a reference lacks the field", async () => {
    const { exporter, spans } = memoryExporter();
    exporter.end(
      exporter.start(toolCallEnvelope("ls", { id: 7 }), "steps/toolCallRequest", TRUSTED),
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
    expect(attributes?.["acs.policy.versions"]).toEqual(["v1", ""]);
  });

  it("pads a missing rule_id with \"\" in its own position", async () => {
    const { exporter, spans } = memoryExporter();
    exporter.end(
      exporter.start(toolCallEnvelope("ls", { id: 7 }), "steps/toolCallRequest", TRUSTED),
      decisionResponse(7, {
        decision: "deny",
        reasoning: "x",
        policy_references: [
          { policy_id: "p1", rule_id: "r1" },
          { policy_id: "p2" },
          { policy_id: "p3", rule_id: "r3" },
        ],
      }),
    );
    await exporter.flush();

    const attributes = spans()[0]?.events[0]?.attributes;
    expect(attributes?.["acs.policy.rule_ids"]).toEqual(["r1", "", "r3"]);
  });

  // The #228 rule, as the maintainer's own case states it: every policy
  // column is emitted whenever policy_references is non-empty, all the same
  // length, "" where a reference has no value.
  it("emits all three policy columns at the length of policy_references", async () => {
    const { exporter, spans } = memoryExporter();
    exporter.end(
      exporter.start(toolCallEnvelope("ls", { id: 7 }), "steps/toolCallRequest", TRUSTED),
      decisionResponse(7, {
        decision: "deny",
        reasoning: "x",
        policy_references: [{ policy_id: "a", rule_id: "r" }, { policy_id: "b" }],
      }),
    );
    await exporter.flush();

    const attributes = spans()[0]?.events[0]?.attributes;
    expect(attributes?.["acs.policy.ids"]).toEqual(["a", "b"]);
    expect(attributes?.["acs.policy.rule_ids"]).toEqual(["r", ""]);
    expect(attributes?.["acs.policy.versions"]).toEqual(["", ""]);
  });

  it("carries acs.chain_hash only when the response does", async () => {
    const { exporter, spans } = memoryExporter();
    exporter.end(exporter.start(toolCallEnvelope("ls", { id: 1 }), "steps/toolCallRequest", TRUSTED), decisionResponse(1, { decision: "allow", chain_hash: "a".repeat(64) }));
    exporter.end(exporter.start(toolCallEnvelope("ls", { id: 2 }), "steps/toolCallRequest", TRUSTED), decisionResponse(2, { decision: "allow" }));
    await exporter.flush();

    const [withHash, withoutHash] = spans();
    expect(withHash?.events[0]?.attributes?.["acs.chain_hash"]).toBe("a".repeat(64));
    expect(withoutHash?.events[0]?.attributes?.["acs.chain_hash"]).toBeUndefined();
  });

  it("emits no span for a method the mapping does not name, nor for one this Guardian does not dispatch", async () => {
    const { exporter, spans } = memoryExporter();
    // handshake/hello has no step_to_span entry. steps/sessionStart has one,
    // and is not in the ServerHello's methods_evaluated.
    const hello = exporter.start(makeEnvelope("handshake/hello", {}, { id: 1 }), "handshake/hello", TRUSTED);
    const sessionStart = exporter.start(makeEnvelope("steps/sessionStart", {}, { id: 2 }), "steps/sessionStart", TRUSTED);
    expect(hello).toBeNull();
    expect(sessionStart).toBeNull();
    exporter.end(hello, { jsonrpc: "2.0", id: 1, result: { negotiated_version: "0.1.0" } });
    exporter.end(sessionStart, { jsonrpc: "2.0", id: 2, error: { code: -32011, message: "not dispatched" } });
    await exporter.flush();

    expect(spans()).toHaveLength(0);
  });

  // The first of the two failures a Guardian can see itself (#37): it
  // answered an error instead of a decision. No acs.decision event, since
  // there was no decision; one acs.decision.failure event, with the code.
  it("ends a span answered with a JSON-RPC error in error status, with a guardian_error failure event and no decision event", async () => {
    const { exporter, spans } = memoryExporter();
    exporter.end(
      exporter.start(toolCallEnvelope("ls", { id: 9 }), "steps/toolCallRequest", TRUSTED),
      { jsonrpc: "2.0", id: 9, error: { code: -32020, message: "evaluation failed" } },
    );
    await exporter.flush();

    const [span] = spans();
    expect(span?.status.code).toBe(SpanStatusCode.ERROR);
    expect(span?.status.message).toBe(FAILURE_DETAIL_BY_KIND.error_without_decision);
    expect(span?.events.map((event) => event.name)).toEqual(["acs.decision.failure"]);
    const failure = span?.events[0]?.attributes;
    expect(failure?.["acs.failure.class"]).toBe("guardian_error");
    expect(failure?.["acs.failure.error_code"]).toBe(-32020);
    expect(failure?.["acs.failure.detail"]).toBeUndefined();
    expect(failure?.["acs.failure.reported_by"]).toBe("guardian");
    expect(failure?.["acs.failure.posture"]).toBe("fail_open");
    expect(typeof failure?.["acs.failure.elapsed_ms"]).toBe("number");
  });

  // The pairing is the handle, not the id: an envelope with no JSON-RPC id
  // at all still gets its span, closed by its own response. The schema
  // requires an id, so such an envelope is always one the Guardian rejected.
  it("pairs request and response by handle, so a request with no JSON-RPC id still gets its span", async () => {
    const { exporter, spans } = memoryExporter();
    const step = exporter.start(toolCallEnvelope("ls", { id: null }), "steps/toolCallRequest", {
      trusted: false,
      reason: "envelope_invalid",
    });
    expect(step).not.toBeNull();
    exporter.end(step, { jsonrpc: "2.0", id: null, error: { code: -32010, message: "invalid" } });
    await exporter.flush();

    expect(spans()).toHaveLength(1);
    expect(spans()[0]?.name).toBe(REJECTED_SPAN_NAME);
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

    const step = exporter.start(toolCallEnvelope("ls", { id: 1 }), "steps/toolCallRequest", TRUSTED);
    expect(() => exporter.end(step, decisionResponse(1, DENY))).not.toThrow();
    await exporter.flush();
    expect(() => exporter.start(toolCallEnvelope("ls", { id: 2 }), "steps/toolCallRequest", TRUSTED)).not.toThrow();
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
      expect(exporter.start(toolCallEnvelope("ls", { id: 1 }), "steps/toolCallRequest", TRUSTED)).toBeNull();
      await exporter.shutdown();
      expect(errors).toHaveLength(1);
    } finally {
      unlinkSync(blocker);
      rmdirSync(dir);
    }
  });

  // The lab reads the file. A collector that is down, restarting or
  // answering 4xx must cost the endpoint and nothing else: every span still
  // reaches the file, and the endpoint is reported once.
  it("keeps writing the file when the HTTP collector rejects every export, and reports that output once", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-otel-isolated-"));
    const path = join(dir, "traces.jsonl");
    const collector = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response("bad request", { status: 400 }) });
    const errors: unknown[] = [];
    const exporter = createOtelTraceExporter({
      filePath: path,
      endpoint: `http://127.0.0.1:${collector.port}/v1/traces`,
      methodsEvaluated: METHODS_EVALUATED,
      onError: (error) => errors.push(error),
    });
    try {
      for (const id of [1, 2, 3]) {
        exporter.end(exporter.start(toolCallEnvelope("ls", { id }), "steps/toolCallRequest", TRUSTED), decisionResponse(id, { decision: "allow" }));
        await exporter.flush();
      }
      await exporter.shutdown();

      expect(otlpSpans(otlpFile(path)).map((span) => span.name)).toEqual([
        TOOL_CALL_SPAN.span_name,
        TOOL_CALL_SPAN.span_name,
        TOOL_CALL_SPAN.span_name,
      ]);
      expect(errors).toHaveLength(1);
    } finally {
      collector.stop(true);
      unlinkSync(path);
      rmdirSync(dir);
    }
  });

  it("sends one OTLP/JSON request over HTTP whose span is named by the mapping", async () => {
    const bodies: OtlpRequest[] = [];
    const collector = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(req) {
        bodies.push((await req.json()) as OtlpRequest);
        return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
      },
    });
    const exporter = createOtelTraceExporter({ endpoint: `http://127.0.0.1:${collector.port}/v1/traces`, methodsEvaluated: METHODS_EVALUATED });
    try {
      exporter.end(exporter.start(toolCallEnvelope("ls", { id: 1 }), "steps/toolCallRequest", TRUSTED), decisionResponse(1, { decision: "allow" }));
      await exporter.flush();
      await exporter.shutdown();

      expect(bodies).toHaveLength(1);
      expect(otlpSpans(bodies).map((span) => span.name)).toEqual([TOOL_CALL_SPAN.span_name]);
    } finally {
      collector.stop(true);
    }
  });

  it("carries provenance facts as one column per attribute, one element per Provenance object, in argument order", async () => {
    const { exporter, spans } = memoryExporter();
    const request = makeEnvelope(
      "steps/toolCallRequest",
      {
        tool: { name: "run_shell" },
        capability: "process.exec",
        arguments: {
          command: { value: "ls", provenance: provenance("user_input", { source_id: "user-1" }) },
          cwd: { value: "/tmp", provenance: provenance("tool_output", { source_id: "run_shell" }) },
          // No provenance: contributes no element to any column.
          flags: { value: "-la" },
        },
      },
      { id: 1 },
    );
    exporter.end(exporter.start(request, "steps/toolCallRequest", TRUSTED), decisionResponse(1, { decision: "allow" }));
    await exporter.flush();

    const attributes = spans()[0]?.attributes;
    expect(attributes?.["acs.provenance.origin"]).toEqual(["user_input", "tool_output"]);
    expect(attributes?.["acs.provenance.source_id"]).toEqual(["user-1", "run_shell"]);
  });

  it("pads acs.provenance.source_id to the length of acs.provenance.origin with \"\"", async () => {
    const { exporter, spans } = memoryExporter();
    const request = makeEnvelope(
      "steps/toolCallRequest",
      {
        tool: { name: "run_shell" },
        arguments: {
          command: { value: "ls", provenance: provenance("user_input", { source_id: "user-1" }) },
          cwd: { value: "/tmp", provenance: provenance("system") },
        },
      },
      { id: 1 },
    );
    exporter.end(exporter.start(request, "steps/toolCallRequest", TRUSTED), decisionResponse(1, { decision: "allow" }));
    await exporter.flush();

    const attributes = spans()[0]?.attributes;
    expect(attributes?.["acs.provenance.origin"]).toEqual(["user_input", "system"]);
    expect(attributes?.["acs.provenance.source_id"]).toEqual(["user-1", ""]);
  });

  it("carries no provenance attribute when nothing in the payload has one", async () => {
    const { exporter, spans } = memoryExporter();
    exporter.end(exporter.start(toolCallEnvelope("ls", { id: 1 }), "steps/toolCallRequest", TRUSTED), decisionResponse(1, { decision: "allow" }));
    await exporter.flush();

    const attributes = spans()[0]?.attributes ?? {};
    expect(Object.keys(attributes).filter((key) => key.startsWith("acs.provenance."))).toEqual([]);
  });

  it("reads output provenance on the result gate the same way, in array order", async () => {
    const { exporter, spans } = memoryExporter();
    const request = makeEnvelope(
      "steps/toolCallResult",
      {
        tool: { name: "Bash" },
        exit_status: "success",
        outputs: [{ value: "a", provenance: provenance("tool_output", { source_id: "Bash" }) }, { value: "b" }],
      },
      { id: 1 },
    );
    exporter.end(exporter.start(request, "steps/toolCallResult", TRUSTED), decisionResponse(1, { decision: "allow" }));
    await exporter.flush();

    const [span] = spans();
    expect(span?.name).toBe(MAPPING.stepToSpan["steps/toolCallResult"]!.span_name);
    expect(span?.attributes["acs.provenance.origin"]).toEqual(["tool_output"]);
    expect(span?.attributes["acs.provenance.source_id"]).toEqual(["Bash"]);
  });

  // The file exporter on its own: two exports handed over back to back,
  // without waiting between them, land as two lines in export order. The
  // append is asynchronous, so order is a property the chain has to keep.
  it("writes two exports as two lines, in export order", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-otel-file-order-"));
    const path = join(dir, "traces.jsonl");
    const { exporter, spans } = memoryExporter();
    const first = crypto.randomUUID();
    const second = crypto.randomUUID();
    exporter.end(exporter.start(toolCallEnvelope("ls", { id: 1, requestId: first }), "steps/toolCallRequest", TRUSTED), decisionResponse(1, { decision: "allow" }));
    exporter.end(exporter.start(toolCallEnvelope("ls", { id: 2, requestId: second }), "steps/toolCallRequest", TRUSTED), decisionResponse(2, { decision: "allow" }));
    await exporter.flush();
    const [spanA, spanB] = spans();
    try {
      const file = createFileSpanExporter(path);
      const results = await Promise.all([
        new Promise<number>((resolve) => file.export([spanA!], (result) => resolve(result.code))),
        new Promise<number>((resolve) => file.export([spanB!], (result) => resolve(result.code))),
      ]);
      await file.shutdown();

      expect(results).toEqual([0, 0]);
      const lines = otlpFile(path).map((request) => otlpSpans([request]).map((span) => otlpAttribute(span, "acs.request_id")));
      expect(lines).toEqual([[first], [second]]);
    } finally {
      await exporter.shutdown();
      unlinkSync(path);
      rmdirSync(dir);
    }
  });

  // The file holds reasoning text and provenance source ids (#71), so it is
  // created readable by its owner only, and so is the directory the
  // exporter makes for it.
  it("creates the file 0600 and its directory 0700", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-otel-file-mode-"));
    const nested = join(dir, "nested");
    const path = join(nested, "traces.jsonl");
    const exporter = createOtelTraceExporter({ filePath: path, methodsEvaluated: METHODS_EVALUATED });
    try {
      exporter.end(exporter.start(toolCallEnvelope("ls", { id: 1 }), "steps/toolCallRequest", TRUSTED), decisionResponse(1, { decision: "allow" }));
      await exporter.shutdown();

      expect((statSync(nested).mode & 0o777).toString(8)).toBe("700");
      expect((statSync(path).mode & 0o777).toString(8)).toBe("600");
    } finally {
      unlinkSync(path);
      rmdirSync(nested);
      rmdirSync(dir);
    }
  });

  // SIGINT followed by SIGTERM is two calls to close(). The second must
  // wait for the first's flush to finish, not return at once and let the
  // process exit in the middle of it.
  it("makes a second shutdown() call wait for the first", async () => {
    let shutDown = false;
    const slow: SpanExporter = {
      export(_spans, resultCallback): void {
        resultCallback({ code: 0 });
      },
      async shutdown(): Promise<void> {
        await Bun.sleep(150);
        shutDown = true;
      },
    };
    const exporter = createOtelTraceExporter({ spanExporter: slow, methodsEvaluated: METHODS_EVALUATED });
    exporter.end(exporter.start(toolCallEnvelope("ls", { id: 1 }), "steps/toolCallRequest", TRUSTED), decisionResponse(1, { decision: "allow" }));

    const first = exporter.shutdown();
    const second = exporter.shutdown();
    await second;

    expect(shutDown).toBe(true);
    await first;
  });

  // #227 moves acs.capability into a per-span conditional_attributes list.
  // A small mapping of this test's own proves the exporter reads that list;
  // the real-mapping test below proves the sources cover whatever the real
  // file lists.
  it("emits an attribute a step_to_span entry lists under conditional_attributes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-otel-conditional-"));
    const mappingPath = join(dir, "otel-mapping.json");
    writeFileSync(
      mappingPath,
      JSON.stringify({
        properties: {
          step_to_span: {
            default: {
              "steps/toolCallRequest": {
                span_name: "test.tool.call",
                required_attributes: ["gen_ai.tool.name"],
                conditional_attributes: ["acs.capability"],
              },
            },
          },
          decision_event: {
            properties: {
              event_name: { const: "acs.decision" },
              required_attributes: { default: ["acs.decision"] },
              conditional_attributes: { default: [] },
            },
          },
          provenance_attributes: { properties: { required: { default: [] }, optional: { default: [] } } },
        },
      }),
    );
    try {
      const { exporter, spans } = memoryExporter({ mappingPath });
      exporter.end(exporter.start(toolCallEnvelope("ls", { id: 1 }), "steps/toolCallRequest", TRUSTED), decisionResponse(1, { decision: "allow" }));
      await exporter.flush();

      const [span] = spans();
      expect(span?.name).toBe("test.tool.call");
      expect(span?.attributes["gen_ai.tool.name"]).toBe("run_shell");
      expect(span?.attributes["acs.capability"]).toBe("process.exec");
    } finally {
      unlinkSync(mappingPath);
      rmdirSync(dir);
    }
  });

  // Against the real mapping, not a fixture: a name the mapping lists for
  // an evaluated method, in any of its three lists, must have a source here,
  // or that attribute quietly stops appearing when the mapping changes --
  // which is what #227's conditional_attributes would have done.
  it("has a source for every attribute the real mapping lists on an evaluated method, and for every decision attribute", () => {
    for (const method of METHODS_EVALUATED) {
      const entry = MAPPING.stepToSpan[method];
      if (entry === undefined) {
        continue;
      }
      const listed = [...entry.required_attributes, ...(entry.conditional_attributes ?? []), ...(entry.optional_attributes ?? [])];
      for (const attribute of listed) {
        expect({ method, attribute, known: attribute in STEP_ATTRIBUTE_SOURCES }).toEqual({ method, attribute, known: true });
      }
    }
    for (const attribute of MAPPING.decisionAttributes) {
      expect({ attribute, known: attribute in DECISION_ATTRIBUTE_SOURCES }).toEqual({ attribute, known: true });
    }
  });

  it("maps every method the ServerHello evaluates, or names it in METHODS_WITHOUT_SPAN with a reason", () => {
    for (const method of METHODS_EVALUATED) {
      const mapped = MAPPING.stepToSpan[method] !== undefined;
      const listed = typeof METHODS_WITHOUT_SPAN[method] === "string" && METHODS_WITHOUT_SPAN[method].length > 0;
      expect({ method, mappedOrListed: mapped || listed }).toEqual({ method, mappedOrListed: true });
    }
  });

  it("NULL_OTEL_TRACE_EXPORTER writes nothing and never throws", async () => {
    expect(NULL_OTEL_TRACE_EXPORTER.start(toolCallEnvelope("ls"), "steps/toolCallRequest", TRUSTED)).toBeNull();
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
      // This Guardian sends metadata.evaluator once #229 lands; until then
      // the event carries none, rather than one the exporter made up.
      expect(event?.attributes?.["acs.evaluator"]).toBeUndefined();
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
  // Every span a real Guardian emits is named by the mapping: one of its
  // step_to_span span_name values, never a name this module made up.
  it("names every emitted span with a span_name from step_to_span", async () => {
    const { exporter, spans } = memoryExporter();
    const guardian = await startGuardian({ ...baseOptions, traceExporter: exporter });
    try {
      await postRaw(guardian.url, toolCallEnvelope("ls -la", { id: 1 }));
      await postRaw(
        guardian.url,
        makeEnvelope("steps/toolCallResult", { tool: { name: "Bash" }, exit_status: "success", outputs: [{ value: "ok" }] }, { id: 2 }),
      );
      await exporter.flush();

      const names = new Set(Object.values(MAPPING.stepToSpan).map((entry) => entry.span_name));
      expect(spans()).toHaveLength(2);
      for (const span of spans()) {
        expect({ span: span.name, mapped: names.has(span.name) }).toEqual({ span: span.name, mapped: true });
      }
    } finally {
      await guardian.close();
    }
  });

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

  // `capability` is optional on the wire (#227) and required on the span by
  // the mapping. The exporter emits what the envelope supplies and invents
  // nothing: no capability, no acs.capability, and the span is otherwise whole.
  it("emits a span without acs.capability for a request that carries no capability, and nothing breaks", async () => {
    const { exporter, spans } = memoryExporter();
    const guardian = await startGuardian({ ...baseOptions, traceExporter: exporter });
    try {
      const response = await postRaw(
        guardian.url,
        makeEnvelope("steps/toolCallRequest", { tool: { name: "run_shell" }, arguments: { command: { value: "ls -la" } } }, { id: 1 }),
      );
      await exporter.flush();

      expect((response.result as { decision?: string }).decision).toBe("allow");
      const [span] = spans();
      expect(span?.name).toBe(TOOL_CALL_SPAN.span_name);
      expect(span?.attributes["gen_ai.tool.name"]).toBe("run_shell");
      expect(span?.attributes["acs.capability"]).toBeUndefined();
      expect(span?.events[0]?.attributes?.["acs.decision"]).toBe("allow");
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

  // Trace Events (PR #273): a Guardian MUST NOT emit acs.decision, or
  // acs.decision.failure, under the pair of a request it rejects before
  // trusting it, because such a request can carry any pair, a genuine
  // request's included. Issue #283 ruled that it is still recorded, apart,
  // under names outside step_to_span, so the attack stays visible.
  it("records a schema-invalid steps/* envelope as a rejected request, and still answers it with a deny", async () => {
    const { exporter, spans } = memoryExporter();
    const guardian = await startGuardian({ ...baseOptions, traceExporter: exporter });
    try {
      const bad = toolCallEnvelope("rm -rf /", { id: 12 });
      delete (bad.params as Record<string, unknown>).acs_version;
      const answer = await postRaw(guardian.url, bad);
      await exporter.flush();

      // The host still gets its honoured deny. Only the trace changes.
      expect((answer.result as { decision?: string } | undefined)?.decision).toBe("deny");
      const [span] = spans();
      expect(spans()).toHaveLength(1);
      expect(span?.name).toBe(REJECTED_SPAN_NAME);
      expect(span?.attributes["acs.session.id"]).toBeUndefined();
      expect(span?.attributes["acs.request_id"]).toBeUndefined();
      expect(span?.attributes["guardian.rejected.reason"]).toBe("envelope_invalid");
      expect(span?.events).toEqual([]);
    } finally {
      await guardian.close();
    }
  });

  // The forgery here fails the schema. One that passes it is still recorded
  // as a step: this Guardian verifies no signature, replay or timestamp yet.
  for (const order of ["genuine first", "forgery first"] as const) {
    it(`keeps a genuine request the only span under its pair when a schema-invalid request forges it (${order})`, async () => {
      const { exporter, spans } = memoryExporter();
      const guardian = await startGuardian({ ...baseOptions, traceExporter: exporter });
      try {
        const requestId = crypto.randomUUID();
        const sessionId = crypto.randomUUID();
        const genuine = toolCallEnvelope("ls -la", { id: 1, requestId, sessionId });
        const forged = toolCallEnvelope("rm -rf /", { id: 2, requestId, sessionId });
        delete (forged.params as Record<string, unknown>).acs_version;
        for (const envelope of order === "genuine first" ? [genuine, forged] : [forged, genuine]) {
          await postRaw(guardian.url, envelope);
        }
        await exporter.flush();

        const underPair = spans().filter(
          (span) => span.attributes["acs.request_id"] === requestId && span.attributes["acs.session.id"] === sessionId,
        );
        expect(underPair).toHaveLength(1);
        expect(underPair[0]?.events.map((event) => event.attributes?.["acs.decision"])).toEqual(["allow"]);
        const rejected = spans().filter((span) => span.name === REJECTED_SPAN_NAME);
        expect(rejected).toHaveLength(1);
        expect(rejected[0]?.attributes["guardian.rejected.claimed_request_id"]).toBe(requestId);
      } finally {
        await guardian.close();
      }
    });
  }

  it("records a schema-invalid envelope for a method it does not dispatch as a rejected request too", async () => {
    const { exporter, spans } = memoryExporter();
    const guardian = await startGuardian({ ...baseOptions, traceExporter: exporter });
    try {
      const bad = makeEnvelope("steps/sessionStart", {}, { id: 44 });
      delete (bad.params as Record<string, unknown>).acs_version;
      await postRaw(guardian.url, bad);
      await exporter.flush();

      expect(spans().map((span) => span.name)).toEqual([REJECTED_SPAN_NAME]);
    } finally {
      await guardian.close();
    }
  });

  it("records an invalid envelope answered with a bare error as a rejected request, with no decision failure", async () => {
    const { exporter, spans } = memoryExporter();
    const guardian = await startGuardian({ ...baseOptions, traceExporter: exporter });
    try {
      // No request_id and no JSON-RPC id: denyOnInvalidEnvelope cannot address
      // a decision, so the Guardian answers with a JSON-RPC error instead.
      const bad = toolCallEnvelope("ls", { id: null });
      delete (bad.params as Record<string, unknown>).request_id;
      await postRaw(guardian.url, bad);
      await exporter.flush();

      const [span] = spans();
      expect(span?.name).toBe(REJECTED_SPAN_NAME);
      expect(span?.events).toEqual([]);
      expect(span?.attributes["guardian.rejected.error_code"]).toBe(-32010);
    } finally {
      await guardian.close();
    }
  });

  it("carries the provenance a real envelope's argument attaches", async () => {
    const { exporter, spans } = memoryExporter();
    const guardian = await startGuardian({ ...baseOptions, traceExporter: exporter });
    try {
      const envelope = makeEnvelope(
        "steps/toolCallRequest",
        {
          tool: { name: "run_shell" },
          arguments: { command: { value: "ls -la", provenance: provenance("user_input", { source_id: "user-12345" }) } },
        },
        { id: 31 },
      );
      const response = await postRaw(guardian.url, envelope);
      await exporter.flush();

      expect((response.result as { decision?: string }).decision).toBe("allow");
      const [span] = spans();
      expect(span?.attributes["acs.provenance.origin"]).toEqual(["user_input"]);
      expect(span?.attributes["acs.provenance.source_id"]).toEqual(["user-12345"]);
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

  it("adds no failure event to a decision that arrives in time", async () => {
    const memory = new InMemorySpanExporter();
    const exporter = createOtelTraceExporter({
      spanExporter: memory,
      methodsEvaluated: METHODS_EVALUATED,
      timeoutConfig: { default_ms: 5000 },
      posture: "fail_open",
    });
    const guardian = await startGuardian({ ...baseOptions, traceExporter: exporter });
    try {
      await postRaw(guardian.url, toolCallEnvelope("ls -la", { id: 1 }));
      await exporter.flush();

      const [span] = memory.getFinishedSpans();
      expect(span?.events.map((event) => event.name)).toEqual([MAPPING.decisionEventName]);
    } finally {
      await guardian.close();
    }
  });

  // The second failure a Guardian can see itself: a decision that finished
  // after the host stopped waiting. The host applied its posture at the
  // timeout, so the decision on the span probably never took effect, and a
  // reader has to be told. A 50 ms timeout against a 200 ms bridge keeps
  // the test fast and the ordering certain.
  it("adds a timeout failure event when the decision finishes after the negotiated timeout", async () => {
    const memory = new InMemorySpanExporter();
    const exporter = createOtelTraceExporter({
      spanExporter: memory,
      methodsEvaluated: METHODS_EVALUATED,
      timeoutConfig: { default_ms: 50 },
      posture: "fail_open",
    });
    const slow: PolicyBridge<GuardianSnapshot> = {
      async evaluate() {
        await Bun.sleep(200);
        return { decision: "allow" };
      },
    };
    const guardian = await startGuardian({ ...baseOptions, bridge: slow, traceExporter: exporter });
    try {
      await postRaw(guardian.url, toolCallEnvelope("ls -la", { id: 1 }));
      await exporter.flush();

      const [span] = memory.getFinishedSpans();
      expect(span?.events.map((event) => event.name)).toEqual([MAPPING.decisionEventName, "acs.decision.failure"]);
      const failure = span?.events[1]?.attributes;
      expect(failure?.["acs.failure.class"]).toBe("timeout");
      expect(failure?.["acs.failure.timeout_ms"]).toBe(50);
      expect(failure?.["acs.failure.elapsed_ms"]).toBeGreaterThanOrEqual(200);
      expect(failure?.["acs.failure.posture"]).toBe("fail_open");
      expect(failure?.["acs.failure.reported_by"]).toBe("guardian");
      expect(failure?.["acs.failure.payload_bytes"]).toBeGreaterThan(0);
    } finally {
      await guardian.close();
    }
  });

  // A bridge that never answers leaves the span open, and an open span is
  // never exported: the step would leave no trace at all. Shutdown closes
  // it with an `other` failure event that says why. close() drains for the
  // negotiated timeout (5 s in the ServerHello) before it gives up on the
  // handler, which is what bounds this test.
  it("closes a step still open at shutdown with an other failure event and ERROR status", async () => {
    // The file, not an in-memory exporter: close() shuts the provider down,
    // and InMemorySpanExporter forgets its spans when it is shut down.
    const dir = mkdtempSync(join(tmpdir(), "acs-otel-open-at-shutdown-"));
    const path = join(dir, "traces.jsonl");
    const exporter = createOtelTraceExporter({ filePath: path, methodsEvaluated: METHODS_EVALUATED, posture: "fail_open" });
    let reached: () => void = () => {};
    const reachedBridge = new Promise<void>((resolve) => {
      reached = resolve;
    });
    const silent: PolicyBridge<GuardianSnapshot> = {
      evaluate() {
        reached();
        return new Promise(() => {});
      },
    };
    const guardian = await startGuardian({ ...baseOptions, bridge: silent, traceExporter: exporter });
    const pending = postRaw(guardian.url, toolCallEnvelope("ls -la", { id: 1 })).catch(() => undefined);
    try {
      await reachedBridge;
      const closeStarted = performance.now();
      await guardian.close();
      const closeMs = performance.now() - closeStarted;
      // The request is answered by the server going away, never by a
      // decision; bounded so a connection that lingers cannot hang the test.
      await Promise.race([pending, Bun.sleep(2000)]);

      const spans = otlpSpans(otlpFile(path));
      expect(spans).toHaveLength(1);
      expect(spans[0]?.status?.code).toBe(2);
      expect(spans[0]?.events?.map((event) => event.name)).toEqual(["acs.decision.failure"]);
      const failure = spans[0]?.events?.[0];
      expect(otlpAttribute(failure, "acs.failure.class")).toBe("other");
      expect(typeof otlpAttribute(failure, "acs.failure.detail")).toBe("string");
      expect(otlpAttribute(failure, "acs.failure.reported_by")).toBe("guardian");
      expect(closeMs).toBeLessThan(10000);
    } finally {
      unlinkSync(path);
      rmdirSync(dir);
    }
  }, 15_000);

  // Ariel's review on PR #286: close() applies the same bounded drain with
  // export off as with it on, since the null exporter's shutdown resolves at
  // once. Before, a Guardian with export off waited on stop(true) alone. On
  // Bun 1.3.11 that waits for every in-flight handler, and a handler whose
  // bridge never answers never returns, so close() hung. Bun 1.3.14 resolves
  // stop(true) at once, and there this test passes either way.
  it("closes in bounded time with export off while a step is still in flight", async () => {
    let reached: () => void = () => {};
    const reachedBridge = new Promise<void>((resolve) => {
      reached = resolve;
    });
    const silent: PolicyBridge<GuardianSnapshot> = {
      evaluate() {
        reached();
        return new Promise(() => {});
      },
    };
    const guardian = await startGuardian({ ...baseOptions, bridge: silent });
    const pending = postRaw(guardian.url, toolCallEnvelope("ls -la", { id: 1 })).then(
      () => "answered",
      () => "connection closed",
    );
    await reachedBridge;
    const closeStarted = performance.now();
    await guardian.close();
    const closeMs = performance.now() - closeStarted;
    // The request is never decided. It ends because the server went away.
    expect(await Promise.race([pending, Bun.sleep(2000).then(() => "still open")])).toBe("connection closed");
    // At most the ServerHello's default timeout, 5 s: past it, no host is
    // still waiting for the answer.
    expect(closeMs).toBeLessThan(buildServerHello().timeout_config.default_ms + 1000);
  }, 15_000);

  // server.ts builds the exporter from the ServerHello, so the posture on a
  // failure event is the one this Guardian declared to the host. The failure
  // here is a decision that finished after the ServerHello's own timeout, on
  // a request the Guardian trusted, through the file path production uses.
  // An invalid envelope would not do: a request rejected before it is
  // trusted gets no failure event at all (see the schema-invalid case above).
  it("reports the ServerHello's posture on a failure event: a Guardian declaring deny says fail_closed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-otel-posture-"));
    const path = join(dir, "traces.jsonl");
    const late: PolicyBridge<GuardianSnapshot> = {
      async evaluate() {
        await Bun.sleep(buildServerHello().timeout_config.default_ms + 200);
        return { decision: "allow" };
      },
    };
    const guardian = await startGuardian({ ...baseOptions, bridge: late, onDecisionFailure: "deny", otelTraceFile: path });
    try {
      const response = await postRaw(guardian.url, toolCallEnvelope("ls -la", { id: 1 }));
      expect(response.result).toBeDefined();
    } finally {
      await guardian.close();
    }
    try {
      const [span] = otlpSpans(otlpFile(path));
      const failure = span?.events?.find((event) => event.name === "acs.decision.failure");
      expect(otlpAttribute(failure, "acs.failure.class")).toBe("timeout");
      expect(otlpAttribute(failure, "acs.failure.posture")).toBe("fail_closed");
      expect(otlpAttribute(failure, "acs.failure.reported_by")).toBe("guardian");
    } finally {
      unlinkSync(path);
      rmdirSync(dir);
    }
  }, 15_000);

  // A collector that is down must cost the endpoint and nothing else. The
  // real OTLPTraceExporter against a closed port, not the throwing stub: a
  // real collector fails late, after the exporter's retry budget (a refused
  // connection is retryable in this exporter), and the stub never walked
  // that path. Port 1 is closed on any normal machine.
  it("keeps the file running after the HTTP endpoint dies, answers as with export off, and closes in bounded time", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-otel-dead-endpoint-"));
    const path = join(dir, "traces.jsonl");
    const errors: unknown[] = [];
    const exporter = createOtelTraceExporter({
      filePath: path,
      endpoint: "http://127.0.0.1:1/v1/traces",
      methodsEvaluated: METHODS_EVALUATED,
      onError: (error) => errors.push(error),
    });
    const exporting = await startGuardian({ ...baseOptions, traceExporter: exporter });
    const silent = await startGuardian(baseOptions);
    let exportingClosed = false;
    try {
      // Decisions are the same as with export off, before the endpoint dies.
      for (const envelope of [toolCallEnvelope("rm -rf /", { id: 1 }), toolCallEnvelope("ls -la", { id: 2 })]) {
        expect(await postRaw(exporting.url, envelope)).toEqual(await postRaw(silent.url, envelope));
      }
      // flush() returns once every output has answered, and the dead
      // endpoint answers only when it gives up -- so this is where its
      // death is reported, and how long that took.
      const flushStarted = performance.now();
      await exporter.flush();
      const flushMs = performance.now() - flushStarted;
      expect(errors).toHaveLength(1);

      // And the same again, after the endpoint died.
      const after = [crypto.randomUUID(), crypto.randomUUID()];
      for (const [index, requestId] of after.entries()) {
        const envelope = toolCallEnvelope("ls -la", { id: 10 + index, requestId });
        expect(await postRaw(exporting.url, envelope)).toEqual(await postRaw(silent.url, envelope));
      }
      const closeStarted = performance.now();
      await exporting.close();
      exportingClosed = true;
      const closeMs = performance.now() - closeStarted;

      // The file holds every span, the two sent after the endpoint failed
      // included -- the assertion that fails when one dead output stops the
      // others.
      const requestIds = otlpSpans(otlpFile(path)).map((span) => otlpAttribute(span, "acs.request_id"));
      expect(requestIds).toHaveLength(4);
      for (const requestId of after) {
        expect(requestIds).toContain(requestId);
      }
      expect(errors).toHaveLength(1);
      // Bounded: the endpoint gives up within its own short timeout, not the
      // exporter's 10 s default, and closing never waits that budget again.
      expect(flushMs).toBeLessThan(5000);
      expect(closeMs).toBeLessThan(5000);
    } finally {
      if (!exportingClosed) {
        await exporting.close();
      }
      await silent.close();
      unlinkSync(path);
      rmdirSync(dir);
    }
  }, 20_000);

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
      const requests = otlpFile(path);
      expect(requests.length).toBeGreaterThan(0);
      const spans = otlpSpans(requests);
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

// Review fixes on PR #244. Each test names the finding it pins.
describe("createOtelTraceExporter -- review fixes", () => {
  const SENTINEL = "SENTINEL-/Users/alice/.secrets/token";

  // #228: acs.failure.detail MUST be text the emitter composes itself, and
  // never bytes copied from a response or an error. The span status is held
  // to the same rule, since it lands in the same backend.
  it("copies no JSON-RPC error text into the failure event or the span status, and keeps the code", async () => {
    const { exporter, spans } = memoryExporter();
    exporter.end(exporter.start(toolCallEnvelope("ls", { id: 3 }), "steps/toolCallRequest", TRUSTED), {
      jsonrpc: "2.0",
      id: 3,
      error: { code: -32020, message: `evaluation failed: ${SENTINEL}` },
    });
    await exporter.flush();

    const [span] = spans();
    expect(JSON.stringify(span?.events)).not.toContain("SENTINEL");
    expect(span?.status.message ?? "").not.toContain("SENTINEL");
    expect(span?.events[0]?.attributes?.["acs.failure.error_code"]).toBe(-32020);
    expect(span?.events[0]?.attributes?.["acs.failure.detail"]).toBeUndefined();
  });

  // #228 and PR #273: a request rejected before it was trusted gets no
  // acs.decision.failure under its pair, because the pair may be a genuine
  // request's. That holds even when the check ran after the span opened, as
  // a signature, replay or timestamp check inside dispatch would: the span
  // ends as a rejected request, renamed and without the pair.
  for (const [code, reason] of [
    [-32004, "signature_invalid"],
    [-32005, "replay_detected"],
    [-32006, "timestamp_out_of_window"],
  ] as const) {
    it(`records a step answered with ${code} as a rejected request, without its pair`, async () => {
      const { exporter, spans } = memoryExporter();
      const requestId = crypto.randomUUID();
      exporter.end(exporter.start(toolCallEnvelope("ls", { id: 4, requestId }), "steps/toolCallRequest", TRUSTED), {
        jsonrpc: "2.0",
        id: 4,
        error: { code, message: "rejected" },
      });
      await exporter.flush();

      const [span] = spans();
      expect(span?.name).toBe(REJECTED_SPAN_NAME);
      expect(span?.events).toEqual([]);
      expect(span?.attributes["acs.request_id"]).toBeUndefined();
      expect(span?.attributes["acs.session.id"]).toBeUndefined();
      expect(span?.attributes["guardian.rejected.claimed_request_id"]).toBe(requestId);
      expect(span?.attributes["guardian.rejected.reason"]).toBe(reason);
      expect(span?.attributes["guardian.rejected.error_code"]).toBe(code);
    });
  }

  it("records a request the Guardian did not trust as a rejected request, with the reason it was given", async () => {
    const { exporter, spans } = memoryExporter();
    const requestId = crypto.randomUUID();
    const handle = exporter.start(toolCallEnvelope("ls", { id: 5, requestId }), "steps/toolCallRequest", {
      trusted: false,
      reason: "guardian_fault",
    });
    expect(handle).not.toBeNull();
    exporter.end(handle, { jsonrpc: "2.0", id: 5, error: { code: -32020, message: "schemas missing" } });
    await exporter.flush();

    const [span] = spans();
    expect(span?.name).toBe(REJECTED_SPAN_NAME);
    expect(span?.attributes["acs.request_id"]).toBeUndefined();
    expect(span?.attributes["guardian.rejected.claimed_request_id"]).toBe(requestId);
    expect(span?.attributes["guardian.rejected.reason"]).toBe("guardian_fault");
    expect(span?.status.code).toBe(SpanStatusCode.ERROR);
    // The host got an error, so the step went ungoverned: still a decision
    // failure, recorded on a span and event that carry no pair.
    expect(span?.events.map((event) => event.attributes?.["acs.failure.class"])).toEqual(["guardian_error"]);
    expect(span?.events[0]?.attributes?.["acs.request_id"]).toBeUndefined();
  });

  it("carries none of a rejected result's step attributes, so acs.request_id_ref cannot name the genuine call", async () => {
    const { exporter, spans } = memoryExporter();
    const genuineCall = crypto.randomUUID();
    const forgedResult = makeEnvelope(
      "steps/toolCallResult",
      { tool: { name: "run_shell" }, exit_status: "success", outputs: [{ value: "ok" }], request_id_ref: genuineCall },
      { id: 8 },
    );
    exporter.end(exporter.start(forgedResult, "steps/toolCallResult", TRUSTED), {
      jsonrpc: "2.0",
      id: 8,
      error: { code: -32005, message: "replay" },
    });
    await exporter.flush();

    const [span] = spans();
    expect(span?.name).toBe(REJECTED_SPAN_NAME);
    expect(span?.attributes["acs.request_id_ref"]).toBeUndefined();
    expect(span?.attributes["gen_ai.tool.name"]).toBeUndefined();
    expect(Object.keys(span?.attributes ?? {}).every((key) => key.startsWith("guardian.rejected."))).toBe(true);
  });

  it("records a step dispatch rejected as a rejected request even when it answered with a deny", async () => {
    const { exporter, spans } = memoryExporter();
    const handle = exporter.start(toolCallEnvelope("ls", { id: 9 }), "steps/toolCallRequest", TRUSTED);
    exporter.end(handle, decisionResponse(9, { decision: "deny", reason_codes: ["signature_invalid"] }), "signature_invalid");
    await exporter.flush();

    const [span] = spans();
    expect(span?.name).toBe(REJECTED_SPAN_NAME);
    expect(span?.events).toEqual([]);
    expect(span?.attributes["acs.request_id"]).toBeUndefined();
    expect(span?.attributes["guardian.rejected.reason"]).toBe("signature_invalid");
  });

  it("counts the time before the span opened toward a late decision", async () => {
    const { exporter, spans } = memoryExporter({ timeoutConfig: { default_ms: 50 } });
    const handle = exporter.start(toolCallEnvelope("ls", { id: 6 }), "steps/toolCallRequest", {
      trusted: true,
      receivedAt: performance.now() - 100,
    });
    exporter.end(handle, decisionResponse(6, { decision: "allow" }));
    await exporter.flush();

    const [span] = spans();
    const failure = span?.events.find((event) => event.name === "acs.decision.failure");
    expect(failure?.attributes?.["acs.failure.class"]).toBe("timeout");
    // The span starts at arrival too, so its own duration covers the 100 ms.
    const durationMs = (span?.duration[0] ?? 0) * 1000 + (span?.duration[1] ?? 0) / 1e6;
    expect(durationMs).toBeGreaterThanOrEqual(90);
  });

  // #228: acs.provenance.source_id is emitted only when at least one attached
  // Provenance object has a source_id.
  it("omits acs.provenance.source_id when no Provenance object carries one", async () => {
    const { exporter, spans } = memoryExporter();
    const envelope = makeEnvelope("steps/toolCallRequest", {
      tool: { name: "run_shell" },
      arguments: { a: { value: "x", provenance: provenance("tool_output") }, b: { value: "y", provenance: provenance("user_input") } },
    });
    exporter.end(exporter.start(envelope, "steps/toolCallRequest", TRUSTED), decisionResponse(1, DENY));
    await exporter.flush();

    const attributes = spans()[0]?.attributes;
    expect(attributes?.["acs.provenance.origin"]).toEqual(["tool_output", "user_input"]);
    expect(attributes?.["acs.provenance.source_id"]).toBeUndefined();
  });

  // Unbounded attribute values let one large request grow the Guardian's
  // memory without limit; a crash then fails open under the default posture.
  // Driven through start() directly, because the server's body cap would
  // refuse a request this large before any span existed.
  it("caps attribute values at 4096 characters and provenance columns at 64 entries", async () => {
    const { exporter, spans } = memoryExporter();
    const args: Record<string, unknown> = {};
    for (let i = 0; i < 200; i += 1) {
      args[`a${i}`] = { value: i, provenance: provenance("tool_output", { source_id: `s${i}` }) };
    }
    const envelope = makeEnvelope(
      "steps/toolCallRequest",
      { tool: { name: "run_shell" }, arguments: args },
      { sessionId: "x".repeat(10_000) },
    );
    exporter.end(exporter.start(envelope, "steps/toolCallRequest", TRUSTED), decisionResponse(1, DENY));
    await exporter.flush();

    expect(spans()).toHaveLength(1);
    const attributes = spans()[0]?.attributes;
    expect(String(attributes?.["acs.session.id"]).length).toBeLessThanOrEqual(4096);
    expect((attributes?.["acs.provenance.origin"] as string[]).length).toBe(64);
    expect((attributes?.["acs.provenance.source_id"] as string[]).length).toBe(64);
  });

  // A machine-wide OTEL_TRACES_SAMPLER or OTEL_SPAN_EVENT_COUNT_LIMIT must
  // not silently drop the Guardian's spans or its decision events.
  it("ignores sampler and event-limit environment variables", async () => {
    const saved = { sampler: process.env.OTEL_TRACES_SAMPLER, events: process.env.OTEL_SPAN_EVENT_COUNT_LIMIT };
    process.env.OTEL_TRACES_SAMPLER = "always_off";
    process.env.OTEL_SPAN_EVENT_COUNT_LIMIT = "0";
    try {
      const { exporter, spans } = memoryExporter();
      exporter.end(exporter.start(toolCallEnvelope("ls"), "steps/toolCallRequest", TRUSTED), decisionResponse(1, DENY));
      await exporter.flush();

      expect(spans()).toHaveLength(1);
      expect(spans()[0]?.events.map((event) => event.name)).toEqual([MAPPING.decisionEventName]);
    } finally {
      for (const [key, value] of [["OTEL_TRACES_SAMPLER", saved.sampler], ["OTEL_SPAN_EVENT_COUNT_LIMIT", saved.events]] as const) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
  });

  // A stalled output must not hold shutdown, and with it the process, open.
  it("bounds shutdown when an output never finishes, and reports it", async () => {
    const stuck: SpanExporter = {
      export(): void {},
      shutdown(): Promise<void> {
        return new Promise(() => {});
      },
    };
    const errors: unknown[] = [];
    const exporter = createOtelTraceExporter({
      spanExporter: stuck,
      methodsEvaluated: METHODS_EVALUATED,
      exportTimeoutMs: 100,
      onError: (error) => errors.push(error),
    });
    exporter.end(exporter.start(toolCallEnvelope("ls"), "steps/toolCallRequest", TRUSTED), decisionResponse(1, DENY));

    const started = performance.now();
    await exporter.shutdown();
    expect(performance.now() - started).toBeLessThan(2000);
    expect(errors.length).toBeGreaterThan(0);
  });

  // #228 moves the six decision extras into decision_event's own list. The
  // exporter has to emit them under both mappings, so #244 and #228 can land
  // in either order.
  it("emits the decision extras whether the mapping lists them or not", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-mapping-228-"));
    const path = join(dir, "otel-mapping.json");
    try {
      const schema = JSON.parse(
        readFileSync(new URL("../../../../../specification/v0.1.0/trace/otel-mapping.json", import.meta.url), "utf8"),
      ) as { properties: { decision_event: { properties: { conditional_attributes: { default: string[] } } } } };
      const extras = ["acs.reason_codes", "acs.policy.ids", "acs.policy.versions", "acs.policy.rule_ids", "acs.cited_provenance_ids", "acs.chain_hash"];
      const listed = schema.properties.decision_event.properties.conditional_attributes;
      listed.default = [...listed.default.filter((name) => !extras.includes(name)), ...extras];
      writeFileSync(path, JSON.stringify(schema));

      for (const attribute of loadOtelMapping(path).decisionAttributes) {
        expect({ attribute, known: attribute in DECISION_ATTRIBUTE_SOURCES }).toEqual({ attribute, known: true });
      }
      for (const mappingPath of [undefined, path]) {
        const { exporter, spans } = memoryExporter({ mappingPath });
        exporter.end(
          exporter.start(toolCallEnvelope("ls"), "steps/toolCallRequest", TRUSTED),
          decisionResponse(1, { ...DENY, reason_codes: ["blocked"], chain_hash: "a".repeat(64) }),
        );
        await exporter.flush();
        const event = spans()[0]?.events.find((e) => e.name === MAPPING.decisionEventName);
        expect(event?.attributes?.["acs.reason_codes"]).toEqual(["blocked"]);
        expect(event?.attributes?.["acs.chain_hash"]).toBe("a".repeat(64));
      }
    } finally {
      unlinkSync(path);
      rmdirSync(dir);
    }
  });
});

// Issue #274: nothing in the lab's shell changes what the Guardian exports.
describe("the Guardian's exporter does not depend on its environment", () => {
  const saved: Record<string, string | undefined> = {};
  const remember = (key: string): void => {
    if (!(key in saved)) saved[key] = process.env[key];
  };
  const setEnv = (values: Record<string, string>): void => {
    for (const [key, value] of Object.entries(values)) {
      remember(key);
      process.env[key] = value;
    }
  };
  const unsetEnv = (...keys: string[]): void => {
    for (const key of keys) {
      remember(key);
      delete process.env[key];
    }
  };
  /** A local stand-in for the collector that records what it receives. */
  const startCollector = () => {
    const received: { headers: Headers }[] = [];
    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(request) {
        // Copied now: Bun invalidates the Request once the handler returns,
        // and a header read after that comes back empty.
        received.push({ headers: new Headers(request.headers) });
        return new Response("{}", { headers: { "content-type": "application/json" } });
      },
    });
    return { server, received, url: `http://127.0.0.1:${server.port}/v1/traces` };
  };
  afterEach(() => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) {
        // Bun's HTTP client latches a proxy variable when it is set and does
        // not see it deleted, so every later fetch in this process would go
        // to the dead proxy. Assigning an empty value first clears it.
        // Seen on Bun 1.3.14 (the suite was also confirmed on 1.3.11).
        process.env[key] = "";
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  });

  const envelope = (id: number) => ({
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id,
    params: {
      acs_version: "0.1.0",
      request_id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "a", session_id: crypto.randomUUID() },
      payload: { tool: { name: "run_shell" }, capability: "process.exec", arguments: { command: { value: "ls" } } },
    },
  });
  const allow = (id: number) => ({ jsonrpc: "2.0", id, result: { type: "final", acs_version: "0.1.0", request_id: "r", decision: "allow" } });

  it("keeps every span when OTEL_BSP_MAX_QUEUE_SIZE is 1", async () => {
    setEnv({ OTEL_BSP_MAX_QUEUE_SIZE: "1" });
    const dir = mkdtempSync(join(tmpdir(), "acs-bsp-"));
    try {
      const path = join(dir, "trace.jsonl");
      const exporter = createOtelTraceExporter({ filePath: path, methodsEvaluated: METHODS_EVALUATED });
      // Three spans ended in one synchronous turn: with a queue of one, the
      // SDK's default-from-environment processor drops the ones that arrive
      // while the first export is in flight.
      for (const id of [1, 2, 3]) exporter.end(exporter.start(envelope(id), "steps/toolCallRequest", TRUSTED), allow(id));
      await exporter.shutdown();
      const spans = readFileSync(path, "utf8")
        .split("\n")
        .filter(Boolean)
        .flatMap((line) => JSON.parse(line).resourceSpans[0].scopeSpans[0].spans);
      expect(spans.length).toBe(3);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 10_000);

  it("keeps full ids, every attribute, and its own service.name under hostile limit and resource variables", async () => {
    // A guard, not a red test: the Guardian already set its limits in code.
    // It pins that the Task 1 refactor to the shared SPAN_LIMITS kept them.
    setEnv({
      OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT: "8",
      OTEL_SPAN_ATTRIBUTE_COUNT_LIMIT: "1",
      OTEL_SERVICE_NAME: "zzz",
      OTEL_RESOURCE_ATTRIBUTES: "service.name=evil",
    });
    const dir = mkdtempSync(join(tmpdir(), "acs-attr-"));
    try {
      const path = join(dir, "trace.jsonl");
      const exporter = createOtelTraceExporter({ filePath: path, methodsEvaluated: METHODS_EVALUATED });
      const request = envelope(1);
      exporter.end(exporter.start(request, "steps/toolCallRequest", TRUSTED), allow(1));
      await exporter.shutdown();
      const resourceSpans = JSON.parse(readFileSync(path, "utf8").split("\n")[0]!).resourceSpans[0];
      expect(resourceSpans.resource.attributes).toEqual([{ key: "service.name", value: { stringValue: OTEL_SERVICE_NAME } }]);
      const span = resourceSpans.scopeSpans[0].spans[0];
      expect(span.droppedAttributesCount ?? 0).toBe(0);
      expect(span.attributes.find((a: { key: string }) => a.key === "acs.request_id").value.stringValue).toBe(request.params.request_id);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 10_000);

  it("sends uncompressed JSON even when OTEL_EXPORTER_OTLP_COMPRESSION is gzip", async () => {
    setEnv({ OTEL_EXPORTER_OTLP_COMPRESSION: "gzip", OTEL_EXPORTER_OTLP_TRACES_COMPRESSION: "gzip" });
    const collector = startCollector();
    try {
      const exporter = createOtelTraceExporter({ endpoint: collector.url, methodsEvaluated: METHODS_EVALUATED });
      exporter.end(exporter.start(envelope(1), "steps/toolCallRequest", TRUSTED), allow(1));
      await exporter.shutdown();
      expect(collector.received.map((r) => r.headers.get("content-encoding"))).toEqual([null]);
    } finally {
      collector.server.stop(true);
    }
  }, 10_000);

  it("still sends headers from OTEL_EXPORTER_OTLP_TRACES_HEADERS, which the README lists as honored", async () => {
    // The SDK merges environment headers under any set in code, so they
    // cannot be refused. This pins today's behavior: if an SDK update changes
    // it, the README's sentence has to change with it.
    setEnv({ OTEL_EXPORTER_OTLP_TRACES_HEADERS: "x-acs-probe=1" });
    const collector = startCollector();
    try {
      const exporter = createOtelTraceExporter({ endpoint: collector.url, methodsEvaluated: METHODS_EVALUATED });
      exporter.end(exporter.start(envelope(1), "steps/toolCallRequest", TRUSTED), allow(1));
      await exporter.shutdown();
      expect(collector.received.map((r) => r.headers.get("x-acs-probe"))).toEqual(["1"]);
    } finally {
      collector.server.stop(true);
    }
  }, 10_000);

  // The exemption is main.ts's to apply (Ariel's review on PR #286), so this
  // test applies it the way main.ts does, before the exporter is built. It
  // runs in a fresh child for the reason the routing test further down
  // gives: Bun latches proxy variables across edits within a process. In
  // process, this test passed only when an earlier test had already put
  // 127.0.0.1 in NO_PROXY, and failed when run alone. Gated to Bun 1.3.14
  // and later, which honor a runtime edit; 1.3.11 reads the variables only
  // at startup, so main.ts's warning is what an operator gets there.
  it.skipIf(!Bun.semver.satisfies(Bun.version, ">=1.3.14"))(
    "sends to a loopback endpoint directly when HTTP_PROXY is set and the exemption is applied",
    async () => {
      // A proxy that only counts connections and never answers.
      let proxyConnections = 0;
      const proxy = createServer((socket) => {
        proxyConnections += 1;
        socket.destroy();
      });
      await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
      const proxyUrl = `http://127.0.0.1:${(proxy.address() as { port: number }).port}`;
      const source = new URL("../src/otel-trace-exporter.ts", import.meta.url).pathname;
      const script = `
        const { createOtelTraceExporter, keepLoopbackOffProxy } = await import(${JSON.stringify(source)});
        let collected = 0;
        const collector = Bun.serve({
          port: 0,
          hostname: "127.0.0.1",
          fetch() {
            collected += 1;
            return new Response("{}", { headers: { "content-type": "application/json" } });
          },
        });
        const endpoint = "http://127.0.0.1:" + collector.port + "/v1/traces";
        keepLoopbackOffProxy(endpoint, process.env);
        const exporter = createOtelTraceExporter({ endpoint, methodsEvaluated: ["steps/toolCallRequest"], onError: () => {} });
        exporter.end(exporter.start(${JSON.stringify(envelope(1))}, "steps/toolCallRequest", { trusted: true }), ${JSON.stringify(allow(1))});
        await exporter.shutdown();
        console.log(JSON.stringify({ collected }));
        collector.stop(true);
        process.exit(0);
      `;
      try {
        // Async spawn, so the proxy listener on this event loop can count
        // the child's connections.
        const child = Bun.spawn([process.execPath, "-e", script], {
          env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", HTTP_PROXY: proxyUrl, http_proxy: proxyUrl },
          stdout: "pipe",
        });
        const output = await new Response(child.stdout).text();
        await child.exited;
        const result = JSON.parse(output.trim().split("\n").pop()!);
        expect({ proxyConnections, collected: result.collected }).toEqual({ proxyConnections: 0, collected: 1 });
      } finally {
        proxy.close();
      }
    },
    10_000,
  );

  // Ariel's review on PR #286: the composition root owns the environment.
  // main.ts applies the loopback exemption, so an embedder that builds the
  // exporter itself decides whether its own environment changes.
  it("leaves NO_PROXY and no_proxy as they were when built for a loopback endpoint", async () => {
    unsetEnv("NO_PROXY", "no_proxy");
    const unset = createOtelTraceExporter({ endpoint: "http://127.0.0.1:4318/v1/traces", methodsEvaluated: METHODS_EVALUATED, onError: () => {} });
    await unset.shutdown();
    expect({ NO_PROXY: "NO_PROXY" in process.env, no_proxy: "no_proxy" in process.env }).toEqual({ NO_PROXY: false, no_proxy: false });

    setEnv({ NO_PROXY: "corp.internal", no_proxy: "corp.internal" });
    const set = createOtelTraceExporter({ endpoint: "http://127.0.0.1:4318/v1/traces", methodsEvaluated: METHODS_EVALUATED, onError: () => {} });
    await set.shutdown();
    expect([process.env.NO_PROXY, process.env.no_proxy]).toEqual(["corp.internal", "corp.internal"]);
  });
});

describe("keepLoopbackOffProxy", () => {
  const saved: Record<string, string | undefined> = {
    NO_PROXY: process.env.NO_PROXY,
    no_proxy: process.env.no_proxy,
  };
  const reset = (value: string | undefined): void => {
    for (const key of ["NO_PROXY", "no_proxy"]) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  };
  afterEach(() => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  it("adds localhost for a localhost endpoint", () => {
    reset(undefined);
    keepLoopbackOffProxy("http://localhost:4318/v1/traces", process.env);
    expect([process.env.NO_PROXY, process.env.no_proxy]).toEqual(["localhost", "localhost"]);
  });

  it("adds ::1 both bare and bracketed for an IPv6 loopback endpoint, because Bun matches only [::1]", () => {
    reset(undefined);
    keepLoopbackOffProxy("http://[::1]:4318/v1/traces", process.env);
    expect([process.env.NO_PROXY, process.env.no_proxy]).toEqual(["::1,[::1]", "::1,[::1]"]);
  });

  // Bar's finding on issue #274: Bun 1.3.14 reads a non-empty no_proxy in
  // preference to NO_PROXY, so creating the one the user did not set switches
  // off every exemption in the one they did.
  it("appends to NO_PROXY alone when only NO_PROXY is set, and does not create no_proxy", () => {
    reset(undefined);
    process.env.NO_PROXY = "corp.internal";
    keepLoopbackOffProxy("http://127.0.0.1:4318/v1/traces", process.env);
    expect(process.env.NO_PROXY).toBe("corp.internal,127.0.0.1");
    expect("no_proxy" in process.env).toBe(false);
  });

  it("appends to no_proxy alone when only no_proxy is set, and does not create NO_PROXY", () => {
    reset(undefined);
    process.env.no_proxy = "corp.internal";
    keepLoopbackOffProxy("http://127.0.0.1:4318/v1/traces", process.env);
    expect(process.env.no_proxy).toBe("corp.internal,127.0.0.1");
    expect("NO_PROXY" in process.env).toBe(false);
  });

  it("treats an empty no_proxy as unset, since Bun then falls back to NO_PROXY", () => {
    reset(undefined);
    process.env.NO_PROXY = "corp.internal";
    process.env.no_proxy = "";
    keepLoopbackOffProxy("http://127.0.0.1:4318/v1/traces", process.env);
    expect([process.env.NO_PROXY, process.env.no_proxy]).toEqual(["corp.internal,127.0.0.1", ""]);
  });

  it("fills a no_proxy that holds no entries, because Bun reads any non-empty value as the list", () => {
    for (const blank of [",", " ", " , "]) {
      reset(undefined);
      process.env.NO_PROXY = "corp.internal";
      process.env.no_proxy = blank;
      keepLoopbackOffProxy("http://127.0.0.1:4318/v1/traces", process.env);
      expect({ blank, NO_PROXY: process.env.NO_PROXY, no_proxy: process.env.no_proxy }).toEqual({
        blank,
        NO_PROXY: "corp.internal,127.0.0.1",
        no_proxy: "127.0.0.1",
      });
    }
  });

  it("sets both when neither is set, and appends once to each when both are set", () => {
    reset(undefined);
    keepLoopbackOffProxy("http://127.0.0.1:4318/v1/traces", process.env);
    expect([process.env.NO_PROXY, process.env.no_proxy]).toEqual(["127.0.0.1", "127.0.0.1"]);
    process.env.NO_PROXY = "a.internal";
    process.env.no_proxy = "b.internal";
    keepLoopbackOffProxy("http://127.0.0.1:4318/v1/traces", process.env);
    keepLoopbackOffProxy("http://127.0.0.1:4318/v1/traces", process.env);
    expect([process.env.NO_PROXY, process.env.no_proxy]).toEqual(["a.internal,127.0.0.1", "b.internal,127.0.0.1"]);
  });

  it("does not duplicate the entry when called twice", () => {
    reset(undefined);
    keepLoopbackOffProxy("http://127.0.0.1:4318/v1/traces", process.env);
    keepLoopbackOffProxy("http://127.0.0.1:4318/v1/traces", process.env);
    expect([process.env.NO_PROXY, process.env.no_proxy]).toEqual(["127.0.0.1", "127.0.0.1"]);
  });

  it("preserves existing entries", () => {
    reset("example.internal");
    keepLoopbackOffProxy("http://localhost:4318/v1/traces", process.env);
    expect([process.env.NO_PROXY, process.env.no_proxy]).toEqual(["example.internal,localhost", "example.internal,localhost"]);
  });

  it("leaves both variables exactly as they were for a non-loopback endpoint", () => {
    reset(undefined);
    keepLoopbackOffProxy("http://collector.example.com:4318/v1/traces", process.env);
    expect("NO_PROXY" in process.env).toBe(false);
    expect("no_proxy" in process.env).toBe(false);
    reset("example.internal");
    keepLoopbackOffProxy("http://collector.example.com:4318/v1/traces", process.env);
    expect([process.env.NO_PROXY, process.env.no_proxy]).toEqual(["example.internal", "example.internal"]);
  });
});

// Bun 1.3.11 reads the proxy variables only when the process starts, so the
// runtime edit above cannot help there. The warning is what every version
// gets: it judges the variables as they stand when the exporter is built.
describe("loopbackProxyWarning", () => {
  const endpoint = "http://127.0.0.1:4318/v1/traces";

  it("warns when a proxy is set and the list Bun reads does not exempt the host", () => {
    const warning = loopbackProxyWarning(endpoint, { HTTP_PROXY: "http://proxy:3128", NO_PROXY: "corp.internal" });
    expect(warning).toContain("127.0.0.1");
    expect(warning).toContain("NO_PROXY");
  });

  it("judges by no_proxy when it is non-empty, the list Bun reads first", () => {
    expect(loopbackProxyWarning(endpoint, { http_proxy: "http://proxy:3128", NO_PROXY: "127.0.0.1", no_proxy: "corp.internal" })).toBeDefined();
    expect(loopbackProxyWarning(endpoint, { http_proxy: "http://proxy:3128", NO_PROXY: "corp.internal", no_proxy: "127.0.0.1" })).toBeUndefined();
    expect(loopbackProxyWarning(endpoint, { http_proxy: "http://proxy:3128", NO_PROXY: "127.0.0.1", no_proxy: "" })).toBeUndefined();
  });

  it("stays quiet with no proxy, with a wildcard exemption, or for a non-loopback endpoint", () => {
    expect(loopbackProxyWarning(endpoint, {})).toBeUndefined();
    expect(loopbackProxyWarning(endpoint, { HTTP_PROXY: "http://proxy:3128", NO_PROXY: "*" })).toBeUndefined();
    expect(loopbackProxyWarning("http://collector.example.com:4318/v1/traces", { HTTP_PROXY: "http://proxy:3128" })).toBeUndefined();
  });

  it("wants the bracketed form for IPv6, the only one Bun matches", () => {
    const v6 = "http://[::1]:4318/v1/traces";
    expect(loopbackProxyWarning(v6, { HTTP_PROXY: "http://proxy:3128", NO_PROXY: "::1" })).toBeDefined();
    expect(loopbackProxyWarning(v6, { HTTP_PROXY: "http://proxy:3128", NO_PROXY: "[::1]" })).toBeUndefined();
  });
});

// Routing, not strings. It runs in a fresh child with its environment set at
// spawn, because Bun latches proxy variables across edits within a process,
// which makes any in-process routing check pass for the wrong reason. Bun
// 1.3.11 ignores runtime edits altogether, so this is gated to 1.3.14 and
// later, and CI on 1.3.11 skips it.
describe("keepLoopbackOffProxy, routed through a real proxy in a child process", () => {
  const runtimeEditsHonored = Bun.semver.satisfies(Bun.version, ">=1.3.14");

  it.skipIf(!runtimeEditsHonored)("keeps loopback off the proxy without switching off the user's existing NO_PROXY entries", async () => {
    let proxyConnections = 0;
    const proxy = createServer((socket) => {
      proxyConnections += 1;
      socket.destroy();
    });
    await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
    const proxyUrl = `http://127.0.0.1:${(proxy.address() as { port: number }).port}`;
    const source = new URL("../src/otel-trace-exporter.ts", import.meta.url).pathname;
    const script = `
      const { keepLoopbackOffProxy } = await import(${JSON.stringify(source)});
      const target = Bun.serve({ port: 0, hostname: "127.0.0.1", fetch: () => new Response("ok") });
      const go = async (host) => {
        try {
          const response = await fetch("http://" + host + ":" + target.port + "/", { signal: AbortSignal.timeout(1500) });
          return (await response.text()) === "ok" ? "direct" : "other";
        } catch {
          return "proxied";
        }
      };
      const guard = await go("127.0.0.1");
      keepLoopbackOffProxy("http://127.0.0.1:" + target.port + "/v1/traces", process.env);
      const loopback = await go("127.0.0.1");
      const existing = await go("localhost");
      console.log(JSON.stringify({ guard, loopback, existing }));
      target.stop(true);
      process.exit(0);
    `;
    try {
      // localhost stands in for a corporate host the user already exempted.
      // Async spawn, not spawnSync: the proxy listener runs on this process's
      // event loop and could not count the child's connection while blocked.
      const child = Bun.spawn([process.execPath, "-e", script], {
        env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", HTTP_PROXY: proxyUrl, http_proxy: proxyUrl, NO_PROXY: "localhost" },
        stdout: "pipe",
      });
      const output = await new Response(child.stdout).text();
      await child.exited;
      const result = JSON.parse(output.trim().split("\n").pop()!);
      // The guard proves the proxy was in the path before the call.
      expect(result).toEqual({ guard: "proxied", loopback: "direct", existing: "direct" });
      expect(proxyConnections).toBe(1);
    } finally {
      proxy.close();
    }
  }, 15_000);
});
