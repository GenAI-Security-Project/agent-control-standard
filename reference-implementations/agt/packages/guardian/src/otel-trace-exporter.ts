/**
 * createOtelTraceExporter emits one OpenTelemetry span per ACS step this
 * Guardian decides, so a reviewer can rebuild a session offline from a trace
 * file without reading the envelope log. Span names, the attributes each
 * span must and may carry, and the event a decision is recorded as all come
 * from `specification/v0.1.0/trace/otel-mapping.json`, read once at
 * construction. A rename in that mapping needs no change here.
 *
 * What the mapping does not say is which envelope field feeds which
 * attribute. That is the one piece of knowledge this module adds, in the
 * three source tables below, written once by hand. An attribute the mapping
 * names and no table knows is not emitted, and nothing is invented to fill a
 * slot the wire did not carry -- a required attribute the envelope lacks is
 * simply absent, which is itself a fact worth seeing.
 *
 * Span lifetime follows the envelope log. `start` is called where the
 * request is recorded and hands back the span; `end` is called with that
 * same handle where the response is recorded, at the same two call sites in
 * server.ts. The handle is what pairs them, never a lookup: a JSON-RPC id is
 * the client's, two sessions can reuse one at the same moment, and nothing
 * keyed on the id could tell their responses apart. Only a method that has a
 * `step_to_span` entry AND that this Guardian dispatches becomes a span;
 * `handshake/hello`, a method the Guardian does not dispatch, and an
 * unparseable body produce none, and `start` answers null for them.
 *
 * Off by default. With no file and no endpoint configured, startGuardian is
 * handed NULL_OTEL_TRACE_EXPORTER and behaves exactly as before.
 *
 * Total by construction, as envelope-log-sink.ts is. Every entry point is
 * wrapped: a failure disables export for the process lifetime and reports
 * once, and nothing propagates into or delays the decision path. Ended spans
 * go to a BatchSpanProcessor, so serialisation and I/O happen off the
 * request's own turn. Observability degrades; governance does not.
 */
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SpanStatusCode, type Attributes, type AttributeValue, type Span, type Tracer } from "@opentelemetry/api";
import { ExportResultCode } from "@opentelemetry/core";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { JsonTraceSerializer } from "@opentelemetry/otlp-transformer";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { BasicTracerProvider, BatchSpanProcessor, type SpanExporter } from "@opentelemetry/sdk-trace-base";

/** The `service.name` every span carries. The literal key rather than the
 * semantic-conventions package: one constant does not earn a dependency. */
export const OTEL_SERVICE_NAME = "acs-reference-guardian";

// The repository's own mapping, five directories up from this file -- the
// same relationship SCHEMA_ROOT in validate-envelope.ts relies on.
const OTEL_MAPPING_PATH = fileURLToPath(
  new URL("../../../../../specification/v0.1.0/trace/otel-mapping.json", import.meta.url),
);

/** What this Guardian's evaluator is, for the one attribute the mapping
 * requires on every decision event and the reference never puts on the
 * wire: every decision here is deterministic, read from `policy/manifest.yaml`
 * through the pinned bundle. Used only when the response carries no
 * `metadata.evaluator` of its own. */
const DEFAULT_EVALUATOR = "deterministic";

type StepSpanEntry = { span_name: string; required_attributes: string[]; optional_attributes?: string[] };

/** otel-mapping.json is a JSON Schema whose data lives inside `default`
 * keys -- the same three places `packages/conformance/src/trace-pillar.ts`
 * reads. This type names only those. */
type OtelMappingSchema = {
  properties: {
    step_to_span: { default: Record<string, StepSpanEntry> };
    decision_event: {
      properties: {
        event_name: { const: string };
        required_attributes: { default: string[] };
        conditional_attributes: { default: string[] };
      };
    };
  };
};

export type OtelMapping = {
  stepToSpan: Record<string, StepSpanEntry>;
  decisionEventName: string;
  /** The event's required attributes first, then its conditional ones. Both
   * are read the same way -- emitted when a value is present -- so one list
   * serves. */
  decisionAttributes: string[];
};

export function loadOtelMapping(path: string = OTEL_MAPPING_PATH): OtelMapping {
  const schema = JSON.parse(readFileSync(path, "utf8")) as OtelMappingSchema;
  const decision = schema.properties.decision_event.properties;
  return {
    stepToSpan: schema.properties.step_to_span.default,
    decisionEventName: decision.event_name.const,
    decisionAttributes: [...decision.required_attributes.default, ...decision.conditional_attributes.default],
  };
}

type JsonObject = Record<string, unknown>;

function asObject(value: unknown): JsonObject | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as JsonObject) : undefined;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

/** A non-empty array of strings, or nothing. An empty array is carried by
 * the wire (`policy_references: []` on an envelope-invalid deny) but says
 * nothing a reader can use, so it is not emitted. */
function asStrings(value: unknown): string[] | undefined {
  if (!Array.isArray(value) || value.length === 0) return undefined;
  return value.every((item) => typeof item === "string") ? (value as string[]) : undefined;
}

/**
 * One column of `policy_references`, in the wire's own order, and only when
 * every reference carries the field. A column with a gap cannot be lined up
 * against its siblings by position, and a placeholder would be a value nobody
 * sent -- so `acs.policy.versions` is absent whenever any reference omits
 * `policy_version`, while `acs.policy.ids` and `acs.policy.rule_ids` still
 * line up with each other.
 */
function policyColumn(references: unknown, field: string): string[] | undefined {
  if (!Array.isArray(references) || references.length === 0) return undefined;
  const column: string[] = [];
  for (const reference of references) {
    const value = asString(asObject(reference)?.[field]);
    if (value === undefined) return undefined;
    column.push(value);
  }
  return column;
}

/** The parts of a request envelope the source tables read. Read off the
 * parsed JSON rather than the validated envelope, because the span starts
 * before validation runs and an envelope that fails the schema is still a
 * step this session took. */
type RequestParts = { params: JsonObject; metadata: JsonObject; payload: JsonObject; tool: JsonObject };

function requestParts(envelope: unknown): RequestParts {
  const params = asObject(asObject(envelope)?.params) ?? {};
  const metadata = asObject(params.metadata) ?? {};
  const payload = asObject(params.payload) ?? {};
  const tool = asObject(payload.tool) ?? {};
  return { params, metadata, payload, tool };
}

/** The decision half of a success response: the `result` and its optional
 * `metadata`. `undefined` for a JSON-RPC error response, which carries no
 * decision. */
type ResultParts = { result: JsonObject; metadata: JsonObject };

function resultParts(response: unknown): ResultParts | undefined {
  const result = asObject(asObject(response)?.result);
  if (result === undefined) return undefined;
  return { result, metadata: asObject(result.metadata) ?? {} };
}

type Source<Parts> = (parts: Parts) => AttributeValue | undefined;

/**
 * Attribute name -> where it is read from on the request envelope, for every
 * attribute `step_to_span` can name on a span this Guardian emits. The
 * mapping decides WHICH of these a span carries; this table only says HOW
 * each one is read. Paths follow the hook payload schemas
 * (`hooks/tool-call-request.json`, `hooks/tool-call-result.json`) and
 * `request-envelope.json`'s `AcsParams.metadata`.
 */
const STEP_ATTRIBUTE_SOURCES: Record<string, Source<RequestParts>> = {
  "acs.session.id": (r) => asString(r.metadata.session_id),
  "acs.agent.id": (r) => asString(r.metadata.agent_id),
  "gen_ai.tool.name": (r) => asString(r.tool.name),
  "acs.tool.provider": (r) => asString(r.tool.provider),
  "acs.tool.version": (r) => asString(r.tool.version),
  "acs.capability": (r) => asString(r.payload.capability),
  "acs.operation": (r) => asString(r.payload.operation),
  "acs.exit_status": (r) => asString(r.payload.exit_status),
  "acs.duration_ms": (r) => asNumber(r.payload.duration_ms),
  "acs.request_id_ref": (r) => asString(r.payload.request_id_ref),
};

/**
 * Carried on every span, whatever the mapping lists for it, so a reader can
 * rebuild a session and pair each span with its two envelope-log lines.
 * `acs.session.id` is the mapping's own name for the session.
 * `acs.request_id` is this module's name for `params.request_id`, the ACS
 * correlation id the response echoes; the mapping has no attribute for the
 * step's own request id (its `acs.request_id_ref` names the request a
 * RESULT refers back to, which is a different fact).
 */
const CORRELATION_ATTRIBUTE_SOURCES: Record<string, Source<RequestParts>> = {
  "acs.session.id": (r) => asString(r.metadata.session_id),
  "acs.request_id": (r) => asString(r.params.request_id),
};

/**
 * The `acs.decision` event's attributes, for every name the mapping's
 * `decision_event` lists. Paths follow `response-envelope.json`'s
 * `AcsResult`: `decision` and `reasoning` are direct members; the other four
 * sit under `metadata`. `acs.evaluator` falls back to DEFAULT_EVALUATOR
 * because the mapping requires it and the reference never sends
 * `metadata.evaluator` on the wire.
 */
const DECISION_ATTRIBUTE_SOURCES: Record<string, Source<ResultParts>> = {
  "acs.decision": (d) => asString(d.result.decision),
  "acs.evaluator": (d) => asString(d.metadata.evaluator) ?? DEFAULT_EVALUATOR,
  "acs.reasoning": (d) => asString(d.result.reasoning),
  "acs.confidence": (d) => asNumber(d.metadata.confidence),
  "acs.evaluator_version": (d) => asString(d.metadata.evaluator_version),
  "acs.model_id": (d) => asString(d.metadata.model_id),
};

/**
 * Decision facts the mapping does not name but a reviewer reconstructing a
 * decision needs, on the same event. Each is emitted only when the response
 * carries it; `acs.chain_hash` in particular appears only once a Guardian
 * puts the chain head on the wire, which it does only after a ContextEntry
 * was written -- an envelope that failed validation never reaches that step.
 */
const DECISION_DETAIL_SOURCES: Record<string, Source<ResultParts>> = {
  "acs.reason_codes": (d) => asStrings(d.result.reason_codes),
  "acs.policy.ids": (d) => policyColumn(d.result.policy_references, "policy_id"),
  "acs.policy.versions": (d) => policyColumn(d.result.policy_references, "policy_version"),
  "acs.policy.rule_ids": (d) => policyColumn(d.result.policy_references, "rule_id"),
  "acs.cited_provenance_ids": (d) => asStrings(d.result.cited_provenance_ids),
  "acs.chain_hash": (d) => asString(d.result.chain_hash),
};

function collect<Parts>(into: Attributes, names: Iterable<string>, sources: Record<string, Source<Parts>>, parts: Parts): void {
  for (const name of names) {
    const value = sources[name]?.(parts);
    if (value !== undefined) {
      into[name] = value;
    }
  }
}

/**
 * The span this module started for one step, handed to the caller so the
 * response can close the same span and no other. Opaque: a caller holds it
 * between the two calls and reads nothing off it.
 */
export type StepSpan = { readonly span: Span };

/** The Guardian-side writer role, called at the envelope log's own two
 * points: `start` where the request is recorded, `end` where the response
 * is, with the handle `start` returned. */
export type OtelTraceExporter = {
  /** Null when this request produces no span -- `end` then does nothing. */
  start(envelope: unknown, method: string | null): StepSpan | null;
  end(stepSpan: StepSpan | null, response: unknown): void;
  /** Pushes every ended span through to the exporters now rather than on
   * the batch timer. Tests call it; shutdown does too. */
  flush(): Promise<void>;
  /** Flushes, then releases the processors. Safe to call twice. */
  shutdown(): Promise<void>;
};

/** The exporter a Guardian gets when neither output is configured: the
 * composition root disabling trace export gets a value of the same type,
 * not a special case. */
export const NULL_OTEL_TRACE_EXPORTER: OtelTraceExporter = {
  start(): null {
    return null;
  },
  end(): void {},
  async flush(): Promise<void> {},
  async shutdown(): Promise<void> {},
};

export type CreateOtelTraceExporterOptions = {
  /** OTLP/JSON file, one ExportTraceServiceRequest per line. */
  filePath?: string;
  /** OTLP/HTTP traces endpoint, e.g. `http://127.0.0.1:4318/v1/traces`. */
  endpoint?: string;
  /** A span exporter used beside (or instead of) the two above. Exists so
   * tests can read spans back in-process; not meant for production use. */
  spanExporter?: SpanExporter;
  /** The methods this Guardian dispatches -- the ServerHello's own list.
   * A method outside it produces no span even when the mapping names one. */
  methodsEvaluated: readonly string[];
  /** Overrides the mapping file. Defaults to the repository's own. */
  mappingPath?: string;
  /** Called at most once, on the first failure. Defaults to one stderr line. */
  onError?: (error: unknown) => void;
};

/**
 * Writes OTLP/JSON, one `ExportTraceServiceRequest` per line -- the shape
 * the OpenTelemetry Collector's file exporter writes -- serialised by the
 * official JsonTraceSerializer rather than by hand. Reports a failed write
 * through the result callback; the processor above routes it to `fail`.
 */
export function createFileSpanExporter(path: string): SpanExporter {
  mkdirSync(dirname(path), { recursive: true });
  return {
    export(spans, resultCallback): void {
      try {
        const bytes = JsonTraceSerializer.serializeRequest(spans);
        if (bytes === undefined) {
          throw new Error("JsonTraceSerializer produced no request");
        }
        appendFileSync(path, `${new TextDecoder().decode(bytes)}\n`);
        resultCallback({ code: ExportResultCode.SUCCESS });
      } catch (error) {
        resultCallback({ code: ExportResultCode.FAILED, error: error instanceof Error ? error : new Error(String(error)) });
      }
    },
    async shutdown(): Promise<void> {},
    async forceFlush(): Promise<void> {},
  };
}

/**
 * Wraps a SpanExporter so a failed export reaches `fail`. The SDK's own route
 * for a failed result is its global error handler, which is silent unless a
 * diag logger is installed; this module's contract is one stderr line and
 * then quiet, and an exporter that throws out of `export` must not throw into
 * the processor either.
 */
function reportingFailures(exporter: SpanExporter, fail: (error: unknown) => void): SpanExporter {
  return {
    export(spans, resultCallback): void {
      try {
        exporter.export(spans, (result) => {
          if (result.code === ExportResultCode.FAILED) {
            fail(result.error ?? new Error("span export failed"));
          }
          resultCallback(result);
        });
      } catch (error) {
        fail(error);
        resultCallback({ code: ExportResultCode.FAILED, error: error instanceof Error ? error : new Error(String(error)) });
      }
    },
    shutdown: () => exporter.shutdown(),
    async forceFlush(): Promise<void> {
      await exporter.forceFlush?.();
    },
  };
}

export function createOtelTraceExporter({
  filePath,
  endpoint,
  spanExporter,
  methodsEvaluated,
  mappingPath,
  onError,
}: CreateOtelTraceExporterOptions): OtelTraceExporter {
  let disabled = false;

  const fail = (error: unknown): void => {
    if (disabled) {
      return;
    }
    disabled = true;
    try {
      if (onError) {
        onError(error);
        return;
      }
      const message = error instanceof Error ? error.message : String(error);
      console.error(`otel trace exporter disabled after failure: ${message}`);
    } catch {
      // Silently swallow any error from the callback or console.error
      // to maintain the total-by-construction guarantee
    }
  };

  const exporters: SpanExporter[] = [];
  try {
    if (filePath !== undefined) {
      exporters.push(createFileSpanExporter(filePath));
    }
    if (endpoint !== undefined) {
      exporters.push(new OTLPTraceExporter({ url: endpoint }));
    }
    if (spanExporter !== undefined) {
      exporters.push(spanExporter);
    }
  } catch (error) {
    fail(error);
  }
  if (exporters.length === 0 && !disabled) {
    return NULL_OTEL_TRACE_EXPORTER;
  }

  let provider: BasicTracerProvider | undefined;
  let tracer: Tracer | undefined;
  let mapping: OtelMapping | undefined;
  try {
    mapping = loadOtelMapping(mappingPath);
    provider = new BasicTracerProvider({
      resource: resourceFromAttributes({ "service.name": OTEL_SERVICE_NAME }),
      spanProcessors: exporters.map((exporter) => new BatchSpanProcessor(reportingFailures(exporter, fail))),
    });
    tracer = provider.getTracer(OTEL_SERVICE_NAME);
  } catch (error) {
    fail(error);
  }

  const handled = new Set(methodsEvaluated);

  function begin(envelope: unknown, method: string | null, tracer: Tracer, mapping: OtelMapping): StepSpan | null {
    if (method === null || !handled.has(method)) {
      return null;
    }
    const entry = mapping.stepToSpan[method];
    if (entry === undefined) {
      return null;
    }
    const parts = requestParts(envelope);
    const attributes: Attributes = {};
    collect(attributes, Object.keys(CORRELATION_ATTRIBUTE_SOURCES), CORRELATION_ATTRIBUTE_SOURCES, parts);
    collect(attributes, [...entry.required_attributes, ...(entry.optional_attributes ?? [])], STEP_ATTRIBUTE_SOURCES, parts);
    return { span: tracer.startSpan(entry.span_name, { attributes, root: true }) };
  }

  function finish({ span }: StepSpan, envelope: unknown, mapping: OtelMapping): void {
    const decision = resultParts(envelope);
    if (decision === undefined) {
      // A JSON-RPC error: the step was answered but not decided. The error
      // text is the host's own message and may name the failure.
      const error = asObject(asObject(envelope)?.error);
      span.setStatus({ code: SpanStatusCode.ERROR, message: asString(error?.message) });
    } else {
      const attributes: Attributes = {};
      collect(attributes, mapping.decisionAttributes, DECISION_ATTRIBUTE_SOURCES, decision);
      collect(attributes, Object.keys(DECISION_DETAIL_SOURCES), DECISION_DETAIL_SOURCES, decision);
      if (attributes["acs.decision"] !== undefined) {
        span.addEvent(mapping.decisionEventName, attributes);
      }
    }
    span.end();
  }

  let stopped = false;

  return {
    start(envelope, method): StepSpan | null {
      if (disabled || stopped || tracer === undefined || mapping === undefined) {
        return null;
      }
      try {
        return begin(envelope, method, tracer, mapping);
      } catch (error) {
        fail(error);
        return null;
      }
    },
    end(stepSpan, response): void {
      if (stepSpan === null || disabled || stopped || mapping === undefined) {
        return;
      }
      try {
        finish(stepSpan, response, mapping);
      } catch (error) {
        fail(error);
      }
    },
    async flush(): Promise<void> {
      if (provider === undefined || stopped) {
        return;
      }
      try {
        await provider.forceFlush();
      } catch (error) {
        fail(error);
      }
    },
    async shutdown(): Promise<void> {
      if (provider === undefined || stopped) {
        return;
      }
      stopped = true;
      try {
        // Flushes every processor, then releases them.
        await provider.shutdown();
      } catch (error) {
        fail(error);
      }
    },
  };
}
