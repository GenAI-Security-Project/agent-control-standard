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
 * four source tables below, written once by hand. An attribute the mapping
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
 * wrapped, and nothing propagates into or delays the decision path. Each
 * output fails on its own: the first failed or throwing export disables
 * that output alone, reports once under its label, and reaches the
 * processor as a success, so a collector that is down, restarting or
 * answering 4xx cannot reject a flush and take the file down with it -- the
 * lab reads the file. A broken mapping or a bug inside start/end still
 * disables everything, once. Ended spans go to one BatchSpanProcessor per
 * output and the file is appended asynchronously, so serialisation and I/O
 * happen off the request's own turn. Observability degrades; governance
 * does not.
 */
import { mkdirSync, readFileSync } from "node:fs";
import { appendFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { SpanStatusCode, type Attributes, type AttributeValue, type Span, type Tracer } from "@opentelemetry/api";
import { ExportResultCode } from "@opentelemetry/core";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { JsonTraceSerializer } from "@opentelemetry/otlp-transformer";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { BasicTracerProvider, BatchSpanProcessor, type SpanExporter } from "@opentelemetry/sdk-trace-base";

/** How long the OTLP/HTTP exporter keeps retrying one batch against an
 * endpoint that does not answer before it reports the failure. */
const ENDPOINT_TIMEOUT_MS = 2000;

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
    provenance_attributes: {
      properties: {
        required: { default: string[] };
        optional: { default: string[] };
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
  /** Required first, then optional -- carried on a step span whose payload
   * has a Provenance object attached, as the mapping's own text says. */
  provenanceAttributes: string[];
};

export function loadOtelMapping(path: string = OTEL_MAPPING_PATH): OtelMapping {
  const schema = JSON.parse(readFileSync(path, "utf8")) as OtelMappingSchema;
  const decision = schema.properties.decision_event.properties;
  const provenance = schema.properties.provenance_attributes.properties;
  return {
    stepToSpan: schema.properties.step_to_span.default,
    decisionEventName: decision.event_name.const,
    decisionAttributes: [...decision.required_attributes.default, ...decision.conditional_attributes.default],
    provenanceAttributes: [...provenance.required.default, ...provenance.optional.default],
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
 * One column of `policy_references`, in the wire's own order: the same
 * length as `policy_references`, with `""` where a reference lacks the
 * field. That is the rule agreed on #228, so a reader lines the three
 * columns up by position and never loses the values the other references
 * did carry. Absent only when there are no references at all.
 */
function policyColumn(references: unknown, field: string): string[] | undefined {
  if (!Array.isArray(references) || references.length === 0) return undefined;
  return references.map((reference) => asString(asObject(reference)?.[field]) ?? "");
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

/**
 * Attribute name -> which field of a Provenance object (`provenance.json`)
 * it reads. Unlike the tables above, each of these becomes a COLUMN: one
 * array per attribute, one element per Provenance object the payload
 * carries, in wire order. A span has one value per attribute key, and a
 * payload can carry several Provenance objects -- one per argument -- so an
 * array is the only shape that keeps every object visible; the i-th element
 * of each column describes the i-th object, and `acs.provenance.origin` is
 * always complete because provenance.json requires `origin`.
 *
 * `acs.provenance.lineage_depth` is in the mapping's optional list and has
 * no entry here. provenance.json defines no lineage_depth field, so there is
 * nothing on the wire to read it from, and deriving one (from the length of
 * `derived_from`, say) would be a value nobody sent.
 */
const PROVENANCE_ATTRIBUTE_SOURCES: Record<string, (provenance: JsonObject) => string | undefined> = {
  "acs.provenance.origin": (p) => asString(p.origin),
  "acs.provenance.source_id": (p) => asString(p.source_id),
};

/** The Provenance objects a payload carries, in wire order: one per
 * argument that has one, in the order the parsed object holds them, then one
 * per output that has one, in array order. "Parsed" order rather than the
 * bytes' order because `JSON.parse` has already hoisted integer-like
 * argument names ahead of the rest (envelope-log-sink.ts notes `{"0": ...}`
 * is a real shape), so this is the order every reader of the envelope log
 * sees too. The two never meet on one payload -- the request gate carries
 * `arguments`, the result gate `outputs` -- and an argument or output
 * without one contributes nothing. */
function provenanceObjects(payload: JsonObject): JsonObject[] {
  const carriers: unknown[] = [
    ...Object.values(asObject(payload.arguments) ?? {}),
    ...(Array.isArray(payload.outputs) ? payload.outputs : []),
  ];
  const found: JsonObject[] = [];
  for (const carrier of carriers) {
    const provenance = asObject(asObject(carrier)?.provenance);
    if (provenance !== undefined) {
      found.push(provenance);
    }
  }
  return found;
}

/** One column over every Provenance object, in order, padded with `""`
 * where an object lacks the field -- the same rule policyColumn applies, for
 * the same reason: every column is the length of `acs.provenance.origin`, so
 * the i-th element of each describes the i-th object, and a `source_id` one
 * argument carries is never hidden by another argument that has none. */
function provenanceColumn(objects: JsonObject[], read: (provenance: JsonObject) => string | undefined): string[] {
  return objects.map((object) => read(object) ?? "");
}

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
  /** Called at most once per output, on that output's first failure, and
   * at most once more for a failure of the exporter as a whole (a mapping
   * that will not load, a bug inside start or end). Defaults to one stderr
   * line each. */
  onError?: (error: unknown) => void;
};

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

/**
 * Writes OTLP/JSON, one `ExportTraceServiceRequest` per line -- the shape
 * the OpenTelemetry Collector's file exporter writes -- serialised by the
 * official JsonTraceSerializer rather than by hand.
 *
 * The append is asynchronous: this exporter runs on the same event loop the
 * Guardian answers requests on, and a synchronous write would hold every
 * in-flight decision for the duration of the disk I/O. Writes are chained on
 * one promise so lines land in export order even when two batches are in
 * flight, and `forceFlush` and `shutdown` await the chain so a close never
 * leaves a batch unwritten. The chain itself never rejects: one failed write
 * is reported through its own batch's callback and cannot poison every write
 * after it.
 *
 * 0o700 on the directory and 0o600 on the file: the file holds reasoning
 * text and provenance source ids, so other local users should not read it
 * (#71 is the same problem in the envelope log). The mode applies when the
 * exporter creates the path; an existing file keeps whatever it had.
 */
export function createFileSpanExporter(path: string): SpanExporter {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  let chain: Promise<void> = Promise.resolve();
  return {
    export(spans, resultCallback): void {
      let line: string;
      try {
        const bytes = JsonTraceSerializer.serializeRequest(spans);
        if (bytes === undefined) {
          throw new Error("JsonTraceSerializer produced no request");
        }
        line = `${new TextDecoder().decode(bytes)}\n`;
      } catch (error) {
        resultCallback({ code: ExportResultCode.FAILED, error: asError(error) });
        return;
      }
      const write = chain.then(() => appendFile(path, line, { mode: 0o600 }));
      chain = write.then(
        () => undefined,
        () => undefined,
      );
      write.then(
        () => resultCallback({ code: ExportResultCode.SUCCESS }),
        (error: unknown) => resultCallback({ code: ExportResultCode.FAILED, error: asError(error) }),
      );
    },
    async shutdown(): Promise<void> {
      await chain;
    },
    async forceFlush(): Promise<void> {
      await chain;
    },
  };
}

/** One place spans go, with the name its failure is reported under: the
 * file's path, the endpoint's URL, or "span exporter" for an injected one. */
type Output = { label: string; exporter: SpanExporter };

/**
 * Wraps one output so it can fail without taking any other output with it.
 *
 * The first failed result, thrown export, or rejected flush marks this output
 * dead and reports it once, under its label; every later batch for it is
 * dropped. The processor is answered with SUCCESS either way, deliberately:
 * a FAILED result makes the processor's forceFlush reject, the provider's
 * forceFlush and shutdown reject with it, and a collector that is merely down
 * would then end export to the file as well. The failure is this module's
 * finding, reported here, not the processor's. The SDK's own route for a
 * failed result is its global error handler, silent unless a diag logger is
 * installed, which is why the report happens here at all.
 */
function isolated({ label, exporter }: Output, report: (label: string, error: unknown) => void): SpanExporter {
  let dead = false;
  const die = (error: unknown): void => {
    if (dead) {
      return;
    }
    dead = true;
    report(label, error);
  };
  return {
    export(spans, resultCallback): void {
      if (dead) {
        resultCallback({ code: ExportResultCode.SUCCESS });
        return;
      }
      try {
        exporter.export(spans, (result) => {
          if (result.code === ExportResultCode.FAILED) {
            die(result.error ?? new Error("span export failed"));
          }
          resultCallback({ code: ExportResultCode.SUCCESS });
        });
      } catch (error) {
        die(error);
        resultCallback({ code: ExportResultCode.SUCCESS });
      }
    },
    async shutdown(): Promise<void> {
      if (dead) {
        return;
      }
      try {
        await exporter.shutdown();
      } catch (error) {
        die(error);
      }
    },
    async forceFlush(): Promise<void> {
      if (dead) {
        return;
      }
      try {
        await exporter.forceFlush?.();
      } catch (error) {
        die(error);
      }
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
  /** One report, to the caller's hook or to stderr, never thrown: the
   * reporter is the one component here that exists only to report, and a
   * throw out of it would be the failure it is meant to describe. */
  const report = (what: string, error: unknown): void => {
    try {
      if (onError) {
        onError(error);
        return;
      }
      const message = error instanceof Error ? error.message : String(error);
      console.error(`${what} disabled after failure: ${message}`);
    } catch {
      // Silently swallow any error from the callback or console.error
      // to maintain the total-by-construction guarantee
    }
  };

  // The exporter as a whole: a mapping that will not load, a provider that
  // will not build, a bug inside start or end. Once, then quiet.
  let disabled = false;
  const fail = (error: unknown): void => {
    if (disabled) {
      return;
    }
    disabled = true;
    report("otel trace exporter", error);
  };

  // One output: its own first failure, under its own label, and only it.
  const reportOutput = (label: string, error: unknown): void => report(`otel trace export to ${label}`, error);

  // Each output is constructed on its own, so an unwritable file path costs
  // the file and not the endpoint, and the other way round.
  const outputs: Output[] = [];
  const construct = (label: string, build: () => SpanExporter): void => {
    try {
      outputs.push({ label, exporter: build() });
    } catch (error) {
      reportOutput(label, error);
    }
  };
  if (filePath !== undefined) {
    construct(filePath, () => createFileSpanExporter(filePath));
  }
  if (endpoint !== undefined) {
    // A refused connection is retryable to this exporter, so a collector that
    // is down costs its whole timeout before the failure is reported. Two
    // seconds rather than the 10 s default: long enough for a collector that
    // is restarting, short enough that a flush or a shutdown behind a dead
    // one does not hold the process for ten.
    construct(endpoint, () => new OTLPTraceExporter({ url: endpoint, timeoutMillis: ENDPOINT_TIMEOUT_MS }));
  }
  if (spanExporter !== undefined) {
    construct("span exporter", () => spanExporter);
  }
  if (outputs.length === 0) {
    return NULL_OTEL_TRACE_EXPORTER;
  }

  let provider: BasicTracerProvider | undefined;
  let tracer: Tracer | undefined;
  let mapping: OtelMapping | undefined;
  try {
    mapping = loadOtelMapping(mappingPath);
    provider = new BasicTracerProvider({
      resource: resourceFromAttributes({ "service.name": OTEL_SERVICE_NAME }),
      spanProcessors: outputs.map((output) => new BatchSpanProcessor(isolated(output, reportOutput))),
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
    const provenance = provenanceObjects(parts.payload);
    if (provenance.length > 0) {
      for (const name of mapping.provenanceAttributes) {
        const read = PROVENANCE_ATTRIBUTE_SOURCES[name];
        if (read !== undefined) {
          attributes[name] = provenanceColumn(provenance, read);
        }
      }
    }
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
