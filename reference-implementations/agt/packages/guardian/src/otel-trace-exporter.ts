/**
 * createOtelTraceExporter emits one OpenTelemetry span per ACS step this
 * Guardian decides, so a reviewer can rebuild a session offline from a trace
 * file without reading the envelope log. Span names, the attributes each
 * span must and may carry, and the event a decision is recorded as all come
 * from `specification/v0.1.0/trace/otel-mapping.json`, read once at
 * construction. A rename in that mapping needs no change here.
 *
 * This file assembles the exporter. Three neighbors hold the rest:
 * otel-mapping.ts reads the mapping and says which envelope field feeds
 * which attribute, otlp-file-exporter.ts writes the OTLP/JSON file, and
 * loopback-proxy.ts holds the proxy helpers main.ts applies before the
 * Guardian starts.
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
 * A step that got no decision is recorded too, as the `acs.decision.failure`
 * event #37 defines, for the failures this Guardian can see itself: an
 * error it answered instead of a decision, a decision it finished after the
 * host's negotiated timeout (so the host had already applied its posture),
 * and a step still open when the Guardian shut down. The host adapter's
 * audit log holds the failures only the host sees; audit-to-otlp.ts turns
 * those into the same event with `reported_by` set to the observed agent.
 *
 * Off by default. With no file and no endpoint configured, startGuardian is
 * handed NULL_OTEL_TRACE_EXPORTER, which emits nothing. The Guardian's
 * decisions are the same as with export on, and so is the bounded drain in
 * close().
 *
 * Total by construction, as envelope-log-sink.ts is. Every entry point is
 * wrapped, and nothing propagates into or delays the decision path. Each
 * output fails on its own: the first failed or throwing export disables
 * that output alone, reports once under its label, and reaches the
 * processor as a success, so a collector that is down, restarting or
 * answering 4xx cannot reject a flush and take the file down with it. The
 * lab reads the file. A broken mapping or a bug inside start/end still
 * disables everything, once. Ended spans go to one BatchSpanProcessor per
 * output and the file is appended asynchronously, so serialisation and I/O
 * happen off the request's own turn. Observability degrades; governance
 * does not.
 */
import { SpanStatusCode, type Attributes, type Span, type Tracer } from "@opentelemetry/api";
import { ExportResultCode } from "@opentelemetry/core";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { AlwaysOnSampler, BasicTracerProvider, BatchSpanProcessor, type SpanExporter, type SpanLimits } from "@opentelemetry/sdk-trace-base";
import {
  asNumber,
  asObject,
  collect,
  CORRELATION_ATTRIBUTE_SOURCES,
  DECISION_ATTRIBUTE_SOURCES,
  DECISION_DETAIL_NAMES,
  DECISION_FAILURE_EVENT,
  decisionFailureAttributes,
  GUARDIAN_ERROR_STATUS,
  loadOtelMapping,
  PROVENANCE_ATTRIBUTE_SOURCES,
  provenanceColumn,
  provenanceObjects,
  PRE_TRUST_REJECTION_CODES,
  REJECTED_CLAIMED_REQUEST_ID,
  REJECTED_CLAIMED_SESSION_ID,
  REJECTED_ERROR_CODE,
  REJECTED_REASON,
  REJECTED_SPAN_NAME,
  REJECTED_STATUS,
  requestParts,
  resultParts,
  STEP_ATTRIBUTE_SOURCES,
  type DecisionFailure,
  type FailureClass,
  type OtelMapping,
  type RejectionReason,
} from "./otel-mapping.ts";
import { createFileSpanExporter } from "./otlp-file-exporter.ts";

// Every name this module exported before the split, so existing importers
// keep working.
export {
  DECISION_ATTRIBUTE_SOURCES,
  DECISION_FAILURE_EVENT,
  decisionFailureAttributes,
  FAILURE_ATTRIBUTES,
  GUARDIAN_ERROR_STATUS,
  loadOtelMapping,
  METHODS_WITHOUT_SPAN,
  REJECTED_SPAN_NAME,
  STEP_ATTRIBUTE_SOURCES,
  type DecisionFailure,
  type RejectionReason,
  type FailureClass,
  type FailurePosture,
  type FailureReporter,
  type OtelMapping,
  type RequestParts,
  type ResultParts,
  type Source,
} from "./otel-mapping.ts";
export { createFileSpanExporter } from "./otlp-file-exporter.ts";
export { keepLoopbackOffProxy, loopbackProxyWarning } from "./loopback-proxy.ts";

/** The SDK's compression enum, which this package does not import directly. */
type OtlpCompression = NonNullable<ConstructorParameters<typeof OTLPTraceExporter>[0]>["compression"];

/** How long the OTLP/HTTP exporter keeps retrying one batch against an
 * endpoint that does not answer before it reports the failure. */
const ENDPOINT_TIMEOUT_MS = 2000;

/** How long one batch export, and the exporter's shutdown, may take before
 * it is abandoned and reported. A stalled output (a hung network mount, a
 * collector that never answers) must not hold the process open: the SDK's
 * own default is 30 s, longer than many supervisors wait before a SIGKILL. */
const EXPORT_TIMEOUT_MS = ENDPOINT_TIMEOUT_MS + 1000;

/** The longest string attribute a span carries. Every attribute value can
 * come from the request, and an uncapped value lets one large request grow
 * the Guardian's memory in the export queue; a Guardian that runs out of
 * memory fails open under the default posture. `acs.reasoning` longer than
 * this is cut to it. */
const ATTRIBUTE_VALUE_LENGTH_LIMIT = 4096;

/** The `service.name` every span carries. The literal key rather than the
 * semantic-conventions package: one constant does not earn a dependency. */
export const OTEL_SERVICE_NAME = "acs-reference-guardian";

/** Every span limit, set in code so no OTEL_SPAN_* or OTEL_ATTRIBUTE_*
 * variable changes what is exported: the SDK reads the environment for any
 * limit left unset. Shared with the audit converter, so the two writers of
 * the same file shape cannot drift. Frozen, because both providers hold it. */
export const SPAN_LIMITS: Readonly<SpanLimits> = Object.freeze({
  attributeValueLengthLimit: ATTRIBUTE_VALUE_LENGTH_LIMIT,
  attributeCountLimit: 128,
  eventCountLimit: 128,
  attributePerEventCountLimit: 128,
  linkCountLimit: 128,
  attributePerLinkCountLimit: 128,
});

/**
 * The span this module started for one step, handed to the caller so the
 * response can close the same span and no other. Opaque: a caller holds it
 * between the two calls and reads nothing off it. Beside the span it keeps
 * what a failure event needs at the end: the method, for its per-method
 * timeout; when it started, for `acs.failure.elapsed_ms`; and the request
 * body's size, when the caller measured one.
 */
export type StepSpan = {
  readonly span: Span;
  readonly method: string;
  readonly startedAt: number;
  readonly payloadBytes?: number;
  /** The session and request id the request claimed. They go onto the span
   * as acs.session.id and acs.request_id only when it ends as a trusted step
   * (see `finish`), and under the rejected names otherwise. */
  readonly claimed: Attributes;
  /** Every other step attribute, read from the request and held back the
   * same way, so a span that ends as a rejected request carries none of
   * them (`acs.request_id_ref` on a forged result names a genuine call). */
  readonly held: Attributes;
  /** Set when the request was rejected before its span opened. */
  readonly rejected?: RejectionReason;
};

/**
 * What `start` is told about the request besides its envelope. `trusted` is
 * whether the Guardian accepted the envelope before acting on it. A request
 * it did not accept is recorded as a rejected request, apart from the steps
 * it governed, with `reason` saying why (see REJECTED_SPAN_NAME). `trusted`
 * is required, not defaulted, so a caller that forgets it fails to compile
 * rather than exporting an untrusted request's ids as a step.
 *
 * Trusted here means accepted by every check this Guardian runs. This
 * reference Guardian checks the envelope against the schema and nothing
 * else: it verifies no signature, replay or timestamp yet (PR #229), so a
 * forgery or a replay that passes the schema is still recorded as a step.
 *
 * `receivedAt` is `performance.now()` when the request arrived, so the time
 * the Guardian spent checking it counts toward a late decision.
 */
export type StepStart = { payloadBytes?: number; receivedAt?: number } & (
  | { trusted: true }
  | { trusted: false; reason: RejectionReason }
);

/** The Guardian-side writer role, called at the envelope log's own two
 * points: `start` where the request is recorded, `end` where the response
 * is, with the handle `start` returned. */
export type OtelTraceExporter = {
  /** Null when this request produces no span, and `end` then does nothing.
   * `payloadBytes` is the request body's size, for the failure event. An
   * untrusted request produces a rejected-request span (see StepStart). */
  start(envelope: unknown, method: string | null, step: StepStart): StepSpan | null;
  /** `rejection` is set when the Guardian rejected the request before
   * trusting it after the span opened (a signature, replay or timestamp
   * check inside dispatch), whatever shape its answer took. */
  end(stepSpan: StepSpan | null, response: unknown, rejection?: RejectionReason): void;
  /** Pushes every ended span through to the exporters now rather than on
   * the batch timer. Tests call it; shutdown does too. */
  flush(): Promise<void>;
  /** Flushes, then releases the processors. A second call waits for the
   * first rather than returning at once: SIGINT followed by SIGTERM is two
   * calls, and the second must not let the process exit mid-flush. */
  shutdown(): Promise<void>;
};

/** The exporter a Guardian gets when neither output is configured: the
 * composition root disabling trace export gets a value of the same type,
 * not a special case. server.ts's close() treats it like any other. */
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
  /** The methods this Guardian dispatches: the ServerHello's own list.
   * A method outside it produces no span even when the mapping names one. */
  methodsEvaluated: readonly string[];
  /** The ServerHello's `timeout_config`: how long the host waits for a
   * decision before it applies its posture. A decision that finishes after
   * that is one the host never acted on. Omitted means no timeout is known
   * and no step is reported as late. */
  timeoutConfig?: { default_ms: number; per_method_ms?: Record<string, number> };
  /** The posture the host applies when no decision arrives, in the trace
   * vocabulary: `fail_open` for a ServerHello declaring `proceed`,
   * `fail_closed` for `deny`. Defaults to `fail_open`, the spec's own default
   * posture (handshake.json), for an exporter built without a ServerHello. */
  posture?: "fail_open" | "fail_closed";
  /** Overrides the mapping file. Defaults to the repository's own. */
  mappingPath?: string;
  /** How long one export, and shutdown, may take before it is abandoned and
   * reported. Defaults to EXPORT_TIMEOUT_MS; tests pass a short one. */
  exportTimeoutMs?: number;
  /** Called at most once per output, on that output's first failure, and
   * at most once more for a failure of the exporter as a whole (a mapping
   * that will not load, a bug inside start or end). Defaults to one stderr
   * line each. */
  onError?: (error: unknown) => void;
};

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
      // Shut the output down whether or not it died: a dead HTTP output
      // still holds its keep-alive agent until its exporter releases it.
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

/** A rejected request's attributes: the ids it claimed, under names a reader
 * cannot mistake for the ACS pair, and why it was rejected. */
function rejectedAttributes(claimed: Attributes, reason: RejectionReason, errorCode?: number): Attributes {
  const attributes: Attributes = { [REJECTED_REASON]: reason };
  if (claimed["acs.session.id"] !== undefined) {
    attributes[REJECTED_CLAIMED_SESSION_ID] = claimed["acs.session.id"];
  }
  if (claimed["acs.request_id"] !== undefined) {
    attributes[REJECTED_CLAIMED_REQUEST_ID] = claimed["acs.request_id"];
  }
  if (errorCode !== undefined) {
    attributes[REJECTED_ERROR_CODE] = errorCode;
  }
  return attributes;
}

export function createOtelTraceExporter({
  filePath,
  endpoint,
  spanExporter,
  methodsEvaluated,
  timeoutConfig,
  posture = "fail_open",
  mappingPath,
  exportTimeoutMs = EXPORT_TIMEOUT_MS,
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
    // compression set in code: OTEL_EXPORTER_OTLP_COMPRESSION would otherwise
    // gzip the body. Headers from OTEL_EXPORTER_OTLP_*HEADERS are merged by
    // the SDK under any set here and cannot be refused, so the README lists
    // them as honored.
    construct(
      endpoint,
      () => new OTLPTraceExporter({ url: endpoint, timeoutMillis: ENDPOINT_TIMEOUT_MS, compression: "none" as OtlpCompression }),
    );
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
      // Set explicitly so no OTEL_* environment variable can sample spans
      // away or drop decision events: the SDK reads OTEL_TRACES_SAMPLER and
      // the span limits from the environment for anything left unset.
      sampler: new AlwaysOnSampler(),
      // Copied, because the SDK may write to the object it is given.
      spanLimits: { ...SPAN_LIMITS },
      spanProcessors: outputs.map(
        (output) =>
          new BatchSpanProcessor(isolated(output, reportOutput), {
            // The SDK defaults, written out: anything left unset is read from
            // OTEL_BSP_*, and a queue of one drops spans.
            maxQueueSize: 2048,
            maxExportBatchSize: 512,
            scheduledDelayMillis: 5000,
            exportTimeoutMillis: exportTimeoutMs,
          }),
      ),
    });
    tracer = provider.getTracer(OTEL_SERVICE_NAME);
  } catch (error) {
    fail(error);
  }

  const handled = new Set(methodsEvaluated);

  // Started and not yet ended, so shutdown can close what no response ever
  // reached: a bridge that never answers, or a signal during traffic. An
  // open span is never exported, and without this the step left no trace.
  const openSpans = new Set<StepSpan>();

  /** The failure event's attributes for one step, as this Guardian reports
   * them: its own posture, elapsed time since the span started, and the
   * request's size when known. */
  function failureAttributes(stepSpan: StepSpan, failureClass: FailureClass, known: Partial<DecisionFailure> = {}): Attributes {
    return decisionFailureAttributes({
      class: failureClass,
      posture,
      reportedBy: "guardian",
      elapsedMs: Math.round(performance.now() - stepSpan.startedAt),
      payloadBytes: stepSpan.payloadBytes,
      ...known,
    });
  }

  function begin(envelope: unknown, method: string | null, step: StepStart, tracer: Tracer, mapping: OtelMapping): StepSpan | null {
    const parts = requestParts(envelope);
    // Held back, not set: the pair, and every other step attribute, goes on
    // only when the span ends as a trusted step, because a check that runs
    // after this point can still reject the request.
    const claimed: Attributes = {};
    collect(claimed, Object.keys(CORRELATION_ATTRIBUTE_SOURCES), CORRELATION_ATTRIBUTE_SOURCES, parts);
    const startedAt = step.receivedAt ?? performance.now();
    // The span's own start is the arrival too, so its duration agrees with
    // the elapsed time the failure event reports.
    const startTime = step.receivedAt;
    // A rejected request is recorded whatever its method, handled or not:
    // its span needs no step_to_span entry.
    if (!step.trusted) {
      const rejected: StepSpan = {
        span: tracer.startSpan(REJECTED_SPAN_NAME, { attributes: rejectedAttributes(claimed, step.reason), root: true, startTime }),
        method: method ?? "",
        startedAt,
        payloadBytes: step.payloadBytes,
        claimed,
        held: {},
        rejected: step.reason,
      };
      openSpans.add(rejected);
      return rejected;
    }
    if (method === null || !handled.has(method)) {
      return null;
    }
    const entry = mapping.stepToSpan[method];
    if (entry === undefined) {
      return null;
    }
    const attributes: Attributes = {};
    collect(
      attributes,
      [...entry.required_attributes, ...(entry.conditional_attributes ?? []), ...(entry.optional_attributes ?? [])],
      STEP_ATTRIBUTE_SOURCES,
      parts,
    );
    const provenance = provenanceObjects(parts.payload);
    if (provenance.length > 0) {
      for (const name of mapping.provenanceAttributes) {
        const read = PROVENANCE_ATTRIBUTE_SOURCES[name];
        // A column is emitted only when at least one object carries the
        // field (#228). `origin` is required, so it always is; an
        // all-padding `source_id` column would say something nobody sent.
        if (read !== undefined && provenance.some((object) => read(object) !== undefined)) {
          attributes[name] = provenanceColumn(provenance, read);
        }
      }
    }
    const stepSpan: StepSpan = {
      span: tracer.startSpan(entry.span_name, { root: true, startTime }),
      method,
      startedAt,
      payloadBytes: step.payloadBytes,
      claimed,
      held: attributes,
    };
    openSpans.add(stepSpan);
    return stepSpan;
  }

  /** Ends a span as a rejected request: renamed if it opened as a step, the
   * claimed ids under the rejected names, and no ACS pair, step attribute or
   * decision event. A Guardian fault is still a decision failure for the
   * host, which got an error, so it keeps that event, on a span with no pair. */
  function finishRejected(stepSpan: StepSpan, reason: RejectionReason, errorCode?: number): void {
    const { span } = stepSpan;
    span.updateName(REJECTED_SPAN_NAME);
    span.setAttributes(rejectedAttributes(stepSpan.claimed, reason, errorCode));
    span.setStatus({ code: SpanStatusCode.ERROR, message: REJECTED_STATUS });
    if (reason === "guardian_fault") {
      span.addEvent(DECISION_FAILURE_EVENT, failureAttributes(stepSpan, "guardian_error", { errorCode }));
    }
    span.end();
  }

  function finish(stepSpan: StepSpan, envelope: unknown, mapping: OtelMapping, rejection: RejectionReason | undefined): void {
    const { span } = stepSpan;
    const error = asObject(asObject(envelope)?.error);
    const errorCode = asNumber(error?.code);
    // Rejected before the span opened, rejected by a check after it opened,
    // or answered with a code that only a rejection carries: each ends as a
    // rejected request, and no held attribute reaches it.
    const reason =
      stepSpan.rejected ?? rejection ?? (errorCode === undefined ? undefined : PRE_TRUST_REJECTION_CODES.get(errorCode));
    if (reason !== undefined) {
      finishRejected(stepSpan, reason, errorCode);
      return;
    }
    span.setAttributes({ ...stepSpan.claimed, ...stepSpan.held });
    const decision = resultParts(envelope);
    if (decision === undefined) {
      // A JSON-RPC error: the step was answered but not decided. The first
      // of the two failures a Guardian can see itself (#37). Only the code is
      // carried: the message can quote the request (a schema error names its
      // argument keys), and #228 forbids copying response or error bytes into
      // the trace, so the status message is a fixed sentence too.
      span.setStatus({ code: SpanStatusCode.ERROR, message: GUARDIAN_ERROR_STATUS });
      span.addEvent(DECISION_FAILURE_EVENT, failureAttributes(stepSpan, "guardian_error", { errorCode }));
    } else {
      const attributes: Attributes = {};
      collect(attributes, new Set([...mapping.decisionAttributes, ...DECISION_DETAIL_NAMES]), DECISION_ATTRIBUTE_SOURCES, decision);
      if (attributes["acs.decision"] !== undefined) {
        span.addEvent(mapping.decisionEventName, attributes);
      }
      // The second: a decision that finished after the host stopped waiting.
      // The host applied its posture at the timeout, so the decision above
      // probably never took effect, and a reader has to be told.
      const timeoutMs = timeoutConfig?.per_method_ms?.[stepSpan.method] ?? timeoutConfig?.default_ms;
      if (timeoutMs !== undefined && performance.now() - stepSpan.startedAt > timeoutMs) {
        span.addEvent(DECISION_FAILURE_EVENT, failureAttributes(stepSpan, "timeout", { timeoutMs }));
      }
    }
    span.end();
  }

  let stopped = false;
  // The one shutdown, started by the first call and returned to every call
  // after it, so a second signal waits for the flush the first began.
  let shutdownPromise: Promise<void> | undefined;

  return {
    start(envelope, method, step): StepSpan | null {
      if (disabled || stopped || tracer === undefined || mapping === undefined) {
        return null;
      }
      try {
        return begin(envelope, method, step, tracer, mapping);
      } catch (error) {
        fail(error);
        return null;
      }
    },
    end(stepSpan, response, rejection): void {
      if (stepSpan === null) {
        return;
      }
      // Removed first, whatever happens next: a span the caller is ending
      // is no longer one shutdown has to close.
      openSpans.delete(stepSpan);
      if (disabled || stopped || mapping === undefined) {
        return;
      }
      try {
        finish(stepSpan, response, mapping, rejection);
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
    shutdown(): Promise<void> {
      shutdownPromise ??= (async () => {
        if (provider === undefined) {
          return;
        }
        stopped = true;
        // Steps still open: a bridge that never answered, or a signal during
        // traffic. Closed here, as the third failure this Guardian can see,
        // so the step is exported at all.
        for (const stepSpan of openSpans) {
          try {
            if (stepSpan.rejected !== undefined) {
              finishRejected(stepSpan, stepSpan.rejected);
              continue;
            }
            stepSpan.span.setAttributes({ ...stepSpan.claimed, ...stepSpan.held });
            stepSpan.span.addEvent(
              DECISION_FAILURE_EVENT,
              failureAttributes(stepSpan, "other", { detail: "the Guardian shut down before it answered this step" }),
            );
            stepSpan.span.setStatus({ code: SpanStatusCode.ERROR, message: "no response before shutdown" });
            stepSpan.span.end();
          } catch (error) {
            fail(error);
          }
        }
        openSpans.clear();
        // Flushes every processor, then releases them. Bounded, because a
        // stalled output would otherwise hold the process open. The SDK's own
        // export timeout covers a batch in flight; this covers an exporter
        // whose shutdown never returns.
        let timer: ReturnType<typeof setTimeout> | undefined;
        const deadline = new Promise<"timeout">((resolve) => {
          timer = setTimeout(() => resolve("timeout"), exportTimeoutMs);
          timer.unref?.();
        });
        try {
          const outcome = await Promise.race([provider.shutdown().then(() => "done" as const), deadline]);
          if (outcome === "timeout") {
            report("otel trace exporter shutdown", new Error(`did not finish within ${exportTimeoutMs} ms; unexported spans were dropped`));
          }
        } catch (error) {
          fail(error);
        } finally {
          clearTimeout(timer);
        }
      })();
      return shutdownPromise;
    },
  };
}

