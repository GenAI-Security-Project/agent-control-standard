/**
 * audit-to-otlp turns the host adapter's audit log into the same OTLP/JSON
 * file the Guardian's trace exporter writes, so a reader of that file sees
 * every decision failure, not only the ones the Guardian could see itself.
 *
 * The Guardian's exporter records the failures it can see: an error it
 * answered, a decision it finished late, a step still open at shutdown. The
 * host adapter sees the rest -- a Guardian it could not reach, one that
 * never answered in time -- and #37 makes it record each one in its own
 * audit log (`.acs/audit.jsonl`, packages/host-adapter/src/audit-sink.ts)
 * and surface it on Trace when it can. The adapter runs once per hook in a
 * fresh process and should not carry the OpenTelemetry SDK, so the surfacing
 * happens here, afterwards, from the log.
 *
 *   bun run packages/guardian/src/audit-to-otlp.ts <audit.jsonl> <otel-file.jsonl>
 *
 * Each posture-resolved entry (`outcome` of `proceeded` or `blocked`)
 * becomes one span named by otel-mapping.json for the entry's method, timed
 * at `recorded_at`, carrying `acs.session.id` and one `acs.decision.failure`
 * event with `acs.failure.reported_by` set to `observed_agent`. The audit
 * entry carries no elapsed time, timeout or payload size, so those
 * "when known" attributes are left out. An `ungoverned` entry is a step no
 * gate asked about, not a decision failure, so it is skipped; an entry whose
 * method has no `step_to_span` entry is skipped and counted.
 *
 * Reads the log with plain JSON.parse and loose field reads, importing
 * nothing from the host adapter: the file is the contract, the same way the
 * Inspector reads it. Run it after the Guardian has stopped. Two writers on
 * one file can interleave lines, and running it twice over the same log
 * writes every span twice.
 */
import { readFileSync } from "node:fs";
import { SpanStatusCode, type Attributes } from "@opentelemetry/api";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { BasicTracerProvider, BatchSpanProcessor } from "@opentelemetry/sdk-trace-base";
import {
  createFileSpanExporter,
  DECISION_FAILURE_EVENT,
  decisionFailureAttributes,
  loadOtelMapping,
  OTEL_SERVICE_NAME,
  type FailureClass,
} from "./otel-trace-exporter.ts";

/**
 * The host's `failure.kind` (packages/host-adapter/src/failure-kinds.ts)
 * to #37's `acs.failure.class`.
 *
 * `transport` is a request that never reached the Guardian, which is what
 * `unreachable` names. `error_without_decision` and `refused` both mean an
 * error came back instead of a decision, so both are `guardian_error`; which
 * refusal it was travels in `acs.failure.detail`, where the adapter put the
 * code. `host_configuration` (no request was ever built) and
 * `decision_unrenderable` (a decision arrived and this host could not
 * express it) are faults on the observed agent's own side. `unknown`, and
 * any kind this table does not know, is `other`, and a rising `other` count
 * is the signal the list needs a row.
 */
export const FAILURE_CLASS_BY_KIND: Readonly<Record<string, FailureClass>> = {
  timeout: "timeout",
  transport: "unreachable",
  error_without_decision: "guardian_error",
  refused: "guardian_error",
  host_configuration: "observed_agent_error",
  decision_unrenderable: "observed_agent_error",
};

export function failureClassOf(kind: unknown): FailureClass {
  return (typeof kind === "string" ? FAILURE_CLASS_BY_KIND[kind] : undefined) ?? "other";
}

export type ConversionSummary = {
  spans: number;
  /** Posture entries whose method the mapping names no span for. */
  skippedUnmapped: number;
  /** Steps no gate asked about. */
  skippedUngoverned: number;
  /** Lines that were not JSON, or not an audit entry. */
  skippedUnreadable: number;
};

type JsonObject = Record<string, unknown>;

function readObject(value: unknown): JsonObject | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as JsonObject) : undefined;
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/** `recorded_at` as a Date, or undefined for a value Date cannot read, in
 * which case the span is timed at now rather than at a nonsense instant. */
function readInstant(value: unknown): Date | undefined {
  const text = readString(value);
  if (text === undefined) return undefined;
  const instant = new Date(text);
  return Number.isNaN(instant.getTime()) ? undefined : instant;
}

export async function convertAuditLog(auditPath: string, otelPath: string, mappingPath?: string): Promise<ConversionSummary> {
  const mapping = loadOtelMapping(mappingPath);
  const provider = new BasicTracerProvider({
    resource: resourceFromAttributes({ "service.name": OTEL_SERVICE_NAME }),
    spanProcessors: [new BatchSpanProcessor(createFileSpanExporter(otelPath))],
  });
  const tracer = provider.getTracer(OTEL_SERVICE_NAME);
  const summary: ConversionSummary = { spans: 0, skippedUnmapped: 0, skippedUngoverned: 0, skippedUnreadable: 0 };

  for (const line of readFileSync(auditPath, "utf8").split("\n")) {
    if (line.trim() === "") continue;
    let entry: JsonObject | undefined;
    try {
      entry = readObject(JSON.parse(line));
    } catch {
      entry = undefined;
    }
    if (entry === undefined) {
      summary.skippedUnreadable += 1;
      continue;
    }
    const outcome = readString(entry.outcome);
    if (outcome === "ungoverned") {
      summary.skippedUngoverned += 1;
      continue;
    }
    if (outcome !== "proceeded" && outcome !== "blocked") {
      summary.skippedUnreadable += 1;
      continue;
    }
    const method = readString(entry.method);
    const spanName = method === undefined ? undefined : mapping.stepToSpan[method]?.span_name;
    if (spanName === undefined) {
      summary.skippedUnmapped += 1;
      continue;
    }

    const instant = readInstant(entry.recorded_at);
    const failure = readObject(entry.failure) ?? {};
    const message = readString(failure.message);
    const attributes: Attributes = {};
    const sessionId = readString(entry.session_id);
    if (sessionId !== undefined) {
      attributes["acs.session.id"] = sessionId;
    }
    // The entry is one instant, so the span is too: it opens and closes at
    // recorded_at. The host, not the Guardian, is the reporter, and the
    // posture is the one the host applied -- `proceeded` is fail-open,
    // `blocked` fail-closed.
    const span = tracer.startSpan(spanName, { attributes, root: true, startTime: instant });
    span.addEvent(
      DECISION_FAILURE_EVENT,
      decisionFailureAttributes({
        class: failureClassOf(failure.kind),
        posture: outcome === "blocked" ? "fail_closed" : "fail_open",
        reportedBy: "observed_agent",
        detail: message,
      }),
      instant,
    );
    span.setStatus({ code: SpanStatusCode.ERROR, message });
    span.end(instant);
    summary.spans += 1;
  }

  // Flushes every span to the file, then releases the processor.
  await provider.shutdown();
  return summary;
}

if (import.meta.main) {
  const [auditPath, otelPath] = Bun.argv.slice(2);
  if (auditPath === undefined || otelPath === undefined) {
    console.error("usage: bun run packages/guardian/src/audit-to-otlp.ts <audit.jsonl> <otel-file.jsonl>");
    process.exit(2);
  }
  const summary = await convertAuditLog(auditPath, otelPath);
  console.log(
    `wrote ${summary.spans} span(s) to ${otelPath}; skipped ${summary.skippedUnmapped} with no mapping entry, ` +
      `${summary.skippedUngoverned} ungoverned, ${summary.skippedUnreadable} unreadable`,
  );
}
