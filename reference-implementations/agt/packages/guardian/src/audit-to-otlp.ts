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
 * at `recorded_at`, carrying the same `acs.session.id` and `acs.request_id`
 * the Guardian's own spans carry, and one `acs.decision.failure` event with
 * `acs.failure.reported_by` set to `observed_agent`. The audit entry carries
 * no elapsed time, timeout or payload size, so those "when known" attributes
 * are left out.
 *
 * Skipped, and counted in the summary:
 * - an `ungoverned` entry: a step no gate asked about, not a decision failure;
 * - an entry with no method: the host never built a request (a broken
 *   hookmap, say), so there is no span name and no request id to carry --
 *   counted by its failure kind, because a fail-open among these is still a
 *   bypass someone has to see;
 * - an entry whose method the mapping names no span for;
 * - a REPLAY_DETECTED error, whose pair belongs to the earlier request (#228);
 * - a line that is not JSON, not an audit entry, or has no posture.
 *
 * Reads the log with plain JSON.parse and loose field reads, importing
 * nothing from the host adapter: the file is the contract, the same way the
 * Inspector reads it. Run it after the agent session has ended, into a file
 * that does not exist when it starts: it refuses an existing output path, so
 * it does not append into the audit log, the Guardian's trace file, or its
 * own earlier run.
 */
import { createHash } from "node:crypto";
import { closeSync, mkdirSync, openSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { SpanStatusCode, type Attributes } from "@opentelemetry/api";
import { ExportResultCode, type ExportResult } from "@opentelemetry/core";
import { resourceFromAttributes } from "@opentelemetry/resources";
import {
  AlwaysOnSampler,
  BasicTracerProvider,
  SimpleSpanProcessor,
  type ReadableSpan,
  type SpanExporter,
} from "@opentelemetry/sdk-trace-base";
import {
  asObject,
  DECISION_FAILURE_EVENT,
  decisionFailureAttributes,
  GUARDIAN_ERROR_STATUS,
  loadOtelMapping,
  REPLAY_DETECTED_CODE,
  type FailureClass,
  type JsonObject,
} from "./otel-mapping.ts";
import { SPAN_LIMITS } from "./otel-trace-exporter.ts";
import { createFileSpanExporter } from "./otlp-file-exporter.ts";

/**
 * The host's `failure.kind` (packages/host-adapter/src/failure-kinds.ts)
 * to #37's `acs.failure.class`.
 *
 * `transport` is a request that never reached the Guardian, which is what
 * `unreachable` names. `error_without_decision` and `refused` both mean an
 * error came back instead of a decision (§6.4), so both are `guardian_error`;
 * the code goes in `acs.failure.error_code`. `signature_invalid` is a reply
 * that failed verification or answered another request, which #37 keeps apart
 * so tampering does not blend into organic failures. `host_configuration` is the host
 * failing before any request existed. `decision_unrenderable` is a decision
 * that did arrive and that this host could not express, which none of the
 * other classes describe, so it falls to `other` with its own detail.
 * `unknown`, and any kind this table does not know, is `other`, and a rising
 * `other` count is the signal the list needs a row.
 */
export const FAILURE_CLASS_BY_KIND: Readonly<Record<string, FailureClass>> = {
  timeout: "timeout",
  transport: "unreachable",
  error_without_decision: "guardian_error",
  refused: "guardian_error",
  signature_invalid: "signature_invalid",
  host_configuration: "observed_agent_error",
};

export function failureClassOf(kind: unknown): FailureClass {
  return (typeof kind === "string" ? FAILURE_CLASS_BY_KIND[kind] : undefined) ?? "other";
}

/**
 * `acs.failure.detail` for each host kind: a sentence this converter writes,
 * never the host's `failure.message`. That message quotes the Guardian's
 * error text, and #228 forbids copying bytes from a response or an error into
 * the trace. The sentence is also the only place the host's kind survives,
 * since the class folds some kinds together. A kind this table does not
 * know gets the generic sentence; the kind string itself is never copied.
 */
export const FAILURE_DETAIL_BY_KIND: Readonly<Record<string, string>> = {
  timeout: "No decision arrived before the host's timeout.",
  transport: "The host could not reach the Guardian.",
  error_without_decision: GUARDIAN_ERROR_STATUS,
  refused: "The Guardian refused the request, and this host blocked the step.",
  signature_invalid: "A reply arrived that failed verification, and this host blocked the step.",
  host_configuration: "The host could not build a request for this hook.",
  decision_unrenderable: "A decision arrived, and this host could not express it in its hook output.",
};
const GENERIC_DETAIL = "The host recorded a failure this converter does not classify.";

/** The JSON-RPC code, parsed out of the two message shapes the host writes
 * (packages/host-adapter/src/failure-posture.ts). Only the integer is
 * taken; nothing else in the message is copied. */
const ERROR_CODE_IN_MESSAGE = /^guardian (?:refused the envelope with|returned) error (-?\d+):/;

/**
 * The host adapter's `toSessionUuid` (packages/host-adapter/src/build-envelope.ts),
 * copied because host-adapter already depends on this package, so importing
 * it would be a cycle. The Guardian's spans carry this derived UUID, not the
 * host's raw session id, so a converter span has to carry it too or the two
 * files cannot be joined. The root test pins the two as equal.
 */
const SESSION_ID_NAMESPACE = "11c79ebd-8469-4b4e-8de0-72674add484c";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function sessionUuid(rawSessionId: string): string {
  if (UUID_RE.test(rawSessionId)) {
    return rawSessionId.toLowerCase();
  }
  const namespaceBytes = Buffer.from(SESSION_ID_NAMESPACE.replace(/-/g, ""), "hex");
  const hash = createHash("sha1")
    .update(Buffer.concat([namespaceBytes, Buffer.from(rawSessionId, "utf8")]))
    .digest();
  hash[6] = (hash[6]! & 0x0f) | 0x50; // version 5
  hash[8] = (hash[8]! & 0x3f) | 0x80; // RFC 4122 variant
  const hex = hash.subarray(0, 16).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

export type ConversionSummary = {
  /** Spans built from the log. */
  converted: number;
  /** Spans the file exporter confirmed written. Differs from `converted`
   * only when an export failed, and then the command exits non-zero. */
  written: number;
  /** Posture entries whose method the mapping names no span for. */
  skippedUnmapped: number;
  /** Posture entries with no method, counted by failure kind. */
  skippedNoMethod: Record<string, number>;
  /** REPLAY_DETECTED errors. */
  skippedReplay: number;
  /** Steps no gate asked about. */
  skippedUngoverned: number;
  /** Lines that were not JSON, not an audit entry, or had no posture. */
  skippedUnreadable: number;
};

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

/** Counts the spans the wrapped exporter reports written, so the summary
 * says what reached the file and not what was handed to the SDK. */
function countingExporter(inner: SpanExporter): { exporter: SpanExporter; written: () => number } {
  let written = 0;
  return {
    written: () => written,
    exporter: {
      export(spans: ReadableSpan[], done: (result: ExportResult) => void): void {
        inner.export(spans, (result) => {
          if (result.code === ExportResultCode.SUCCESS) {
            written += spans.length;
          }
          done(result);
        });
      },
      shutdown: () => inner.shutdown(),
      forceFlush: () => inner.forceFlush?.() ?? Promise.resolve(),
    },
  };
}

/** The converter's `service.name` and tracer name. Its own, not the
 * Guardian's: these spans are derived after the fact from the host's audit
 * log, and `acs.failure.reported_by` on each event already says which party
 * claims the failure. A label, not attribution (see the Guardian README). */
export const CONVERTER_SERVICE_NAME = "acs-reference-audit-converter";

export async function convertAuditLog(auditPath: string, otelPath: string, mappingPath?: string): Promise<ConversionSummary> {
  // Everything that can fail without writing goes first, so a wrong audit
  // path or a bad mapping leaves no output behind to block the rerun.
  const mapping = loadOtelMapping(mappingPath);
  const auditText = readFileSync(auditPath, "utf8");
  // Exclusive create: an output path that exists when the converter starts is
  // refused before anything is written. That one check covers the log itself,
  // a hardlink to it, a symlink, the Guardian's own trace file, and a second
  // run over the same output, each of which the append-only exporter would
  // otherwise corrupt or double. It does not stop another process swapping
  // the path mid-run. Nothing here defends against a same-user writer.
  mkdirSync(dirname(otelPath), { recursive: true, mode: 0o700 });
  try {
    closeSync(openSync(otelPath, "wx", 0o600));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error(`refusing to write ${otelPath}: it already exists, perhaps from an earlier or failed run. Give the converter a new file, or delete this one first.`);
    }
    throw error;
  }
  const output = countingExporter(createFileSpanExporter(otelPath));
  // One span per export, not batched: a batch processor's bounded queue
  // overflowed inside this synchronous loop and dropped spans silently.
  // Sampler set explicitly, so no OTEL_TRACES_SAMPLER can drop them either.
  const provider = new BasicTracerProvider({
    resource: resourceFromAttributes({ "service.name": CONVERTER_SERVICE_NAME }),
    sampler: new AlwaysOnSampler(),
    // Frozen shared limits, copied: no OTEL_* variable may truncate or drop output.
    spanLimits: { ...SPAN_LIMITS },
    spanProcessors: [new SimpleSpanProcessor(output.exporter)],
  });
  const tracer = provider.getTracer(CONVERTER_SERVICE_NAME);
  const summary: ConversionSummary = {
    converted: 0,
    written: 0,
    skippedUnmapped: 0,
    skippedNoMethod: {},
    skippedReplay: 0,
    skippedUngoverned: 0,
    skippedUnreadable: 0,
  };

  for (const line of auditText.split("\n")) {
    if (line.trim() === "") continue;
    let entry: JsonObject | undefined;
    try {
      entry = asObject(JSON.parse(line));
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
    // acs.failure.posture is the deployment's posture (#228), which the host
    // records on every posture entry. Inferring it from `outcome` would be
    // wrong for a refusal, which is blocked whatever the posture said.
    const posture = readString(entry.posture);
    if ((outcome !== "proceeded" && outcome !== "blocked") || (posture !== "proceed" && posture !== "deny")) {
      summary.skippedUnreadable += 1;
      continue;
    }
    const failure = asObject(entry.failure) ?? {};
    const kind = readString(failure.kind);
    const method = readString(entry.method);
    if (method === undefined) {
      const key = kind !== undefined && kind in FAILURE_DETAIL_BY_KIND ? kind : "other";
      summary.skippedNoMethod[key] = (summary.skippedNoMethod[key] ?? 0) + 1;
      continue;
    }
    const spanName = mapping.stepToSpan[method]?.span_name;
    if (spanName === undefined) {
      summary.skippedUnmapped += 1;
      continue;
    }
    const codeText = ERROR_CODE_IN_MESSAGE.exec(readString(failure.message) ?? "")?.[1];
    const errorCode = codeText === undefined ? undefined : Number(codeText);
    if (errorCode === REPLAY_DETECTED_CODE) {
      summary.skippedReplay += 1;
      continue;
    }

    const instant = readInstant(entry.recorded_at);
    const detail = (kind !== undefined ? FAILURE_DETAIL_BY_KIND[kind] : undefined) ?? GENERIC_DETAIL;
    const attributes: Attributes = {};
    const sessionId = readString(entry.session_id);
    if (sessionId !== undefined) {
      attributes["acs.session.id"] = sessionUuid(sessionId);
    }
    // The entry's request_id is the id the Guardian's span for the same
    // request carries. Entries written before that field existed have only
    // rpc_id, which equalled params.request_id whenever the host did not
    // derive the request id from its own call id.
    const requestId = readString(entry.request_id) ?? readString(entry.rpc_id);
    if (requestId !== undefined) {
      attributes["acs.request_id"] = requestId;
    }
    // The entry is one instant, so the span is too: it opens and closes at
    // recorded_at. The host, not the Guardian, is the reporter.
    const span = tracer.startSpan(spanName, { attributes, root: true, startTime: instant });
    span.addEvent(
      DECISION_FAILURE_EVENT,
      decisionFailureAttributes({
        class: failureClassOf(kind),
        posture: posture === "deny" ? "fail_closed" : "fail_open",
        reportedBy: "observed_agent",
        detail,
        errorCode,
      }),
      instant,
    );
    span.setStatus({ code: SpanStatusCode.ERROR, message: detail });
    span.end(instant);
    summary.converted += 1;
  }

  // Every export has settled once forceFlush resolves, so the count is final
  // here; shutdown then releases the processor.
  await provider.forceFlush();
  summary.written = output.written();
  await provider.shutdown();
  return summary;
}

if (import.meta.main) {
  const [auditPath, otelPath] = Bun.argv.slice(2);
  if (auditPath === undefined || otelPath === undefined) {
    console.error("usage: bun run packages/guardian/src/audit-to-otlp.ts <audit.jsonl> <otel-file.jsonl>");
    process.exit(2);
  }
  let summary: ConversionSummary;
  try {
    summary = await convertAuditLog(auditPath, otelPath);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
  const noMethod = Object.entries(summary.skippedNoMethod)
    .map(([kind, count]) => `${count} ${kind}`)
    .join(", ");
  console.log(
    `wrote ${summary.written} of ${summary.converted} span(s) to ${otelPath}; skipped ${summary.skippedUnmapped} with no mapping entry, ` +
      `${noMethod === "" ? 0 : noMethod} with no method, ${summary.skippedReplay} replay, ` +
      `${summary.skippedUngoverned} ungoverned, ${summary.skippedUnreadable} unreadable`,
  );
  if (summary.written !== summary.converted) {
    console.error(`only ${summary.written} of ${summary.converted} span(s) reached ${otelPath}`);
    process.exit(1);
  }
}
