/**
 * The OTLP/JSON file output, the one span exporter this package writes
 * itself. The Guardian's exporter and the audit-log converter both use it,
 * so the two files share one shape.
 */
import { mkdirSync } from "node:fs";
import { appendFile } from "node:fs/promises";
import { dirname } from "node:path";
import { ExportResultCode } from "@opentelemetry/core";
import { JsonTraceSerializer } from "@opentelemetry/otlp-transformer";
import type { SpanExporter } from "@opentelemetry/sdk-trace-base";

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

/**
 * Writes OTLP/JSON, one `ExportTraceServiceRequest` per line (the shape
 * the OpenTelemetry Collector's file exporter writes), serialised by the
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
