// SPDX-License-Identifier: Apache-2.0
import { createWriteStream, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { Writable } from "node:stream";
import { finished } from "node:stream/promises";

export type BatchedLogWriter = {
  write(line: string): void;
  close(): Promise<void>;
};

export const NULL_LOG_WRITER: BatchedLogWriter = {
  write() {},
  async close() {},
};

/** Batches complete JSONL records without waiting for disk on the decision path.
 * Both queued and in-flight writes count toward the bounds. A failed or full
 * sink is disabled and reported once, as the existing log sinks require. */
export function batchLogWrites(
  stream: Writable,
  onError: (error: unknown) => void,
  { batchSize = 64, flushIntervalMs = 100, maxBufferedBytes = 4 * 1024 * 1024, maxBufferedRecords = 4096 } = {},
): BatchedLogWriter {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let batchCount = 0;
  let pendingRecords = 0;
  let closed = false;
  let failed = false;

  const clearTimer = (): void => {
    clearTimeout(timer);
    timer = undefined;
  };
  const fail = (error: unknown): void => {
    if (failed) return;
    failed = true;
    clearTimer();
    stream.destroy();
    try {
      onError(error);
    } catch {
      // A reporter must not turn a logging failure into a policy failure.
    }
  };
  const completion = finished(stream).catch(fail);

  const flush = (): void => {
    clearTimer();
    batchCount = 0;
    stream.uncork();
  };

  return {
    write(line) {
      if (closed || failed) return;
      try {
        const bytes = Buffer.byteLength(line);
        if (stream.writableLength + bytes > maxBufferedBytes || pendingRecords >= maxBufferedRecords) {
          fail(new Error("log buffer limit exceeded; queued records may be lost"));
          return;
        }
        if (batchCount === 0) stream.cork();
        pendingRecords += 1;
        stream.write(line, () => { pendingRecords -= 1; });
        batchCount += 1;
        if (batchCount >= batchSize) {
          flush();
        } else if (timer === undefined) {
          timer = setTimeout(flush, flushIntervalMs);
        }
      } catch (error) {
        fail(error);
      }
    },
    close() {
      if (!closed) {
        closed = true;
        clearTimer();
        // end() uncorks pending records and finishes all outstanding writes.
        stream.end();
      }
      return completion;
    },
  };
}

export function createBatchedFileLog(path: string, onError: (error: unknown) => void): BatchedLogWriter {
  let writer: BatchedLogWriter | undefined;
  let disabled = false;
  let closed = false;
  const fail = (error: unknown): void => {
    if (disabled) return;
    disabled = true;
    try {
      onError(error);
    } catch {
      // Match asynchronous write failures: reporting cannot break governance.
    }
  };
  try {
    mkdirSync(dirname(path), { recursive: true });
  } catch (error) {
    fail(error);
  }
  return {
    write(line) {
      if (closed || disabled) return;
      try {
        // Keep the existing no-traffic behavior: no file until the first record.
        writer ??= batchLogWrites(createWriteStream(path, { flags: "a" }), fail);
        writer.write(line);
      } catch (error) {
        fail(error);
      }
    },
    async close() {
      closed = true;
      await writer?.close();
    },
  };
}
