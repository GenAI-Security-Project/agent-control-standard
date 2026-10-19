// SPDX-License-Identifier: Apache-2.0
import { createWriteStream, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { Writable } from "node:stream";
import { finished } from "node:stream/promises";

export type BatchedLogWriter = {
  readonly droppedRecords: number;
  write(line: string): void;
  close(): Promise<void>;
};

export const NULL_LOG_WRITER: BatchedLogWriter = {
  droppedRecords: 0,
  write() {},
  async close() {},
};

/** Batches complete JSONL records without waiting for disk on the decision path.
 * Both queued and in-flight writes count toward the bounds. Overflow drops
 * only the new record; a disk failure still disables the sink. */
export function batchLogWrites(
  stream: Writable,
  onError: (error: unknown) => void,
  { batchSize = 64, flushIntervalMs = 100, maxBufferedBytes = 4 * 1024 * 1024, maxBufferedRecords = 4096, onDrop = (_count: number) => {} } = {},
): BatchedLogWriter {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let batchCount = 0;
  let pendingRecords = 0;
  let closed = false;
  let failed = false;
  let droppedRecords = 0;
  const reportDrops = (): void => {
    try {
      onDrop(droppedRecords);
    } catch {
      // Reporting must not break governance.
    }
  };

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
    get droppedRecords() { return droppedRecords; },
    write(line) {
      if (closed || failed) return;
      try {
        const bytes = Buffer.byteLength(line);
        if (stream.writableLength + bytes > maxBufferedBytes || pendingRecords >= maxBufferedRecords) {
          droppedRecords += 1;
          if (droppedRecords === 1) reportDrops();
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
        if (droppedRecords > 0) reportDrops();
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
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  } catch (error) {
    fail(error);
  }
  return {
    get droppedRecords() { return writer?.droppedRecords ?? 0; },
    write(line) {
      if (closed || disabled) return;
      try {
        // Keep the existing no-traffic behavior: no file until the first record.
        writer ??= batchLogWrites(createWriteStream(path, { flags: "a", mode: 0o600 }), fail, {
          onDrop: (count) => console.error(`log buffer overflow (${path}): ${count} records dropped; queued records retained`),
        });
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
