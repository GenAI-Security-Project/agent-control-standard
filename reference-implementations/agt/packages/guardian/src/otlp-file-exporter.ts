/**
 * The OTLP/JSON file output, the one span exporter this package writes
 * itself. The Guardian's exporter and the audit-log converter both use it,
 * so the two files share one shape.
 */
import { constants, mkdirSync } from "node:fs";
import { lstat, open, type FileHandle } from "node:fs/promises";
import { dirname } from "node:path";
import { ExportResultCode } from "@opentelemetry/core";
import { JsonTraceSerializer } from "@opentelemetry/otlp-transformer";
import type { SpanExporter } from "@opentelemetry/sdk-trace-base";

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

// O_NOFOLLOW makes the open fail on a symlink at the final path, so no check
// can be raced. O_NONBLOCK stops the open waiting on a FIFO with no reader.
// Windows has neither flag.
const POSIX_OPEN_FLAGS = constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const WINDOWS_OPEN_FLAGS = constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT;

function refusal(path: string, reason: string): Error {
  return new Error(`refusing to write ${path}: ${reason}`);
}

function ownedByThisUser(stats: { uid: number }): boolean {
  return stats.uid === process.geteuid?.();
}

export async function checkTraceDirectory(path: string, windows = process.platform === "win32"): Promise<void> {
  // lstat follows a link named with a trailing "/" or "/.", so both are cut.
  const directory = dirname(path).replace(/(?:\/\.?)+$/, "") || "/";
  const parent = await lstat(directory);
  if (parent.isSymbolicLink()) {
    throw refusal(path, `its directory ${directory} is a symbolic link`);
  }
  if (windows) {
    return;
  }
  if (!ownedByThisUser(parent)) {
    throw refusal(path, `its directory ${directory} is not owned by the user running this process`);
  }
  if ((parent.mode & 0o002) !== 0) {
    throw refusal(path, `its directory ${directory} is writable by every user`);
  }
}

/**
 * The trace file holds reasoning text and provenance source ids, so a line
 * must not reach a file another user can read or a link put in its place
 * (#283). In a directory every user can write to, another user can plant
 * one before the Guardian starts, so the directory is checked first. Only
 * the immediate parent is checked, because the macOS temp directory sits
 * under a system symlink. Bun has no openat, so the directory is checked by
 * name. The file checks still hold if it is swapped after that.
 *
 * Bun's appendFile follows a symlink even with O_NOFOLLOW, so the file is
 * opened here and judged by its descriptor: the file checked is the file
 * written. A mode wider than 0600 is narrowed, not refused, because a refusal
 * would turn the trace off in the walkthrough (#274).
 *
 * Windows has no O_NOFOLLOW, so a symlink is found by looking before the
 * open, and one put there in between is followed. No owner or mode is
 * checked there: Windows decides access by ACL, which this leaves alone.
 */
async function appendLine(path: string, line: string, windows: boolean): Promise<void> {
  await checkTraceDirectory(path, windows);
  if (windows) {
    // A missing path is fine: the open creates it.
    const existing = await lstat(path).catch(() => undefined);
    if (existing?.isSymbolicLink()) {
      throw refusal(path, "it is a symbolic link");
    }
  }

  let handle: FileHandle;
  try {
    handle = await open(path, windows ? WINDOWS_OPEN_FLAGS : POSIX_OPEN_FLAGS, 0o600);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    // ELOOP is O_NOFOLLOW meeting a symlink. ENXIO is a FIFO with no reader.
    if (code === "ELOOP") {
      throw refusal(path, "it is a symbolic link");
    }
    if (code === "ENXIO") {
      throw refusal(path, "it is not a regular file");
    }
    throw error;
  }
  try {
    const stats = await handle.stat();
    if (!stats.isFile()) {
      throw refusal(path, "it is not a regular file");
    }
    if (stats.nlink > 1) {
      throw refusal(path, "it has more than one hard link");
    }
    if (!windows) {
      if (!ownedByThisUser(stats)) {
        throw refusal(path, "it is not owned by the user running this process");
      }
      if ((stats.mode & 0o7777) !== 0o600) {
        await handle.chmod(0o600);
      }
    }
    await handle.appendFile(line);
  } finally {
    await handle.close();
  }
}

export type FileSpanExporterOptions = {
  /** Lets a test run the Windows branch on POSIX. */
  platform?: NodeJS.Platform;
};

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
 * (#71 is the same problem in the envelope log). The directory's mode applies
 * when the exporter creates it. Each append checks the file again and sets it
 * to 0o600 (see appendLine).
 */
export function createFileSpanExporter(path: string, { platform = process.platform }: FileSpanExporterOptions = {}): SpanExporter {
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
      const write = chain.then(() => appendLine(path, line, platform === "win32"));
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
