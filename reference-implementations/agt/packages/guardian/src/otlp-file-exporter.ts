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

/** O_NOFOLLOW makes the open itself fail on a symlink at the final path, so
 * no check can be raced. O_NONBLOCK makes it return at once on a FIFO, where
 * a blocking open waits for a reader that may never come. */
const POSIX_OPEN_FLAGS = constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK;
/** Windows has neither flag. */
const WINDOWS_OPEN_FLAGS = constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT;

/** A refusal names the path and the reason, because the caller reports it to
 * an operator who has to find the file. */
function refusal(path: string, reason: string): Error {
  return new Error(`refusing to write ${path}: ${reason}`);
}

/** Whether the user this process runs as owns the file or directory. The
 * user is read at each check, not once, so a process that changed its user
 * after it started is judged as who it is now. */
function ownedByThisUser(stats: { uid: number }): boolean {
  return stats.uid === process.geteuid?.();
}

/** The directory's part of appendLine's checks, described there. The
 * converter calls it before it creates its output, so a refused directory is
 * left with no file in it. */
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
 * Appends one line to the trace file, or refuses. The file holds reasoning
 * text and provenance source ids, so a line must not reach a file another
 * user can read, or a file some link has put in the path's place (issue
 * #283).
 *
 * The directory is checked first, so nothing is created through one that
 * fails. It must not be a symlink, the user must own it, and it must not be
 * writable by every user: in such a directory another user can put a link or
 * a file of their own at the path before the Guardian starts. A directory
 * its group can write to is accepted. Only the immediate parent is checked.
 * The temp directory on macOS sits under a system symlink, so a walk further
 * up would refuse every path there. The directory is checked by name, because
 * the runtime has no openat. The file's own checks below still hold if the
 * directory is swapped after that look.
 *
 * The file is then opened and judged by its descriptor, never by its path,
 * so the file checked is the file written. It is refused when it is a
 * symlink, when it is not a regular file, when it has a second hard link, or
 * when another user owns it. A file whose mode is wider than 0600 is not
 * refused. It is set to 0600: PR #112 keeps existing file modes, and a
 * refusal would turn the trace off in the walkthrough (issue #274).
 *
 * On Windows (`windows` true) this protects less. There is no O_NOFOLLOW,
 * so a symlink at the path is found by looking before the open, and one put
 * there between the look and the open is followed. A symlink as the
 * directory, a second hard link and a non-regular file are refused as on
 * POSIX. No owner is checked and no mode is set: Windows decides access by
 * ACL, which this neither reads nor changes, so who can read the file is
 * whatever its directory's ACL grants.
 */
async function appendLine(path: string, line: string, windows: boolean): Promise<void> {
  await checkTraceDirectory(path, windows);
  if (windows) {
    // A path that is not there yet has no link to find, and the open below
    // creates it. Any other failure to look is the open's to report.
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
  /** Which platform's rules the append follows. Defaults to this process's
   * own. It is an option so the Windows branch can be tested anywhere. On
   * POSIX, "win32" switches off O_NOFOLLOW, the owner checks and the mode. */
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
 * when the exporter creates it. The file is opened again on every append and
 * checked each time, and an existing file is set to 0o600 (see appendLine).
 * A path that fails a check is refused through that batch's callback, with a
 * message that names the path and the reason.
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
