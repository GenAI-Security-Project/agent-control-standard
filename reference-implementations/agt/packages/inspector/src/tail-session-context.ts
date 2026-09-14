/**
 * tailSessionContextLog, the Inspector's session-context reader, streams the
 * Guardian's per-session hash chain -- appended one JSONL line per entry by
 * packages/guardian/src/session-context-store.ts -- as it grows, the way
 * `tail -f` does.
 *
 * Same contract as tailAuditLog: same option shape, same lazily-started
 * poll, same eagerly-captured starting offset, same Buffer-based
 * partial-line reassembly, same shape check between `JSON.parse` and
 * `yield`, same report-once discipline for a poll that fails and for a log
 * that goes missing after having existed. That design is not re-derived
 * here; see tail-audit-log.ts's module doc for the reasoning behind each of
 * those choices, all of which apply unchanged to this file.
 *
 * This chain's log, like the audit log, is created lazily by its writer on
 * the first entry appended: packages/guardian/src/server.ts's
 * session-context-log appender calls `appendFileSync`, which creates the
 * file on its first call. A session that never appends an entry never
 * creates this file at all, and that must stay silent rather than reported
 * as a missing log -- the same healthy-absence case tail-audit-log.ts's
 * module doc describes for the audit log.
 *
 * This package imports nothing from the Guardian's own package:
 * `SessionContextLogEntry` is re-declared here rather than imported, and the
 * round-trip contract test at test/session-context-roundtrip.test.ts is what
 * keeps the two declarations in agreement.
 *
 * One file holds many sessions. The Guardian appends every session's entries
 * to this one log, in whatever order its own single process happens to
 * append them. `seq` is per session (packages/guardian/src/session-context.ts),
 * so a file's lines are not globally ordered by it. This reader makes no
 * attempt to sort or group entries by session; it yields each line in the
 * order it appears in the file, carrying its own `session_id`, and leaves
 * grouping to whatever reads the stream. `renderSessionChain` (render.ts) is
 * the reader that groups: a chain-break check comparing an entry only to the
 * line immediately before it, with no regard for which session either one
 * belongs to, would report a break every time two different sessions'
 * entries happened to interleave.
 */
import { closeSync, existsSync, openSync, readSync, statSync } from "node:fs";

/**
 * The Inspector's own reader-side entry type. Declares its own shape rather
 * than importing the Guardian's -- the Inspector imports nothing from that
 * package and proves it by reading the chain as a plain file.
 * `test/session-context-roundtrip.test.ts` is what keeps this declaration
 * honest against the writer's.
 */
export type SessionContextLogEntry = {
  session_id: string;
  seq: number;
  prev_hash: string;
  hash: string;
  recorded_at: string;
  method: string;
  request_id: string;
  tool_name: string;
};

export type TailSessionContextLogOptions = {
  path: string;
  /** Replay everything already in the file before following. Default false:
   * start at the current end, like `tail -f`. */
  fromStart?: boolean;
  pollMs?: number;
  signal?: AbortSignal;
  /** Called per unparseable line. Defaults to one stderr warning. Streaming
   * continues either way -- a corrupt line is not a reason to stop showing
   * the ones after it. */
  onMalformedLine?: (line: string, error: unknown) => void;
  /** Called when a poll fails to read the log -- including the log having
   * existed and then gone missing. Defaults to one stderr warning per failed
   * tick. Streaming continues either way. */
  onPollError?: (error: unknown) => void;
};

const NEWLINE = 0x0a;

/**
 * The session-context log is a plain file on disk; anything can write a
 * line to it that is valid JSON but not a valid SessionContextLogEntry.
 * Checked here, right after `JSON.parse`, using every field the renderer
 * depends on, so a line of the wrong shape is routed to `onMalformedLine`
 * instead of reaching a consumer that assumes every field is present and
 * correctly typed.
 */
function isSessionContextLogEntryShape(value: unknown): value is SessionContextLogEntry {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.session_id === "string" &&
    typeof candidate.seq === "number" &&
    typeof candidate.prev_hash === "string" &&
    typeof candidate.hash === "string" &&
    typeof candidate.recorded_at === "string" &&
    typeof candidate.method === "string" &&
    typeof candidate.request_id === "string" &&
    typeof candidate.tool_name === "string"
  );
}

export function tailSessionContextLog({
  path,
  fromStart = false,
  pollMs = 120,
  signal,
  onMalformedLine = warnMalformedLine,
  onPollError = warnPollError,
}: TailSessionContextLogOptions): AsyncGenerator<SessionContextLogEntry, void, void> {
  let offset = fromStart ? 0 : sizeOf(path);
  // Bytes, not a string: a poll can land mid-line and, worse, mid-codepoint.
  // Decoding only complete lines keeps multi-byte UTF-8 intact.
  let pending = Buffer.alloc(0);
  // Becomes true the first tick the log is seen to exist, and stays true
  // forever after -- it is what tells a later "the log is gone" tick that
  // this is a real disappearance and not just "still hasn't been created".
  let everExisted = false;
  // True from the tick absence is first observed until the tick the log is
  // seen to exist again. Doubles as the report-once guard (checked, and set,
  // only on the *first* tick of a gap) and as the reset-once trigger
  // consulted the moment existence returns.
  let missingSinceLastSeen = false;
  // The same report-once discipline for the OTHER way a poll can fail: a
  // read that throws on a log that does exist -- a permission error, or a
  // path that is a directory. Cleared by the first tick that completes a
  // read, so a fault that comes back is reported again.
  let pollFailing = false;

  // Entries the timer has parsed but nobody has consumed yet, and the
  // wake-up the drain loop below is currently parked on while that queue is
  // empty. The timer and the generator only communicate through these two.
  const ready: SessionContextLogEntry[] = [];
  let wake: (() => void) | undefined;
  let stopped = false;
  let timer: ReturnType<typeof setInterval> | undefined;

  function poll(): void {
    if (stopped) {
      return;
    }
    try {
      if (!existsSync(path)) {
        if (everExisted && !missingSinceLastSeen) {
          // First tick of a real gap -- the log existed a moment ago and
          // does not now. Reported here, once; every tick after this one,
          // for as long as the gap continues, takes the
          // `missingSinceLastSeen` branch above instead and reports
          // nothing further.
          missingSinceLastSeen = true;
          reportPollError(onPollError, new Error(`session context log not found at ${path}`));
        }
        // A log that has never existed at all is not a gap and is not
        // reported -- see the module doc: this is the healthy "no entries
        // yet" case, and it must stay silent for as long as it lasts.
        return;
      }

      if (missingSinceLastSeen) {
        // The log just came back. Whatever is on disk now is not assumed
        // to be a continuation of what "offset" already accounts for.
        missingSinceLastSeen = false;
        offset = 0;
        pending = Buffer.alloc(0);
      }
      everExisted = true;

      const size = statSync(path).size;

      if (size < offset) {
        // Truncated or rotated underneath us (`: > .acs/session-context.jsonl`).
        offset = 0;
        pending = Buffer.alloc(0);
      }

      if (size > offset) {
        pending = Buffer.concat([pending, readRange(path, offset, size - offset)]);
        offset = size;

        let added = false;
        try {
          let newline = pending.indexOf(NEWLINE);
          while (newline !== -1) {
            const line = pending.subarray(0, newline).toString("utf8");
            pending = pending.subarray(newline + 1);
            newline = pending.indexOf(NEWLINE);

            if (line.trim() === "") {
              continue;
            }
            try {
              const parsed: unknown = JSON.parse(line);
              if (!isSessionContextLogEntryShape(parsed)) {
                throw new Error("line parsed as JSON but does not match the SessionContextLogEntry shape");
              }
              ready.push(parsed);
              added = true;
            } catch (error) {
              // Guarded here, not left to poll()'s outer catch: `offset` is
              // already at `size`, so a complete line still sitting in
              // `pending` behind a bad one would never be re-scanned on a
              // later tick. One malformed line must not cost the good ones
              // behind it.
              reportMalformedLine(onMalformedLine, line, error);
            }
          }
        } finally {
          // In the `finally`, not after the loop: an entry already pushed
          // to `ready` must reach the consumer even if the scan above left
          // by a throw.
          if (added) {
            wake?.();
          }
        }
      }

      // Reached only when this tick read the log without throwing, so the
      // next failure is a new incident and is reported. Deliberately not
      // reached by the early `return` in the missing-file branch above: an
      // absent log is not a successful read, and it has its own
      // once-per-transition guard.
      pollFailing = false;
    } catch (error) {
      // A timer callback, not a step inside the generator's own call stack:
      // nothing here is awaiting a promise that could catch a throw, so an
      // uncaught one would take the whole process down. Skip this tick
      // instead -- the next one resyncs on its own once the log is
      // readable again.
      //
      // Reported once per transition into failure, not once per tick: a
      // permission error on a file that exists is a standing condition, and
      // repeating it every `pollMs` buries the entries this tool exists to
      // show under a wall of identical lines.
      if (!pollFailing) {
        pollFailing = true;
        reportPollError(onPollError, error);
      }
    }
  }

  function stop(): void {
    if (stopped) {
      return;
    }
    stopped = true;
    if (timer !== undefined) {
      clearInterval(timer);
    }
    signal?.removeEventListener("abort", stop);
    wake?.();
  }

  signal?.addEventListener("abort", stop, { once: true });
  if (signal?.aborted) {
    stop();
  }

  return drain();

  async function* drain(): AsyncGenerator<SessionContextLogEntry, void, void> {
    // Starting the timer here, not above, means a tail nobody ever iterates
    // (and nobody ever aborts) never ticks at all.
    if (!stopped) {
      timer = setInterval(poll, pollMs);
    }
    try {
      while (true) {
        while (ready.length === 0 && !stopped) {
          await new Promise<void>((resolve) => {
            wake = resolve;
          });
          wake = undefined;
        }
        if (ready.length === 0) {
          return;
        }
        const entry = ready.shift();
        if (entry !== undefined) {
          yield entry;
        }
      }
    } finally {
      stop();
    }
  }
}

/** Used only for the eager, at-call-time starting offset (see the module
 * doc on tail-envelope-log.ts for why that capture cannot be deferred into
 * the generator body). A log that has not been created yet is size zero
 * here, same as tail-audit-log.ts's sizeOf. */
function sizeOf(path: string): number {
  if (!existsSync(path)) {
    return 0;
  }
  try {
    return statSync(path).size;
  } catch {
    return 0;
  }
}

function readRange(path: string, offset: number, length: number): Buffer {
  const buffer = Buffer.alloc(length);
  const fd = openSync(path, "r");
  try {
    const read = readSync(fd, buffer, 0, length, offset);
    return buffer.subarray(0, read);
  } finally {
    closeSync(fd);
  }
}

/** Calls the caller's malformed-line reporter without letting it break the
 * scan. A reporter that throws gets one warning of its own; the line it was
 * reporting is still skipped, and the lines after it are still parsed. */
function reportMalformedLine(
  onMalformedLine: (line: string, error: unknown) => void,
  line: string,
  error: unknown,
): void {
  try {
    onMalformedLine(line, error);
  } catch (callbackError) {
    const message = callbackError instanceof Error ? callbackError.message : String(callbackError);
    console.error(`onMalformedLine threw while reporting an unparseable session-context-log line (${message})`);
  }
}

/** Same guard as reportMalformedLine, for the poll-error callback. */
function reportPollError(onPollError: (error: unknown) => void, error: unknown): void {
  try {
    onPollError(error);
  } catch (callbackError) {
    const message = callbackError instanceof Error ? callbackError.message : String(callbackError);
    console.error(`onPollError threw while reporting a failed session-context-log poll (${message})`);
  }
}

function warnMalformedLine(line: string, error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`skipping unparseable session-context-log line (${message}): ${line.slice(0, 120)}`);
}

function warnPollError(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`session context log poll failed, retrying next tick (${message})`);
}
