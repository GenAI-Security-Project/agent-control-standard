/**
 * tailEnvelopeLog streams the Guardian's JSONL envelope log as it grows, the
 * way `tail -f` does.
 *
 * This package deliberately imports nothing from `guardian` or from any of
 * its dependencies. The Inspector reads a file that the Guardian happens to
 * write, and holds no compile-time knowledge of the process that produced
 * it: envelopes are inspectable on the wire, not through a shared type
 * graph. `EnvelopeLogEntry` is therefore re-declared here rather than
 * imported. The round-trip test at test/envelope-log-sink-roundtrip.test.ts
 * keeps the two declarations in agreement; if they drift, it fails.
 *
 * The names are the artifact's, not the writer's: `EnvelopeLogEntry` and
 * `TailEnvelopeLogOptions` name the log they describe, not the Guardian's
 * own writing mechanism, so a second log stream in this package would read
 * as this one's sibling rather than force a shared, ambiguous vocabulary
 * between them.
 *
 * Polling rather than fs.watch: appends to a growing file are exactly the
 * case where watch semantics differ most across platforms, and a 120ms poll
 * on a local demo log costs nothing.
 *
 * The poll runs on its own timer once started, independent of whether
 * anything is actively pulling values from the returned generator. That
 * independence is load-bearing, not incidental: a consumer can read one
 * entry and then pause before asking for the next one, and the file can be
 * truncated and rewritten entirely within that pause. A poll folded into
 * the generator's own suspend/resume points only ever inspects the file at
 * the instant the consumer resumes it -- by then a truncate-and-rewrite can
 * look exactly like ordinary growth (a same-length-or-longer rewrite makes
 * the new size come out >= the old offset, so a size-only check never
 * fires). A timer that keeps ticking regardless of consumption catches the
 * file while it is still sitting at zero.
 *
 * The timer itself, though, only starts on the first `next()` -- inside the
 * returned generator's body, not inside this function. A caller that builds
 * a tail and never iterates it (and never aborts) should not leave a timer
 * running forever; tying its start to first consumption means an unused
 * tail costs nothing.
 *
 * The starting offset is a separate concern from the timer, and is captured
 * synchronously right here, when this function is called -- not lazily
 * inside the generator body, which would not run at all until the caller's
 * first `next()`. "Start at the current end" has to mean the moment
 * `tailEnvelopeLog` was called, not the moment someone first asked it for a
 * value; the truncation scenario above still works even though the timer
 * itself starts later, because by the time a consumer has read anything at
 * all, `next()` has already been called once and the timer is already
 * running.
 *
 * `poll()` runs as a bare timer callback with nothing awaiting it, so
 * nothing is in a position to catch a thrown error the way a rejected
 * promise would be caught by a consumer's `for await`. A file that
 * disappears between the size check and the read -- rotation schemes that
 * unlink-and-recreate rather than truncate-in-place can do this -- must
 * therefore be handled inside `poll()` itself; letting it throw out of a
 * timer callback would crash the whole process instead of merely losing a
 * line.
 */
import { closeSync, existsSync, openSync, readSync, statSync } from "node:fs";

export type EnvelopeLogDirection = "request" | "response";

/** One line of the envelope log the Guardian writes. */
export type EnvelopeLogEntry = {
  seq: number;
  recorded_at: string;
  direction: EnvelopeLogDirection;
  method: string | null;
  rpc_id: string | number | null;
  envelope: unknown;
};

export type TailEnvelopeLogOptions = {
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
};

const NEWLINE = 0x0a;

/**
 * The envelope log is a plain file on disk; anything can write a line to it
 * that is valid JSON but not a valid EnvelopeLogEntry (a number where
 * recorded_at should be a string, a missing direction, ...).
 * `renderEnvelopeLogEntry`'s `clockOf` calls `.slice` on `recorded_at`
 * unconditionally, so an unchecked cast would let such a line reach the
 * renderer and throw -- inside a `for await` loop, that kills the whole
 * stream. Checked here instead, right after `JSON.parse`, using exactly the
 * fields the renderer depends on. `envelope` is deliberately left
 * unconstrained: it is `unknown` by design, not a shape this function's job
 * to police.
 */
function isEnvelopeLogEntryShape(value: unknown): value is EnvelopeLogEntry {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.seq === "number" &&
    typeof candidate.recorded_at === "string" &&
    (candidate.direction === "request" || candidate.direction === "response") &&
    (typeof candidate.method === "string" || candidate.method === null) &&
    (typeof candidate.rpc_id === "string" || typeof candidate.rpc_id === "number" || candidate.rpc_id === null)
  );
}

export function tailEnvelopeLog({
  path,
  fromStart = false,
  pollMs = 120,
  signal,
  onMalformedLine = warnMalformedLine,
}: TailEnvelopeLogOptions): AsyncGenerator<EnvelopeLogEntry, void, void> {
  let offset = fromStart ? 0 : sizeOf(path);
  // Bytes, not a string: a poll can land mid-line and, worse, mid-codepoint.
  // Decoding only complete lines keeps multi-byte UTF-8 intact.
  let pending = Buffer.alloc(0);
  // True from the tick a read first fails until the tick one succeeds. A
  // failing read here is a standing condition (a permission error, a path
  // that is a directory), and warning once per `pollMs` for as long as it
  // lasts buries the entries this tool exists to show. Reported once per
  // transition into failure instead -- the same discipline
  // tail-audit-log.ts applies to a log that goes missing.
  let pollFailing = false;

  // Entries the timer has parsed but nobody has consumed yet, and the
  // wake-up the drain loop below is currently parked on while that queue is
  // empty. The timer and the generator only communicate through these two.
  const ready: EnvelopeLogEntry[] = [];
  let wake: (() => void) | undefined;
  let stopped = false;
  let timer: ReturnType<typeof setInterval> | undefined;

  function poll(): void {
    if (stopped) {
      return;
    }
    try {
      const size = sizeOf(path);

      if (size < offset) {
        // Truncated or rotated underneath us (`: > .acs/envelopes.jsonl`).
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
              if (!isEnvelopeLogEntryShape(parsed)) {
                throw new Error("line parsed as JSON but does not match the EnvelopeLogEntry shape");
              }
              ready.push(parsed);
              added = true;
            } catch (error) {
              // `onMalformedLine` is caller-supplied and may throw. Guarded
              // here rather than left to poll()'s outer catch, which would
              // abandon the rest of this batch: `offset` is already at
              // `size`, so any complete line still sitting in `pending`
              // would never be re-scanned -- no later tick has anything new
              // to read. Reporting one bad line must not cost the good ones
              // behind it.
              reportMalformedLine(onMalformedLine, line, error);
            }
          }
        } finally {
          // In the `finally`, not after the loop: an entry already pushed to
          // `ready` must reach the consumer even if the scan above left by a
          // throw, rather than sit undelivered until some unrelated write or
          // the abort happens to fire `wake`.
          if (added) {
            wake?.();
          }
        }
      }

      // Reached only when this tick read the log without throwing. `sizeOf`
      // is total, so a log that simply does not exist yet reaches here too
      // and clears nothing that was not already clear.
      pollFailing = false;
    } catch (error) {
      // A read can lose a race against a file that vanished between the
      // size check above and the read itself. There is no promise here for
      // that to reject into -- this is a timer callback, not a step inside
      // the generator's own call stack -- so an uncaught throw would take
      // the whole process down. Skip this tick instead: the next one's
      // sizeOf() sees the gap (or the file's return) and resyncs on its
      // own.
      //
      // The only route here is a failed read: a caller-supplied
      // `onMalformedLine` is guarded at its own call site (finding 5), so it
      // no longer reaches this catch and no longer abandons the rest of a
      // batch. The tail-envelope-log tests cover this branch through a
      // deterministic EISDIR rather than through a lost race.
      //
      // Warned once per transition into failure, not once per tick: a lost
      // race is a single event, but a directory or an unreadable file is a
      // standing condition, and this branch could not tell them apart.
      if (!pollFailing) {
        pollFailing = true;
        warnPollError(error);
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

  async function* drain(): AsyncGenerator<EnvelopeLogEntry, void, void> {
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
    console.error(`onMalformedLine threw while reporting an unparseable envelope-log line (${message})`);
  }
}

function warnMalformedLine(line: string, error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`skipping unparseable envelope-log line (${message}): ${line.slice(0, 120)}`);
}

function warnPollError(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`envelope log poll failed, retrying next tick (${message})`);
}
