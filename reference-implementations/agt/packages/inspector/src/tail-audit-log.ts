/**
 * tailAuditLog streams the audit log -- the audit record §6.4 requires for
 * every step that proceeds with no decision behind it -- as it grows, the way
 * `tail -f` does. Same contract as tailEnvelopeLog: same option shape, same
 * lazily-started poll, same eagerly-captured starting offset, same
 * Buffer-based partial-line reassembly, same shape check between
 * `JSON.parse` and `yield`. That design is not re-derived here; see
 * tail-envelope-log.ts's module doc for the reasoning behind each of those
 * choices, all of which apply unchanged to this file.
 *
 * The audit log is written on the other side of the wire from the envelope
 * log: something that negotiates a failure posture, not anything running a
 * policy decision. This package still imports nothing from it. AuditEntry
 * is re-declared here for the same reason EnvelopeLogEntry is: the
 * round-trip contract test at test/audit-sink-roundtrip.test.ts is what
 * keeps the two declarations in agreement, and importing the other side's
 * type would make that agreement a tautology instead of a check.
 *
 * The raw session identifier versus the derived one, stated here because
 * render.ts's renderAuditEntry doc points at this paragraph for it. **The
 * audit log's `session_id` and the envelope log's are two different values;
 * the two logs cannot be joined on it.** The audit log records the
 * identifier the host itself uses -- whatever the host's own session is
 * called, which is also the key its session store is filed under. The
 * envelope log's envelopes carry `metadata.session_id`, which ACS's schemas
 * constrain to `format: uuid`, so a host whose session identifier is not
 * already a UUID has one *derived* from it before the envelope goes out.
 * Derivation is one-way as far as this package is concerned: nothing here can
 * turn one into the other, so nothing here tries. The mitigation is to label
 * rather than to correlate -- renderAuditEntry prints `audit_session=`, never
 * `session=`, so neither value can be misread as comparable to the other.
 * Making the two joinable is out of scope for this package; a future
 * session-chain feature is where that seam would need to be touched next.
 *
 * One divergence from tail-envelope-log.ts, deliberate rather than
 * incidental: there, a log file that does not exist yet is ordinary --
 * nothing has written to it, and `sizeOf` reports that as size zero with no
 * complaint. Here, a log that *existed and then went missing* is reported
 * through `onPollError` instead of silently read as size zero -- but a log
 * that has never yet appeared is still treated as size zero without
 * comment, exactly like tail-envelope-log.ts. That distinction matters
 * because a session with zero fail-open bypasses never creates the audit
 * log at all (the sink on the other side of the wire creates its file
 * lazily, on its first write) -- that is the *healthy* outcome, and it must
 * not read as an error repeated on every tick for as long as the Inspector
 * runs. A log that vanishes after this tailer had already read from it is a
 * different, genuinely reportable event -- but reported once, on the tick
 * the absence is first observed, not on every tick it remains absent: a
 * human watching this stream needs to be told the log went away, once, not
 * shown the same line every poll interval forever.
 *
 * Because the poll after recreation must not assume whatever is on disk now
 * continues what was read before -- an unlink-and-recreate can land a
 * same-length replacement at the very offset already consumed, which a
 * size-only comparison would then read as no growth at all -- the offset is
 * still reset once, on the tick the file is seen to exist again, whether or
 * not its absence was ever reported.
 */
import { closeSync, existsSync, openSync, readSync, statSync } from "node:fs";

/** What every audit line carries, whichever kind it is. */
type AuditEntryIdentity = {
  seq: number;
  recorded_at: string;
  /** The writer's own session identifier -- a different value from the
   * `session_id` an envelope in the envelope log carries; see this module's
   * doc. */
  session_id: string;
  /** An ACS method, or null when the writer never determined one. Never a
   * host's own event name: this reader knows ACS and nothing else. */
  method: string | null;
  rpc_id: string | number | null;
};

/** A step the writer's negotiated posture answered, because no decision
 * arrived -- §6.4's own case. */
type PostureResolvedAuditEntry = AuditEntryIdentity & {
  posture: "proceed" | "deny";
  posture_source: "negotiated" | "default";
  outcome: "proceeded" | "blocked";
  failure: { kind: string; message: string };
  /** Present only when establishing the session's negotiated configuration
   * failed. Distinct from `failure`, which is the failure of the step the
   * entry is filed against. */
  session_failure?: { kind: string; message: string };
};

/** A step no gate asked about: the writer's own hookmap scoped it out. No
 * posture and no failure, because neither was ever reached -- see the
 * writer's own `UngovernedAuditEntry` for why those are absent rather than
 * defaulted. */
type UngovernedAuditEntry = AuditEntryIdentity & {
  outcome: "ungoverned";
  ungoverned: { tool: string; tools: string[] };
};

/** One line of the audit log, as written by the audit sink on the
 * posture-negotiating side of the wire. A union, because the two kinds of
 * line share nothing but their identity fields; narrow on `outcome`. */
export type AuditEntry = PostureResolvedAuditEntry | UngovernedAuditEntry;

export type TailAuditLogOptions = {
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
   * existed and then gone missing (see the module doc). Defaults to one
   * stderr warning per failed tick. Streaming continues either way. */
  onPollError?: (error: unknown) => void;
};

const NEWLINE = 0x0a;

/**
 * The audit log is a plain file on disk; anything can write a line to it
 * that is valid JSON but not a valid AuditEntry. Checked here, right after
 * `JSON.parse`, using exactly the fields the renderer depends on, so a line
 * of the wrong shape is routed to `onMalformedLine` instead of reaching a
 * consumer that assumes every field is present and correctly typed.
 */
function isAuditEntryShape(value: unknown): value is AuditEntry {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  if (
    !(
      typeof candidate.seq === "number" &&
      typeof candidate.recorded_at === "string" &&
      typeof candidate.session_id === "string" &&
      (typeof candidate.method === "string" || candidate.method === null) &&
      (typeof candidate.rpc_id === "string" || typeof candidate.rpc_id === "number" || candidate.rpc_id === null)
    )
  ) {
    return false;
  }
  // Branched on the discriminant rather than checked as one flat conjunction
  // of optionals: the two kinds of line have disjoint field sets, so a flat
  // check that made every arm-specific field optional would accept a line
  // carrying an `ungoverned` block beside a `posture` -- a shape no writer
  // produces and this renderer has no line for.
  if (candidate.outcome === "ungoverned") {
    return isUngovernedShape(candidate.ungoverned);
  }
  return (
    (candidate.posture === "proceed" || candidate.posture === "deny") &&
    (candidate.posture_source === "negotiated" || candidate.posture_source === "default") &&
    (candidate.outcome === "proceeded" || candidate.outcome === "blocked") &&
    isFailureShape(candidate.failure) &&
    // Optional, so absent is valid -- but a present one is checked as
    // strictly as the required one, because the renderer prints it.
    (candidate.session_failure === undefined || isFailureShape(candidate.session_failure))
  );
}

/** The `tools` list is checked element by element: the renderer joins it, and
 * a line whose list held a number would print `[object Object]`-grade noise
 * in the one log an incident review reads. */
function isUngovernedShape(value: unknown): value is { tool: string; tools: string[] } {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.tool === "string" &&
    Array.isArray(candidate.tools) &&
    candidate.tools.every((tool) => typeof tool === "string")
  );
}

function isFailureShape(value: unknown): value is { kind: string; message: string } {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as Record<string, unknown>).kind === "string" &&
    typeof (value as Record<string, unknown>).message === "string"
  );
}

export function tailAuditLog({
  path,
  fromStart = false,
  pollMs = 120,
  signal,
  onMalformedLine = warnMalformedLine,
  onPollError = warnPollError,
}: TailAuditLogOptions): AsyncGenerator<AuditEntry, void, void> {
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
  // only on the *first* tick of a gap -- see the comment at its use below)
  // and as the reset-once trigger consulted the moment existence returns.
  let missingSinceLastSeen = false;
  // The same report-once discipline for the OTHER way a poll can fail: a
  // read that throws on a log that does exist -- a permission error, or a
  // path that is a directory. The missing-file branch above was given this
  // treatment and this one was not, so the identical noise problem survived
  // through a different branch: one stderr line per poll interval, forever,
  // for a condition a human needs told once. Cleared by the first tick that
  // completes a read, so a fault that comes back is reported again.
  let pollFailing = false;

  // Entries the timer has parsed but nobody has consumed yet, and the
  // wake-up the drain loop below is currently parked on while that queue is
  // empty. The timer and the generator only communicate through these two.
  const ready: AuditEntry[] = [];
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
          // for as long as the gap continues, takes the `missingSinceLastSeen`
          // branch above instead and reports nothing further.
          missingSinceLastSeen = true;
          reportPollError(onPollError, new Error(`audit log not found at ${path}`));
        }
        // A log that has never existed at all is not a gap and is not
        // reported -- see the module doc: this is the healthy "no bypass
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
        // Truncated or rotated underneath us (`: > .acs/audit.jsonl`).
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
              if (!isAuditEntryShape(parsed)) {
                throw new Error("line parsed as JSON but does not match the AuditEntry shape");
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
      // Reported once per transition into failure, not once per tick. A
      // permission error on a file that exists is a standing condition, and
      // repeating it every `pollMs` buries the entries this tool exists to
      // show under a wall of identical lines -- the same noise the
      // missing-file case was fixed for, reached through this branch
      // instead.
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

  async function* drain(): AsyncGenerator<AuditEntry, void, void> {
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
 * here, same as tail-envelope-log.ts's sizeOf -- there is nothing wrong yet
 * to report; the divergence documented above is about a log disappearing
 * *after* this tailer has already been reading it, which poll() alone
 * tracks. */
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
    console.error(`onMalformedLine threw while reporting an unparseable audit-log line (${message})`);
  }
}

/** Same guard as reportMalformedLine, for the poll-error callback. */
function reportPollError(onPollError: (error: unknown) => void, error: unknown): void {
  try {
    onPollError(error);
  } catch (callbackError) {
    const message = callbackError instanceof Error ? callbackError.message : String(callbackError);
    console.error(`onPollError threw while reporting a failed audit-log poll (${message})`);
  }
}

function warnMalformedLine(line: string, error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`skipping unparseable audit-log line (${message}): ${line.slice(0, 120)}`);
}

function warnPollError(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`audit log poll failed, retrying next tick (${message})`);
}
