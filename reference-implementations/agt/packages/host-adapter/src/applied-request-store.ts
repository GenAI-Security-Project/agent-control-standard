/**
 * The applied request store: which `toolCallRequest` a later `toolCallResult`
 * has to name, for the one case where that is not the request the host can
 * derive on its own.
 *
 * `buildEnvelope` derives a request's `request_id` from the host's call id
 * and derives the result's `request_id_ref` the same way, so a host that
 * asks once about a call pairs the two with no state at all. A host that
 * asks twice about one call sends the derived id twice, a Guardian enforcing
 * Specification §10.3 answers the repeat with REPLAY_DETECTED, and
 * `governStep` retries once with a random id (§17.1). The answer the host
 * acts on is then the retry's. A result that still named the derived id
 * would resolve against the first ask: a denied first ask and an allowed
 * retry would read as a host that ignored a DENY, and the reverse would hide
 * a denial (issue #351). `hooks.md` says `request_id_ref` names the request
 * whose decision the host applied, so the retry's id has to reach the result
 * gate, which on one host runs in a process that never saw the retry.
 *
 * Keyed by the derived id, holding the one the host acted on. Only a retried
 * call is recorded: for every other call the applied request IS the derived
 * one, so an absent record means "the derived id is right" and the result
 * gate falls back to it. That keeps the common path free of writes and
 * leaves nothing behind for a call that was asked about once.
 *
 * Two implementations behind one interface, for the reason the session
 * config store has two: the OpenCode plugin is one object for the whole
 * session and keeps the record in memory, while the Claude Code shim runs
 * each hook as a fresh subprocess, so the request gate's process has to
 * leave the record where the result gate's process can find it.
 */

import { mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export type AppliedRequestStore = {
  /**
   * The `request_id` the host acted on for the call `derivedRequestId`
   * names, or undefined when that is the derived id itself. Total: a
   * missing or unreadable record is undefined, never a throw, because the
   * result gate reads this on its way to building an envelope and a throw
   * there would turn bookkeeping into a decision failure.
   */
  get(derivedRequestId: string): string | undefined;
  /**
   * Records that the host acted on `appliedRequestId` for that call.
   * Total for the same reason: the step that retried has a decision in
   * hand, and no write about how its result will be paired may drop it.
   * A file store that cannot write reports it instead.
   */
  set(derivedRequestId: string, appliedRequestId: string): void;
};

/** Creates a fresh, empty store. */
export function createMemoryAppliedRequestStore(): AppliedRequestStore {
  const applied = new Map<string, string>();
  return {
    get(derivedRequestId: string): string | undefined {
      return applied.get(derivedRequestId);
    },
    set(derivedRequestId: string, appliedRequestId: string): void {
      applied.set(derivedRequestId, appliedRequestId);
    },
  };
}

/**
 * Both ids are UUIDs by construction (`toInvocationRequestId` and
 * `randomUUID`), and the derived one becomes a filename, so anything else
 * is a caller defect and is refused before the filesystem is touched.
 * Checked on the value too, so a record never holds a string the result
 * gate would put on the wire as a `request_id_ref` that no schema accepts.
 */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class InvalidRequestIdError extends Error {
  constructor(requestId: unknown) {
    super(`request id ${JSON.stringify(requestId)} is not a uuid, so it cannot name a record`);
    this.name = "InvalidRequestIdError";
  }
}

function assertUuid(requestId: string): void {
  if (!UUID_RE.test(requestId)) {
    throw new InvalidRequestIdError(requestId);
  }
}

/** Where one retried call's record lives. Exported so tests and the runbook
 * name the same path this module writes. */
export function appliedRequestPath(dir: string, derivedRequestId: string): string {
  assertUuid(derivedRequestId);
  return join(dir, `${derivedRequestId}.json`);
}

export type CreateFileAppliedRequestStoreOptions = {
  /** Directory holding one file per retried call. Created on first write. */
  dir: string;
  /**
   * Where a failed write is reported. Defaults to one line on stderr, the
   * audit sink's own fallback. The report is the only trace that the next
   * result for this call may name the request the host did not act on.
   */
  onError?: (error: unknown) => void;
};

/**
 * The record with a home that outlives the process.
 *
 * `set` writes to a temp file and renames, so a result gate's process that
 * reads while the request gate's process is still writing (Claude Code may
 * run hooks in parallel) sees either no record or a complete one, never a
 * half-written file.
 */
export function createFileAppliedRequestStore({ dir, onError }: CreateFileAppliedRequestStoreOptions): AppliedRequestStore {
  function report(error: unknown): void {
    if (onError) {
      try {
        onError(error);
      } catch {
        // A broken reporter cannot be reported. Nothing further to do.
      }
      return;
    }
    try {
      console.error(`applied request store: ${error instanceof Error ? error.message : String(error)}`);
    } catch {
      // stderr is unavailable; there is nowhere left to say so.
    }
  }

  return {
    get(derivedRequestId: string): string | undefined {
      const path = appliedRequestPath(dir, derivedRequestId);
      let parsed: unknown;
      try {
        parsed = JSON.parse(readFileSync(path, "utf8"));
      } catch {
        return undefined;
      }
      const applied = (parsed as { applied_request_id?: unknown } | null)?.applied_request_id;
      return typeof applied === "string" && UUID_RE.test(applied) ? applied : undefined;
    },

    set(derivedRequestId: string, appliedRequestId: string): void {
      const path = appliedRequestPath(dir, derivedRequestId);
      assertUuid(appliedRequestId);
      const temp = `${path}.tmp-${process.pid}`;
      try {
        mkdirSync(dir, { recursive: true });
        writeFileSync(temp, `${JSON.stringify({ applied_request_id: appliedRequestId })}\n`);
        renameSync(temp, path);
      } catch (error) {
        try {
          unlinkSync(temp);
        } catch {
          // The temp file may not exist; nothing to clean up.
        }
        report(error);
      }
    },
  };
}
