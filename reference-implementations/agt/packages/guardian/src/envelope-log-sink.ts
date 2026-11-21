/**
 * createEnvelopeLogSink writes a JSONL record of every ACS envelope that
 * crosses this Guardian's wire, in both directions. The Envelope Inspector
 * reads this file and nothing else -- see packages/inspector, which
 * deliberately imports nothing from here.
 *
 * Named for the artifact it produces and the role it plays, not for the
 * mechanism: it writes a log, it does not "tap a wire".
 *
 * What "records the envelope" means here, precisely: the sink is handed the
 * JSON *value* the Guardian parsed, and writes it unmodified -- no field
 * stripping, no redaction, no reordering of anything we control. It is not a
 * byte-for-byte copy of the request body. The parse happens upstream in
 * server.ts (`await req.json()`) and has already collapsed duplicate keys,
 * canonicalised number literals, and hoisted integer-like object keys -- and
 * `arguments` keys are host-controlled, so `{"0": ...}` is a real shape, not
 * a hypothetical. Recording raw bytes instead would make `envelope` a string
 * rather than a JSON value, costing the Inspector its pretty-printing and
 * the round-trip contract test; the accurate sentence is the better trade.
 *
 * Total by construction. Every write is wrapped: a failure disables the sink
 * for the process lifetime, reports once, and is never propagated to the
 * caller. The sink sits on the decision path: an observability feature that
 * can turn a governed tool call into an ungoverned one is the one failure
 * mode this module must never have. Observability degrades; governance does
 * not.
 */
import { appendFileSync, closeSync, fchmodSync, fstatSync, mkdirSync, openSync } from "node:fs";
import { dirname } from "node:path";

/**
 * Which side of the exchange one envelope-log line recorded, or "finding" for
 * a fact the Guardian established about a request that the spec requires it
 * to record. A finding's `envelope` is the Guardian's own record, not a
 * JSON-RPC object, and its `rpc_id` names the request it concerns.
 */
export type EnvelopeLogDirection = "request" | "response" | "finding";

/**
 * One line of the envelope log, named for what was recorded rather than for
 * what recorded it. `envelope` is the JSON-RPC object as parsed, unmodified
 * -- request or response -- and every other field is Guardian-side context
 * the wire does not carry: a sequence number so a reader can detect gaps, a
 * timestamp, the direction, the ACS method (JSON-RPC responses carry none,
 * so the Guardian supplies the one it dispatched), and the JSON-RPC id that
 * pairs the two directions.
 */
export type EnvelopeLogEntry = {
  seq: number;
  recorded_at: string;
  direction: EnvelopeLogDirection;
  method: string | null;
  rpc_id: string | number | null;
  envelope: unknown;
};

/**
 * Where envelope-log lines go: the Guardian-side writer role. `write` says
 * whether the line landed. Most callers ignore that, because the log is
 * observability. A caller recording a fact the spec requires it to keep
 * reads it and puts the fact somewhere else when the log did not take it.
 */
export type EnvelopeLogSink = {
  write(direction: EnvelopeLogDirection, envelope: unknown, method: string | null, rpcId?: string | number | null): boolean;
  readonly path: string | null;
};

export type CreateEnvelopeLogSinkOptions = {
  path: string;
  /** Injectable clock, so tests can assert recorded_at exactly. */
  now?: () => Date;
  /** Called at most once, on the first failure. Defaults to one stderr line. */
  onError?: (error: unknown) => void;
};

/** The sink a Guardian gets when no envelope log path was configured: a
 * composition root disabling observability gets a value of the same
 * `EnvelopeLogSink` type, not a special case. */
export const NULL_ENVELOPE_LOG_SINK: EnvelopeLogSink = {
  path: null,
  write(): boolean {
    return false;
  },
};

/** The JSON-RPC id, when it is a scalar. Both request and response envelopes
 * carry `id` at the top level, so one extractor serves both directions. */
export function extractRpcId(envelope: unknown): string | number | null {
  if (typeof envelope === "object" && envelope !== null && "id" in envelope) {
    const id = envelope.id;
    if (typeof id === "string" || typeof id === "number") {
      return id;
    }
  }
  return null;
}

/**
 * Appends to a file only its owner can read. The mode on `openSync` applies
 * only when this call creates the file, so a log left by an older version
 * keeps its 0644. `fchmodSync` tightens that log too. Windows has no such
 * bits, and a device such as /dev/null is not ours to change.
 */
export function appendPrivate(path: string, text: string): void {
  const fd = openSync(path, "a", 0o600);
  try {
    if (process.platform !== "win32" && fstatSync(fd).isFile()) {
      fchmodSync(fd, 0o600);
    }
    appendFileSync(fd, text);
  } finally {
    closeSync(fd);
  }
}

export function createEnvelopeLogSink({
  path,
  now = () => new Date(),
  onError,
}: CreateEnvelopeLogSinkOptions): EnvelopeLogSink {
  let seq = 0;
  let disabled = false;

  const fail = (error: unknown): void => {
    disabled = true;
    try {
      if (onError) {
        onError(error);
        return;
      }
      const message = error instanceof Error ? error.message : String(error);
      console.error(`envelope log sink disabled after failure (${path}): ${message}`);
    } catch {
      // Silently swallow any error from the callback or console.error
      // to maintain the total-by-construction guarantee
    }
  };

  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  } catch (error) {
    fail(error);
  }

  return {
    path,
    write(direction, envelope, method, rpcId): boolean {
      if (disabled) {
        return false;
      }
      try {
        const entry: EnvelopeLogEntry = {
          seq: seq + 1,
          recorded_at: now().toISOString(),
          direction,
          method,
          // A finding carries no JSON-RPC id of its own, so the caller names
          // the request it concerns.
          rpc_id: rpcId === undefined ? extractRpcId(envelope) : rpcId,
          envelope,
        };
        const line = `${JSON.stringify(entry)}\n`;
        appendPrivate(path, line);
        seq += 1;
        return true;
      } catch (error) {
        fail(error);
        return false;
      }
    },
  };
}
