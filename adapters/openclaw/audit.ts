/**
 * Writes shared and adapter-specific audit entries to one JSONL file.
 * `host-adapter` defines entries shared by all hosts. This adapter adds run
 * admission and approval entries, so it writes the same format with one
 * sequence. Its sink implements `AuditSink` for `applyFailurePosture`.
 */
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import type { AuditEvent, SessionFailureKind, StepFailureKind } from "./host-adapter.ts";

type EntryIdentity = {
  session_id: string;
  method: string | null;
  rpc_id: string | number | null;
  request_id?: string | null;
};

/**
 * Adds entries that `host-adapter` cannot write:
 * - `substituted`: a decision the gate carried out as a block (§6.5);
 * - `approval`: an ASK resolved by a person through OpenClaw;
 * - `blocked`: `posture_source: "host"` when `failurePosture` is `closed`, or
 *   `failure.kind: "decision_invalid"` when a signed decision fails the
 *   response schema. Invalid signed decisions block under either posture (#182).
 */
export type AdapterAuditEvent =
  | AuditEvent
  | (EntryIdentity & { outcome: "substituted"; substituted: { decision: string; reason_code: string } })
  | (EntryIdentity & {
      outcome: "approval";
      approval: { requested_approver: { type: string; id: string }; resolution: string; decision: "allow" | "deny" };
    })
  | (EntryIdentity & {
      outcome: "blocked";
      posture: "proceed" | "deny";
      posture_source: "host" | "negotiated" | "default";
      failure: { kind: StepFailureKind | "decision_invalid"; message: string };
      session_failure?: { kind: SessionFailureKind; message: string };
    });

export type AdapterAuditSink = {
  path: string | null;
  /** Returns `false` on a write failure; the sink then disables itself and reports the error once. */
  write(event: AdapterAuditEvent): boolean;
};

/** Seeds the counter so a restarted process continues the file's sequence. */
function lastSeqIn(path: string): number {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return 0;
  }
  let last = 0;
  for (const line of text.split("\n")) {
    try {
      const { seq } = JSON.parse(line) as { seq?: unknown };
      if (typeof seq === "number" && Number.isFinite(seq) && seq > last) {
        last = seq;
      }
    } catch {
      // Ignore malformed, incomplete, and empty lines.
    }
  }
  return last;
}

/**
 * Shares sequence and failure state by path. OpenClaw can register multiple
 * plugin instances, and every instance may write to the same file.
 */
const files = new Map<string, { seq: number | undefined; disabled: boolean }>();

export function createAdapterAuditSink({
  path,
  now = () => new Date(),
  onError,
}: {
  path: string;
  now?: () => Date;
  onError: (error: unknown) => void;
}): AdapterAuditSink {
  const file = files.get(path) ?? { seq: undefined, disabled: false };
  files.set(path, file);
  return {
    path,
    write(event) {
      if (file.disabled) {
        return false;
      }
      try {
        file.seq ??= lastSeqIn(path);
        mkdirSync(dirname(path), { recursive: true });
        appendFileSync(path, `${JSON.stringify({ seq: file.seq + 1, recorded_at: now().toISOString(), ...event })}\n`);
        file.seq += 1;
        return true;
      } catch (error) {
        file.disabled = true;
        onError(error);
        return false;
      }
    },
  };
}
