/**
 * The host-side audit sink. §6.4 makes one thing a MUST: every step that
 * proceeds without a decision is recorded, so a fail-open bypass is visible
 * rather than silent.
 *
 * That is most of the job, and for a while it was thought to be all of it.
 * It is not: a step can also proceed without a decision because no gate ever
 * asked for one. A hookmap entry that declares a `tools` list skips every
 * tool the list does not name (`governsTool`, govern-step.ts), and a list
 * that stops matching the names a host actually sends skips everything --
 * silently, since a skip builds no envelope, consults no posture and fails
 * at nothing. Recorded here too, as its own outcome, so the log tells an
 * ungoverned session apart from a quiet one.
 *
 * Total by construction, the same contract
 * packages/guardian/src/envelope-log-sink.ts's envelope log sink keeps. This
 * sink runs on the decision path, in a hook process whose stdout is a
 * policy decision. It must never throw, never change a decision, and never
 * delay one beyond the append it is asked for -- so the first failure
 * disables it, reports once, and every later write is a no-op.
 *
 * It does, however, SAY whether the append happened: `write` returns a
 * boolean. Totality and the sink's own silence about its failures are
 * different properties: the sink must never throw, but a `proceed` with no
 * audit entry is a silent bypass, and §6.4 makes the entry a MUST for a step
 * that proceeds without a decision -- an unauditable bypass is not a bypass
 * the spec permits. So the sink still never throws, and
 * `applyFailurePosture` decides what an unrecorded proceed means. This sink
 * does not decide it, and does not change a decision to express it.
 *
 * Structurally the same as packages/guardian/src/envelope-log-sink.ts, and
 * deliberately not shared with it: that one is the Guardian's, recording the
 * wire; this one is the host's, recording what became of a step the wire
 * never answered for -- whether because a posture answered instead, or
 * because no gate asked. They record different things at different sides of
 * the wire, and this package stays free of the Guardian's imports.
 */
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import type { SessionFailureKind, StepFailureKind } from "./failure-kinds.ts";

/** What every audit entry carries, whichever kind it is: which step, in
 * which session, and how it pairs with the envelope log. */
type AuditEntryIdentity = {
  /**
   * 1-based and per *session*: continued from the entries already in the log
   * when this sink first writes to it, not counted from zero per instance.
   * The shipped host runs each hook in a fresh subprocess with a fresh sink,
   * so a per-instance counter made every entry in a session `seq: 1` --
   * ordering nothing, unable to exhibit the gap the rest of this sentence
   * tells a reader to look for, and rendering as three identical `#1`
   * headers that read as one entry repeated. Gaps mean lost writes.
   */
  seq: number;
  recorded_at: string;
  session_id: string;
  /**
   * The ACS method this step would have been asked under, or `null` when
   * none was ever determined. It is never a host's own hook or event name:
   * this field is read by consumers that know ACS and nothing else (the
   * Inspector renders it verbatim), and a host name arriving here would make
   * an ACS-only reader print one.
   *
   * Populated on an `ungoverned` entry from the hookmap entry's own
   * `acs_method` rather than from an envelope, because a skipped step builds
   * no envelope and the field is still determined: it is the method the gate
   * maps to, which is what tells a reviewer WHICH gate declined.
   */
  method: string | null;
  rpc_id: string | number | null;
};

/**
 * A step that got no decision and was resolved by the negotiated posture --
 * §6.4's own case, and every entry this log held before `ungoverned` existed.
 */
type PostureResolvedAuditEntry = AuditEntryIdentity & {
  /**
   * What became of the step. `proceeded` is the fail-open bypass §6.4 requires
   * be recorded.
   *
   * A THIRD vocabulary beside the wire posture (`proceed|deny`) and the ACS
   * decision (`allow|deny`), justified only because the Inspector's badge
   * genuinely needs a third stem. Two things it buys, both visible on one
   * rendered line of `bun run inspector`:
   *
   *   - `renderAuditEntry` prints the outcome and `posture=` side by side.
   *     Mirroring the posture would print one word twice and lose which of the
   *     two a reader is looking at: what this deployment declared, against what
   *     became of this step.
   *   - Mirroring the ACS decision would badge the line `ALLOW`/`DENY`, which
   *     is the envelope stream's vocabulary for a step whose decision genuinely
   *     arrived. Every line in THIS arm is a step where none did, and that
   *     difference is the entire thing §6.4 requires be visible.
   *
   * Past tense for the same reason: this field reports, it does not declare.
   *
   * Derived from the posture in exactly one place (failure-posture.ts's
   * RESOLUTION_BY_POSTURE), so the two can never disagree about a step --
   * with one exception, which is the one combination worth knowing how to
   * read here. A step the Guardian REFUSED (`failure.kind: "refused"`) is
   * `blocked` whatever the posture said, because the posture answers a
   * decision that did not arrive and a refusal is one that was withheld. So
   * `posture: "proceed"` beside `outcome: "blocked"` is a refusal, always:
   * the only other route from a `proceed` posture to a blocked step is the
   * unauditable-proceed downgrade, and that one denies precisely because the
   * write failed, so it leaves no entry to read.
   */
  outcome: "proceeded" | "blocked";
  /** The posture in force -- negotiated, or the ACS default when nothing was. */
  posture: "proceed" | "deny";
  /** Whether `posture` was negotiated at handshake or is the ACS default
   * because no handshake ever completed. The `reasoning` string a human
   * reads in a transcript is ephemeral; this field carries the same
   * distinction into the durable record, because "the guardian was down
   * for this whole session" and "this deployment chose to fail open" are
   * different incidents and the audit log is where that has to survive. */
  posture_source: "negotiated" | "default";
  /**
   * What went wrong with THIS step, classified.
   *
   * `kind` carries the taxonomy rather than a bare `string`.
   * `applyFailurePosture` goes to some trouble to tell a delivery failure
   * from a refusal and from a host-side fault -- `DeliveryFailureKind` was
   * deliberately narrowed for it, `RefusalFailureKind` exists because a
   * Guardian that answered "no" is not a Guardian that failed to answer, and
   * `HostFailureKind` exists so a host misconfiguration is not filed as an
   * unknown delivery failure -- and this is the only boundary that outlives
   * the process, so a widening here is where all of that would have been
   * lost. It is also the only place an incident review ever reads: a value
   * this union does not contain is a value nothing downstream was written to
   * interpret, and `string` invited exactly that.
   *
   * `message` is where the Guardian's own JSON-RPC error code survives, for a
   * refusal as for any other error it answered with -- which of the refusals
   * this was is a fact an incident reviewer needs, and this field is the one
   * that already carries it into the record and onto the Inspector's line.
   */
  failure: { kind: StepFailureKind; message: string };
  /**
   * Present only when establishing this session's negotiated config failed
   * -- a handshake that never completed, or a ServerHello that could not be
   * stored. Separate from `failure`, which is always the failure of the step
   * this entry is filed against: the two are different requests that fail
   * for unrelated reasons, and merging them would misattribute one to the
   * other. Recorded because a session whose config cannot be *persisted*
   * re-handshakes on every hook and silently never applies the posture the
   * deployment declared -- which is how a deployment that asked to fail
   * closed ends up failing open, and `posture_source: "default"` alone says
   * that happened without saying why.
   */
  session_failure?: { kind: SessionFailureKind; message: string };
};

/**
 * A step no gate ever asked about: the hook fired, the gate's own `tools`
 * list did not name this tool, and the step ran with no envelope built, no
 * Guardian contacted and no decision sought.
 *
 * A SEPARATE ARM rather than three more optional fields on the one above,
 * because the two kinds of entry share nothing but their identity. Every
 * field of the posture arm would be a lie here, not merely absent:
 *
 *   - `failure` -- nothing failed. A skip is what the deployment's own
 *     hookmap asked for. Filing it under a failure kind would put a fault in
 *     the one log an incident review reads, for a step that had none, and
 *     inventing a kind for it would be a vocabulary entry describing an
 *     outcome that did not happen -- the defect govern-step.ts's own
 *     unmapped-hook guard exists to prevent.
 *   - `posture`/`posture_source` -- no posture was consulted, and at the one
 *     call site that skips earliest (a long-lived plugin shim's own
 *     `governsTool` check) no handshake has run, so there is no negotiated
 *     posture to report even dishonestly. Printing `posture=proceed` beside
 *     `UNGOVERNED` would read as "this deployment chose to proceed", which
 *     is not what happened: it chose not to ask.
 *
 * So `AuditEntry` is a union, and a reader narrows on `outcome`. The cost is
 * that every consumer of `failure` or `posture` now says which arm it means;
 * the alternative was five optional fields and a co-occurrence rule that only
 * a comment enforced.
 *
 * VOLUME IS THE KNOWN COST, stated rather than discovered later. On a host
 * whose gates fire for every tool and scope with `tools` (host #2, whose
 * result gate lists `bash` alone), every call to every other tool writes one
 * of these at each gate -- so an ordinary session's log is mostly this arm.
 * That is the honest consequence of §6.4's own charter, which is about steps
 * that proceeded without a decision and does not distinguish why. Not
 * de-duplicated per session: the one host where a long-lived plugin could
 * hold that state is not the one whose hooks are fresh subprocesses, so
 * de-duplicating would make the two hosts record different things, which is
 * the divergence this package exists to prevent.
 */
type UngovernedAuditEntry = AuditEntryIdentity & {
  outcome: "ungoverned";
  /**
   * Which tool went ungoverned, and the list that declined it -- both,
   * because either alone is unreadable. The tool name alone cannot be told
   * from a legitimate out-of-scope call; the list alone does not say what
   * missed it. Together they are the drift signal: a reviewer reading
   * `bash_tool` against `["bash"]` sees a hookmap whose vocabulary stopped
   * matching the host's, which is the fault that otherwise presents as a
   * quiet session.
   */
  ungoverned: { tool: string; tools: string[] };
};

export type AuditEntry = PostureResolvedAuditEntry | UngovernedAuditEntry;

/** `Omit` over a union collapses it to the keys its arms share, which would
 * silently erase both arms' own fields. Distributed, so each arm keeps them. */
type OmitPerArm<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

export type AuditEvent = OmitPerArm<AuditEntry, "seq" | "recorded_at">;

export type AuditSink = {
  /** Where entries land, or null for the null sink. */
  path: string | null;
  /**
   * Appends one entry. Never throws. Returns true when the entry was
   * actually recorded and false otherwise, so a caller that must not
   * proceed unrecorded (§6.4) can tell the difference.
   * A false return has already been reported through `onError`; the caller
   * does not need to report it again.
   */
  write(event: AuditEvent): boolean;
};

/**
 * Used where no audit path is configured. Accepts writes, records nothing --
 * and says so, by returning false: "nothing was recorded" is exactly what a
 * caller deciding whether a proceed can stand needs to hear, and claiming
 * otherwise would make this the one sink that can hide a bypass.
 */
export const NULL_AUDIT_SINK: AuditSink = {
  path: null,
  write(): boolean {
    return false;
  },
};

export type CreateAuditSinkOptions = {
  path: string;
  now?: () => Date;
  onError?: (error: unknown) => void;
};

/**
 * The highest sequence number already in the log, so a fresh sink continues
 * the session rather than restarting it (see AuditEntry.seq). Falls back to
 * the line count when a line carries no usable `seq`, so an unparseable
 * entry still consumes its number instead of being overwritten in spirit by
 * the next one.
 *
 * TOTAL, like everything else here: a missing or unreadable log means "start
 * from 1", never a throw. Losing the ability to continue the numbering must
 * not cost the entry itself, which is the thing §6.4 actually requires.
 */
function highestSeqIn(path: string): number {
  try {
    const lines = readFileSync(path, "utf8")
      .split("\n")
      .filter((line) => line.trim() !== "");
    let highest = 0;
    for (const line of lines) {
      try {
        const { seq } = JSON.parse(line) as { seq?: unknown };
        if (typeof seq === "number" && Number.isFinite(seq) && seq > highest) {
          highest = seq;
        }
      } catch {
        // Counted by `lines.length` below; nothing else to do with it.
      }
    }
    return Math.max(highest, lines.length);
  } catch {
    return 0;
  }
}

export function createAuditSink({ path, now = () => new Date(), onError }: CreateAuditSinkOptions): AuditSink {
  // Undefined until the first write reads the log. Deferred deliberately:
  // most hook invocations never write an audit entry at all (nothing failed
  // to be delivered), and reading the log at construction would put an fs
  // read on the decision path of every one of them.
  let seq: number | undefined;
  let disabled = false;

  function fail(error: unknown): void {
    // Set FIRST: if onError throws, this sink must already be disabled, or a
    // second write would call the throwing reporter again.
    disabled = true;
    if (onError) {
      try {
        onError(error);
      } catch {
        // A broken reporter cannot be reported. Nothing further to do.
      }
      return;
    }
    try {
      console.error(`audit sink disabled: ${error instanceof Error ? error.message : String(error)}`);
    } catch {
      // stderr is unavailable; there is nowhere left to say so.
    }
  }

  return {
    path,
    write(event: AuditEvent): boolean {
      if (disabled) {
        return false;
      }
      try {
        if (seq === undefined) {
          seq = highestSeqIn(path);
        }
        const entry: AuditEntry = { seq: seq + 1, recorded_at: now().toISOString(), ...event };
        mkdirSync(dirname(path), { recursive: true });
        appendFileSync(path, `${JSON.stringify(entry)}\n`);
        // Only after a successful append, so a failed write does not consume
        // a sequence number and invent a gap that never happened.
        seq += 1;
        return true;
      } catch (error) {
        fail(error);
        return false;
      }
    },
  };
}
