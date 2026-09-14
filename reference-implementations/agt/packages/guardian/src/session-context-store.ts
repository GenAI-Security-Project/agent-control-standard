/**
 * The store a session's chain, intent, and provenance record live in, and
 * the verbs that read and write it.
 *
 * `loadSessionContext` and `appendContextEntry` are a matched pair: the
 * reader and the writer of one chain.
 *
 * Three roles, split on one axis: does the Guardian's request path send this
 * message? `SessionContextStore` is what `evaluateStep` uses and therefore
 * what a stand-in for it has to answer -- every member of it is sent on a
 * real step. The other two carry what nothing on that path sends yet.
 * `SessionIntentStore` carries the session's intent, whose ACS wire `intent`
 * object is unread, so its only senders are tests.
 * `SessionProvenanceReader` carries the whole provenance record, of which
 * the request path reads the labels and nothing else. Leaving those
 * on the live role would make every stand-in answer questions production
 * never asks, which is a documented affordance dressed up as a collaborator.
 * The memory store implements all three, so nothing here is deleted or
 * hidden; it is only off the interface the Guardian depends on until a
 * request-path caller for it exists.
 *
 * Every read is one record wide. There is deliberately no reader returning a
 * whole `SessionState`: handing over the aggregate is as wide a surface on
 * the way out as handing over a whole record to edit and write back would be
 * on the way in, and the aggregate is the memory store's own business rather
 * than a message anyone is sent. On the write side the same rule holds and
 * is stronger --
 * `replaceIfcLabels` is told an array, so it changes labels and cannot
 * express changing `origin` or `source_id`, and `ifc-labels.ts` cannot reach
 * fields it has no business touching.
 *
 * `appendLine` is how the Inspector's session-context view sees the chain
 * without importing this package: the Guardian hands the store a line
 * appender, and the Inspector tails the file it writes and re-declares the
 * entry type itself, so nothing about that view depends on the Guardian's
 * internals.
 *
 * The store is bounded, and the bound is on sessions rather than on entries.
 * `maxSessions` caps how many sessions are retained; a new session that puts
 * the map over the cap evicts the least recently written one whole. It began
 * with no cap at all, and that is a live hazard rather than an untidiness: a
 * Guardian that never forgets a session grows for the life of the process, a
 * larger Guardian answers slower, and a Guardian slower than the host's
 * negotiated `timeout_config.default_ms` produces no decision at all --
 * which the default `proceed` posture resolves by running the tool
 * ungoverned. Degradation turning itself into bypass is the whole reason
 * there is a cap.
 *
 * Truncating entries within a session was the other candidate, and it is
 * rejected because it breaks what the chain means. Dropping a session's
 * oldest entries leaves a chain whose first surviving entry names a
 * `prev_hash` there is nothing to compare against, and the Inspector's chain
 * check (`checkSessionChainLink`, packages/inspector/src/render.ts)
 * documents that it never marks a first entry -- so a front-truncated chain
 * reads exactly like a complete one. That is evidence that looks like
 * evidence, which is the one thing this chain exists not to be. Evicting a
 * whole session cannot produce it: a retained session's chain is entire, and
 * an evicted session's chain is absent.
 *
 * Eviction is therefore reported rather than silent, twice over. `onEvict`
 * is called with the id of every evicted session and defaults to a stderr
 * warning, so a deployment whose cap is too small says so instead of
 * quietly forgetting. And an evicted session that takes another step starts
 * again at `GENESIS_HASH` and `seq` 1, which the Inspector renders as a
 * CHAIN BREAK rather than as a fresh session: it has already recorded a
 * `hash` for that `session_id`, and a `prev_hash` of genesis does not match
 * it.
 *
 * What the cap does not bound is one session's own chain, which still grows
 * linearly in the steps that session takes -- that is the chain being an
 * append-only chain, and the file the Inspector tails grows the same way.
 * What is gone is the quadratic: `append` pushes onto the array it already
 * keeps instead of rebuilding the history around each new entry, so a
 * session's hundredth step costs what its first one did.
 */
import {
  GENESIS_HASH,
  emptySessionState,
  hashEntry,
  type IfcLabels,
  type Intent,
  type SessionContext,
  type SessionContextEntry,
  type SessionProvenance,
  type SessionState,
  type SessionStep,
} from "./session-context.ts";

export {
  GENESIS_HASH,
  type IfcLabels,
  type Intent,
  type SessionContext,
  type SessionContextEntry,
  type SessionProvenance,
  type SessionStep,
} from "./session-context.ts";

/** What the Guardian's request path is told and asks on every step. */
export interface SessionContextStore {
  context(sessionId: string): SessionContext;
  append(sessionId: string, step: SessionStep): SessionContextEntry;
  replaceIfcLabels(sessionId: string, labels: IfcLabels): void;
  sourceLabels(sessionId: string): IfcLabels;
}

/**
 * The intent pair, kept off `SessionContextStore` until something on the
 * request path writes an intent. `createMemorySessionContextStore`
 * implements it.
 */
export interface SessionIntentStore {
  setIntent(sessionId: string, text: string): void;
  intent(sessionId: string): Intent | undefined;
}

/**
 * The whole provenance record. The request path asks only for the labels,
 * through
 * `SessionContextStore.sourceLabels`, so this reader is what keeps the rest
 * of the record observable -- specifically that `replaceIfcLabels` leaves
 * `provenance_id`, `origin` and `source_id` as session birth wrote them.
 * Without it that invariant would hold only by inspection.
 */
export interface SessionProvenanceReader {
  provenance(sessionId: string): SessionProvenance;
}

/**
 * How many sessions the memory store retains before it starts evicting. A
 * ceiling, not a tuning knob: evicting a session that is still taking steps
 * is the harmful direction, so this sits far above the number of sessions a
 * laptop-scale deployment could plausibly have open at once. Its job is to
 * make growth stop, not to keep the map small.
 */
const DEFAULT_MAX_SESSIONS = 1024;

export type CreateMemorySessionContextStoreOptions = {
  now?: () => Date;
  /** Called once per appended entry with its JSON line, no trailing newline. */
  appendLine?: (line: string) => void;
  /**
   * How many sessions to retain before the least recently written one is
   * evicted whole. Defaults to `DEFAULT_MAX_SESSIONS`.
   */
  maxSessions?: number;
  /**
   * Called with the id of each evicted session. Defaults to a stderr
   * warning; what matters is that no default makes eviction silent.
   */
  onEvict?: (sessionId: string) => void;
};

/**
 * The in-memory store. Named for what it is rather than as the default one --
 * a bare `createSessionContextStore` would read as the general factory and
 * is not.
 */
export function createMemorySessionContextStore(
  options: CreateMemorySessionContextStoreOptions = {},
): SessionContextStore & SessionIntentStore & SessionProvenanceReader {
  const now = options.now ?? (() => new Date());
  const appendLine = options.appendLine;
  const maxSessions = options.maxSessions ?? DEFAULT_MAX_SESSIONS;
  const onEvict = options.onEvict ?? warnEvictedSession;
  if (!Number.isInteger(maxSessions) || maxSessions < 1) {
    // Thrown rather than clamped, for the reason `ACS_ON_DECISION_FAILURE`
    // throws on a posture it does not recognise: a cap of 0 evicts every
    // session the instant it is written, so guessing what the caller meant
    // would turn a typo into a Guardian that remembers nothing and says so
    // once per step.
    throw new Error(`maxSessions must be a positive integer, got ${String(maxSessions)}`);
  }
  /**
   * Insertion-ordered, and that order IS the eviction order: `ensure`
   * re-inserts the session it finds, so the map's oldest key is the least
   * recently written session. There is no second structure that could fall
   * out of step with this one.
   */
  const sessions = new Map<string, SessionState>();

  /**
   * A read: never creates a session, and never re-orders one either, so
   * asking about a session neither writes it nor keeps it from being
   * evicted. Reads are what the request path does to a session it is about
   * to write anyway -- `sourceLabels` then `append` -- so write recency is
   * the whole of what "idle" means here.
   */
  const read = (sessionId: string): SessionState => sessions.get(sessionId) ?? emptySessionState(sessionId);

  /**
   * Only an insert can put the map over the cap, and only ever by one -- the
   * loop is here so that stays true by construction rather than by a reader
   * taking this comment's word for it.
   */
  const evictToCap = (): void => {
    while (sessions.size > maxSessions) {
      const oldest = sessions.keys().next();
      if (oldest.done === true) return;
      sessions.delete(oldest.value);
      reportEviction(onEvict, oldest.value);
    }
  };

  const ensure = (sessionId: string): SessionState => {
    const existing = sessions.get(sessionId);
    if (existing !== undefined) {
      // Deleted and re-set rather than merely returned: on a `Map` that is
      // what moves a key to the young end of the insertion order, and the
      // insertion order is what `evictToCap` reads.
      sessions.delete(sessionId);
      sessions.set(sessionId, existing);
      return existing;
    }
    const fresh = emptySessionState(sessionId);
    sessions.set(sessionId, fresh);
    evictToCap();
    return fresh;
  };

  return {
    context(sessionId) {
      // Copied on the way out, like the labels below, and for one reason
      // more: `append` pushes onto the stored array, so an uncopied
      // `entries` would be a chain that grew while its reader held it.
      return { session_id: sessionId, entries: [...read(sessionId).entries] };
    },

    append(sessionId, step) {
      const state = ensure(sessionId);
      const previous = state.entries.at(-1);
      const withoutHash: Omit<SessionContextEntry, "hash"> = {
        session_id: sessionId,
        seq: (previous?.seq ?? 0) + 1,
        prev_hash: previous?.hash ?? GENESIS_HASH,
        recorded_at: now().toISOString(),
        method: step.method,
        request_id: step.request_id,
        tool_name: step.tool_name,
      };
      const entry: SessionContextEntry = { ...withoutHash, hash: hashEntry(withoutHash) };
      // Pushed onto the array this session already owns, rather than rebuilt
      // around it. The rebuild cost one copy of the whole history per step --
      // N per step, N^2 per session -- and the module doc above says what a
      // Guardian that slow does to the decision that never arrives.
      state.entries.push(entry);
      appendLine?.(JSON.stringify(entry));
      return entry;
    },

    setIntent(sessionId, text) {
      const state = ensure(sessionId);
      // Intent is an immutable baseline: the first one a session declares is
      // the one it is held to. Later ones are dropped rather than refused,
      // because a step arriving with a different intent is a fact about the
      // step, not a reason to stop governing it.
      if (state.intent !== undefined) return;
      sessions.set(sessionId, { ...state, intent: { text, recorded_at: now().toISOString() } });
    },

    intent(sessionId) {
      return read(sessionId).intent;
    },

    replaceIfcLabels(sessionId, labels) {
      const state = ensure(sessionId);
      // Copied on the way in: the caller's array is the caller's, and a
      // caller that keeps editing it after this call must not be editing the
      // stored provenance record. Every other member of that record is left
      // exactly as it was -- this verb changes labels and cannot change
      // `origin`.
      sessions.set(sessionId, {
        ...state,
        provenance: { ...state.provenance, ifc_labels: [...labels] },
      });
    },

    sourceLabels(sessionId) {
      // Copied on the way out for the mirror-image reason: the value goes
      // into a snapshot that crosses the bridge into the policy runtime, and
      // a caller holding this array could edit the stored record by editing
      // a snapshot. The return type forbids that; the copy survives a caller
      // who casts.
      return [...read(sessionId).provenance.ifc_labels];
    },

    provenance(sessionId) {
      // Copied like the labels are, and for the same reason: the array inside
      // this record is the stored one, and handing it out uncopied would let
      // a reader edit the stored record by editing what it was shown.
      const stored = read(sessionId).provenance;
      return { ...stored, ifc_labels: [...stored.ifc_labels] };
    },
  };
}

/**
 * Calls the caller's eviction reporter without letting it break the append
 * that triggered it. An `onEvict` that throws would surface as a Guardian
 * failure on whichever unrelated step happened to be the one that overflowed
 * the cap -- and a Guardian-side failure under the default posture is a tool
 * call that runs ungoverned, so a broken reporter must not be able to cause
 * the very thing the cap exists to prevent. Same guard, and the same reason,
 * as `reportMalformedLine` in packages/inspector/src/tail-session-context.ts.
 */
function reportEviction(onEvict: (sessionId: string) => void, sessionId: string): void {
  try {
    onEvict(sessionId);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`onEvict threw while reporting an evicted session (${message}): ${sessionId}`);
  }
}

/**
 * The default report. Names what a reader of the session-context log will
 * see next if this session comes back, because the eviction and the chain
 * break it causes are otherwise two unexplained facts in two different
 * places.
 */
function warnEvictedSession(sessionId: string): void {
  console.error(
    `evicted session ${sessionId} from the session-context store: the retained-session cap was reached. ` +
      `A further step on this session starts a new chain at seq 1, which the Inspector renders as a chain break.`,
  );
}

/** The chain's reader, paired with `appendContextEntry`. */
export function loadSessionContext(store: SessionContextStore, sessionId: string): SessionContext {
  return store.context(sessionId);
}

/** Appends one step to this session's hash chain. */
export function appendContextEntry(
  store: SessionContextStore,
  sessionId: string,
  step: SessionStep,
): SessionContextEntry {
  return store.append(sessionId, step);
}
