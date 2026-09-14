/**
 * This module renders four things: the envelope stream, the decision badge,
 * the posture badge, and the audit-entry line.
 *
 * Every renderer here is pure, and one function is not. No clock, no env, no
 * process anywhere in this file; the CLI decides whether the terminal wants
 * ANSI and passes `color`; tests assert exact plain strings. The exception is
 * named rather than absorbed: `checkSessionChainLink` records each entry's
 * `hash` into the `SessionChainState` its caller owns, because a chain check
 * is a fold over a stream and has to remember what it last saw. It is a
 * separate function from `renderSessionChainRow` because rendering must stay
 * pure while the check itself cannot -- see its own doc comment for why.
 *
 * Nothing here knows what produced a decision -- the decision
 * badge reads ACS's own `decision`, `reason_codes`, and `policy_references`
 * fields and nothing else. The posture badge and the audit-entry line read
 * only the fields the audit log's AuditEntry declares.
 *
 * `renderDecisionBadge` is told a decision rather than handed a log row to
 * interrogate: `outcomeMessageOf` is the one place that reads an envelope's
 * shape, translating a log line into the small message the renderers need,
 * so a caller can build and render that message without owning an envelope
 * log at all.
 *
 * A decision and an error are two outcomes, not two decisions: a
 * schema-invalid envelope comes back as a JSON-RPC error, which is
 * deliberately not the same thing as an ACS `deny`. `OutcomeMessage` is a
 * discriminated union over the two, with its own renderer per arm --
 * `renderDecisionBadge` for a decision, `renderRpcError` for a response that
 * carried none -- and `renderOutcome` dispatches between them for the
 * stream renderer.
 */
import type { AuditEntry } from "./tail-audit-log.ts";
import type { EnvelopeLogEntry } from "./tail-envelope-log.ts";
import type { SessionContextLogEntry } from "./tail-session-context.ts";

export type RenderOptions = { color?: boolean; indent?: number };

const RESET = "\u001b[0m";
const RED = "\u001b[31m";
const GREEN = "\u001b[32m";
const YELLOW = "\u001b[33m";
const CYAN = "\u001b[36m";
const DIM = "\u001b[2m";

export type PolicyReference = { policy_id?: string; policy_version?: string; rule_id?: string };

/**
 * What a caller tells the decision badge, already narrowed to the ACS
 * fields it renders. Only ever an actual ACS decision -- see
 * `OutcomeMessage` for why this type covers only decisions.
 */
export type DecisionMessage = {
  decision: string;
  reason_codes: string[];
  policy_references: PolicyReference[];
};

/** What a response carried instead of a decision: the JSON-RPC error object. */
export type RpcErrorMessage = { code: number | null; message: string };

/**
 * What one envelope-log response line reports about its step: a decision,
 * or the JSON-RPC error that stood in place of one.
 *
 * A discriminated union rather than one object with an optional `error` beside
 * a `decision`, because a response carries exactly one of them and the other
 * arm's fields would have to be invented. A `steps/*` response either names an
 * ACS `decision` or is a JSON-RPC error; a caller cannot report both, and
 * cannot report neither.
 *
 * `kind` rather than structural narrowing on a key's presence, so the two arms
 * stay tellable apart by a caller that does not already know which fields
 * belong to which -- and so the union reads as two outcomes rather than as a
 * decision with an error mode.
 */
export type OutcomeMessage =
  | ({ kind: "decision" } & DecisionMessage)
  | ({ kind: "error" } & RpcErrorMessage);

type DecisionResult = {
  decision?: unknown;
  reason_codes?: unknown;
  policy_references?: unknown;
};
type ResponseEnvelope = { result?: DecisionResult; error?: { code?: unknown; message?: unknown } };

function paint(text: string, color: string, enabled: boolean): string {
  return enabled ? `${color}${text}${RESET}` : text;
}

/** `2026-08-09T12:04:31.221Z` -> `12:04:31.221`. Sliced, not parsed: UTC and
 * locale-independent, so rendered output is the same everywhere. */
function clockOf(recordedAt: string): string {
  const time = recordedAt.slice(11, 23);
  return time.length === 12 ? time : recordedAt;
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

/** The `policy_references` a response carried, narrowed to objects. Kept
 * separate from the formatting below so the message stays structured: a
 * caller building a `DecisionMessage` by hand passes references, not
 * pre-rendered strings. */
function policyReferenceList(value: unknown): PolicyReference[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is PolicyReference => typeof item === "object" && item !== null);
}

/** Formats each `policy_references` entry as `policy_id#rule_id`, falling
 * back to the bare `policy_id` when `rule_id` is absent. ACS's schemas do
 * not require `rule_id` on a policy_reference, so that fallback is a real
 * shape this renders deliberately, not a defect. */
function formatReferences(references: PolicyReference[]): string[] {
  return references.map((ref) => (ref.rule_id ? `${ref.policy_id ?? "?"}#${ref.rule_id}` : `${ref.policy_id ?? "?"}`));
}

/**
 * What one envelope-log line reports, or null when it reports no outcome at
 * all: a request, or a response such as a ServerHello.
 *
 * The one place in this module that reads an envelope's shape. It is a
 * translation, not a collaboration -- it turns an artifact into the message the
 * renderers speak -- and confining it here is what lets `renderDecisionBadge`
 * be told a decision instead of interrogating a log row for one.
 */
export function outcomeMessageOf(entry: EnvelopeLogEntry): OutcomeMessage | null {
  if (entry.direction !== "response") {
    return null;
  }
  const envelope = (typeof entry.envelope === "object" && entry.envelope !== null ? entry.envelope : {}) as ResponseEnvelope;

  if (envelope.error) {
    return {
      kind: "error",
      code: typeof envelope.error.code === "number" ? envelope.error.code : null,
      message: typeof envelope.error.message === "string" ? envelope.error.message : "",
    };
  }

  const result = envelope.result;
  if (!result || typeof result.decision !== "string") {
    return null;
  }

  return {
    kind: "decision",
    decision: result.decision,
    reason_codes: stringList(result.reason_codes),
    policy_references: policyReferenceList(result.policy_references),
  };
}

/**
 * A response that carried no decision, rendered as the error it was.
 *
 * Its own function rather than an arm of the decision badge: a
 * schema-invalid envelope comes back as a JSON-RPC error, which this module
 * treats as a distinct outcome from an ACS decision, never as an implicit
 * `deny`. The line looks like the badge beside it on purpose, but no type or
 * function here calls it a decision.
 */
export function renderRpcError(message: RpcErrorMessage, options: RenderOptions = {}): string {
  const color = options.color ?? false;
  const code = message.code ?? "?";
  const text = message.message;
  return paint(`✖ ERROR ${code}${text ? `  ${text}` : ""}`, RED, color);
}

/** Renders the ACS decision it is given. */
export function renderDecisionBadge(message: DecisionMessage, options: RenderOptions = {}): string {
  const color = options.color ?? false;

  const reasonCodes = message.reason_codes;
  const references = formatReferences(message.policy_references);

  let head: string;
  if (message.decision === "deny") {
    head = paint("● DENY", RED, color);
  } else if (message.decision === "allow" && references.length > 0) {
    // A policy fired and the action still proceeded. ACS carries that as
    // `allow` with a non-empty `policy_references`, and rendering it
    // identically to a clean allow is exactly what this badge exists to
    // prevent.
    //
    // This package carries no policy-runtime vocabulary: the label says only
    // what ACS itself reports, not the policy engine's own name for the case.
    head = paint("◐ ALLOW (policy fired)", YELLOW, color);
  } else if (message.decision === "allow") {
    head = paint("○ ALLOW", GREEN, color);
  } else {
    head = paint(`◆ ${message.decision.toUpperCase()}`, CYAN, color);
  }

  // Dimmed rather than left plain: with color:true, painting only `head`
  // made a coloured badge read as one coloured half and one plain half.
  // `paint` no-ops when `color` is false, so this changes nothing about the
  // color:false output the exact-string tests above assert byte-for-byte.
  const parts = [head];
  if (reasonCodes.length > 0) {
    parts.push(paint(`reason_codes=[${reasonCodes.join(", ")}]`, DIM, color));
  }
  if (references.length > 0) {
    parts.push(paint(`policy_references=[${references.join(", ")}]`, DIM, color));
  }
  return parts.join("  ");
}

/** The line one envelope-log outcome renders as -- the decision badge for a
 * decision, the error line for a response that carried none. One dispatch,
 * so the stream renderer does not have to know the arms apart. */
export function renderOutcome(message: OutcomeMessage, options: RenderOptions = {}): string {
  return message.kind === "decision" ? renderDecisionBadge(message, options) : renderRpcError(message, options);
}

/**
 * Header line, optional badge line, then the envelope as pretty JSON.
 *
 * What the body shows is the JSON value the envelope log recorded, printed
 * unmodified: nothing here strips a field, redacts a value, or reorders
 * anything. It is not a byte-for-byte replay of the wire -- the Guardian
 * records `await req.json()`, so the parse has already collapsed duplicate
 * keys, canonicalised number literals (`1.0` -> `1`), and hoisted
 * integer-like object keys ahead of the rest, and tool argument names are
 * host-controlled, so `arguments` really can carry a key like `"0"`. Storing
 * raw bytes instead would make `entry.envelope` a string rather than a JSON
 * value, which costs the pretty-printing below and the round-trip contract
 * test.
 */
export function renderEnvelopeLogEntry(entry: EnvelopeLogEntry, options: RenderOptions = {}): string {
  const color = options.color ?? false;
  const arrow = entry.direction === "request" ? "→ REQUEST " : "← RESPONSE";
  const method = entry.method ?? "(no method)";
  const id = entry.rpc_id === null ? "(unpaired)" : `id=${entry.rpc_id}`;

  const header = paint(`── #${entry.seq}  ${clockOf(entry.recorded_at)}  ${arrow}  ${method}  ${id}`, DIM, color);
  const message = outcomeMessageOf(entry);
  const outcome = message === null ? null : renderOutcome(message, options);
  // `JSON.stringify` returns `undefined` -- not a string -- for an entry
  // whose `envelope` key is absent, and `join` would coerce that to an empty
  // line indistinguishable from a real blank body. `isEnvelopeLogEntryShape`
  // does not require `envelope` (it is `unknown` by design), so a
  // hand-written or truncated envelope-log line can reach here without one.
  const body = JSON.stringify(entry.envelope, null, options.indent ?? 2) ?? "(no envelope recorded)";

  return [header, ...(outcome === null ? [] : [outcome]), body].join("\n");
}

/**
 * The posture badge's running state: the posture carried by the most recent
 * audit-log entry, and how many audited fail-open proceeds have crossed
 * since the tail started.
 *
 * `posture` is the *last observed* posture, not the negotiated one, and the
 * label says so. It is null until an audit-log entry arrives -- which, in
 * the healthy case, is forever: a session with zero delivery failures
 * writes no audit entry at all, and the posture it negotiated is sitting in
 * the session store this package cannot read. It cannot read it for a
 * stated reason rather than an accidental one: the store is keyed by the
 * host's own raw session identifier, which no artifact this package tails
 * carries (see tail-audit-log.ts's module doc on the raw vs derived split),
 * and reading a host-side store would cross the boundary that keeps this
 * package an observer of the wire, not a participant in the host's own
 * state.
 */
export type PostureBadgeState = { posture: "proceed" | "deny" | null; proceeds: number };

/**
 * The count is the point (see this module's own header and §6.4): a
 * fail-open proceed is a tool call that ran with no policy decision behind
 * it, and it is invisible unless something puts a number on it. A non-zero
 * count is painted as a warning; zero is clean. The posture itself is
 * painted so `deny` and `proceed` read as visibly different states, not
 * just different words -- distinguishing them is what this badge is for.
 *
 * Both halves are labelled as what they are: the posture is the last one
 * *observed* in the audit log, and its absence is "(none observed)", not
 * "(not negotiated)". A label of "(not negotiated)" would make a claim this
 * badge cannot check -- a session that negotiated `deny` and had zero
 * delivery failures is the healthy case, and it would read as though
 * nothing had been negotiated at all.
 */
export function renderPostureBadge(state: PostureBadgeState, options: RenderOptions = {}): string {
  const color = options.color ?? false;
  const postureLabel = state.posture === null ? "(none observed)" : state.posture;
  const postureColor = state.posture === "deny" ? RED : state.posture === "proceed" ? GREEN : DIM;
  const proceedsColor = state.proceeds > 0 ? YELLOW : GREEN;

  return [
    paint(`last_observed_posture=${postureLabel}`, postureColor, color),
    paint(`fail-open proceeds=${state.proceeds}`, proceedsColor, color),
  ].join("  ");
}

/**
 * One audit-log line as a header plus the reason it was written. Every
 * AuditEntry carries an `outcome`, and the three are rendered distinctly
 * (`PROCEEDED` in the same warning colour as the posture badge's non-zero
 * count, `BLOCKED` in the deny colour, `UNGOVERNED` in the warning colour
 * too) for the same reason renderDecisionBadge refuses to render a fired
 * policy identically to a clean allow: the outcome that bypassed a decision
 * is the one line here that must not read like an ordinary one.
 *
 * `UNGOVERNED` shares `PROCEEDED`'s colour rather than getting a fourth,
 * and that is the honest pairing: both are steps that ran with no decision.
 * They are separate WORDS because how they got there differs entirely --
 * one bypassed a decision the deployment wanted made, the other was never
 * asked for because the deployment's own hookmap scoped the tool out -- and
 * an incident review acts on that difference. It is not `BLOCKED`'s colour
 * because nothing was blocked.
 *
 * The audit log records the host's own raw session identifier, not the
 * UUID derived from it that the envelope log's envelopes carry (see
 * tail-audit-log.ts's module doc) -- the two logs cannot be joined on it.
 * Labelled `audit_session` here, deliberately not `session`, so nothing
 * reads this value as comparable to an id printed anywhere near a rendered
 * EnvelopeLogEntry.
 */
export function renderAuditEntry(entry: AuditEntry, options: RenderOptions = {}): string {
  const color = options.color ?? false;
  const outcomeLabel = entry.outcome === "blocked" ? "BLOCKED" : entry.outcome === "proceeded" ? "PROCEEDED" : "UNGOVERNED";
  const outcomeColor = entry.outcome === "blocked" ? RED : YELLOW;
  const id = entry.rpc_id === null ? "(unpaired)" : `id=${entry.rpc_id}`;
  // Same fallback renderEnvelopeLogEntry uses for a log line with no method,
  // and for the same reason: an entry written before any request could be built
  // has no ACS method, and this renderer has no other vocabulary to fall back
  // on.
  const method = entry.method ?? "(no method)";

  // No `posture=` on an ungoverned line, because no posture was consulted --
  // printing this session's declared one there would read as "the deployment
  // chose to proceed", which is not what happened. The writer does not carry
  // the field on that arm at all, so this is the type being honest rather
  // than this renderer choosing to omit something it was given.
  const postureField = entry.outcome === "ungoverned" ? "" : `posture=${entry.posture}/${entry.posture_source}  `;
  const header = paint(
    `── #${entry.seq}  ${clockOf(entry.recorded_at)}  ${outcomeLabel}  ${method}  ${id}  ` +
      `${postureField}audit_session=${entry.session_id}`,
    outcomeColor,
    color,
  );

  // The tool and the list that declined it, together: the drift this line
  // exists to make visible is a `tools` list that stopped matching the names
  // the host sends, and neither half shows it alone.
  if (entry.outcome === "ungoverned") {
    const declared = entry.ungoverned.tools.length === 0 ? "(none)" : entry.ungoverned.tools.join(", ");
    return [header, paint(`ungoverned=${entry.ungoverned.tool}: not in this gate's tools [${declared}]`, DIM, color)].join(
      "\n",
    );
  }

  const failureLine = paint(`failure=${entry.failure.kind}: ${entry.failure.message}`, DIM, color);
  // A second, separately labelled line rather than a merged one: the session's
  // configuration failing and this step's decision failing are different
  // events, and the whole point of recording both is that neither gets
  // attributed to the other.
  const sessionLine =
    entry.session_failure === undefined
      ? []
      : [paint(`session_failure=${entry.session_failure.kind}: ${entry.session_failure.message}`, DIM, color)];

  return [header, failureLine, ...sessionLine].join("\n");
}

/** How many leading characters of a `SessionContextLogEntry` hash
 * `renderSessionChain` prints on a row -- an abbreviation for a human's eye,
 * not the value a chain check compares. The check below always compares the
 * two full 64-character hex digests; only the printed text is shortened. */
const SHORT_HASH_LENGTH = 12;

/**
 * The per-session state a chain-break check needs: the `hash` of the last
 * entry seen so far for each `session_id`. `renderSessionChain` builds one
 * of these itself and throws it away when the whole array has been walked;
 * a caller that renders one entry at a time as they arrive -- the
 * Inspector's own live view in packages/inspector/src/main.ts -- keeps one
 * of these across calls instead, so the check does not have to be re-run
 * over the whole history on every new entry.
 */
export type SessionChainState = { lastHashSeenBySession: Map<string, string> };

/** A fresh, empty `SessionChainState` -- no session has a last-seen hash yet. */
export function createSessionChainState(): SessionChainState {
  return { lastHashSeenBySession: new Map() };
}

/** What the check decided about one entry's link to its predecessor. */
export type SessionChainLink = { broken: boolean };

/**
 * The chain check: the only place that decides whether a link is broken, and
 * the only function in this module that writes anything. `renderSessionChain`
 * calls it once per entry, in array order, against state it owns for the
 * duration of that one call; `main.ts`'s live view calls it once per entry as
 * it is tailed, against state it keeps for the life of the process -- so the
 * two never compute whether a link is broken two different ways.
 *
 * It is kept separate from the renderer because it records as well as
 * answers: it writes this entry's `hash` into `state` as the one the next
 * entry for this session must link to. If that recording were folded into
 * `renderSessionChainRow`, rendering would become a mutation, and rendering
 * the same entry twice would report a chain break on the second call, because
 * by then `state` would hold that entry's own `hash` and its `prev_hash`
 * would no longer match.
 *
 * A link is broken when the entry's `prev_hash` does not match the `hash` of
 * the entry seen immediately before it for the same `session_id` -- read out
 * of `state`, not out of whatever entry came immediately before this one in
 * some caller's array, because that entry can belong to a different session
 * entirely (see tail-session-context.ts's module doc on one log holding many
 * sessions). An entry that is the first one this `state` has seen for its
 * session is never broken: there is nothing recorded yet to compare its
 * `prev_hash` against.
 *
 * The whole reason this view exists is that the chain is checkable, not
 * merely printable -- a row that read as unbroken regardless of whether it
 * actually linked to its predecessor would be evidence that looks like
 * evidence and is not.
 *
 * What this check is not, stated here because a reader is entitled to know
 * its edge. It compares links -- this entry's `prev_hash` against the last
 * `hash` seen for the session -- and never recomputes `hashEntry` over the
 * entry in front of it, so an entry's contents are never checked against its
 * own digest. Three edits therefore read as unbroken, each one measured
 * against this function: a self-consistent rewrite (change a step field and
 * leave `hash`/`prev_hash` alone -- the stored digest stops matching the
 * entry, and nothing recomputes it), a trailing truncation (every surviving
 * link still matches), and a deleted first entry (the next entry becomes the
 * first this `state` has seen, and a first entry is never marked, because
 * nothing here requires it to carry `GENESIS_HASH` or `seq` 1 -- the gap is
 * visible in the printed `seq` but is not flagged). What is caught is a link
 * that stopped matching: a clobbered `prev_hash`, or a dropped middle entry,
 * both measured. So this detects corruption and edits that do not bother to
 * re-link; it does not detect an adversary with write access to the log.
 */
export function checkSessionChainLink(
  entry: SessionContextLogEntry,
  state: SessionChainState,
): SessionChainLink {
  const priorHash = state.lastHashSeenBySession.get(entry.session_id);
  const broken = priorHash !== undefined && priorHash !== entry.prev_hash;
  state.lastHashSeenBySession.set(entry.session_id, entry.hash);
  return { broken };
}

/**
 * The Inspector's row: a pure rendering of an already-decided link. Call it
 * twice with the same arguments and it returns the same string twice, which
 * is what lets a caller re-render without re-checking.
 *
 * `session_id=` names the field it prints, deliberately not the bare
 * `session=`. The audit log's `audit_session=` a few functions up is
 * qualified because that value is the host's own raw session identifier and
 * is not comparable to anything on the ACS wire; this one is
 * `metadata.session_id`, the envelope's own. Two differently-scoped session
 * identifiers stream past the same eye when `main.ts` tails both logs at once,
 * and one of them printed as plain `session` would read as the canonical one.
 */
export function renderSessionChainRow(
  entry: SessionContextLogEntry,
  link: SessionChainLink,
  options: RenderOptions = {},
): string {
  const color = options.color ?? false;
  const row =
    `#${entry.seq}  ${entry.tool_name}  hash=${entry.hash.slice(0, SHORT_HASH_LENGTH)}  ` +
    `session_id=${entry.session_id}`;
  return link.broken ? paint(`✖ CHAIN BREAK  ${row}`, RED, color) : row;
}

/**
 * The Inspector's session-context view. One row per chain entry, in the
 * order given -- the same order `tailSessionContextLog` yields them in,
 * which is file order rather than any global ordering by `seq` (see that
 * module's doc: one log interleaves every session the Guardian has seen).
 * Each entry is checked by `checkSessionChainLink` against one
 * `SessionChainState` shared across the whole walk and then rendered, so a
 * chain break is decided the same way here as it is by a caller handling one
 * entry at a time.
 */
export function renderSessionChain(entries: SessionContextLogEntry[], options: RenderOptions = {}): string {
  if (entries.length === 0) {
    return "(no session chain entries)";
  }
  const state = createSessionChainState();
  return entries
    .map((entry) => renderSessionChainRow(entry, checkSessionChainLink(entry, state), options))
    .join("\n");
}
