/**
 * applyFailurePosture handles the delivery half of ACS's two-failure-domain
 * split: evaluation failures fail closed on their own; this handles a
 * failure of the wire itself, by applying the negotiated posture.
 *
 * This function is only ever reached when NO usable decision arrived: the
 * Guardian stayed silent past the negotiated timeout, the transport died, or
 * an error response carried no decision. §6.4 says all three resolve the
 * same way -- apply the deployment's declared posture -- and that every step
 * which proceeds without a decision MUST be audited.
 *
 * With ONE exception, which is not §6.4's case at all, and which is why this
 * module now reads the failure before it reads the posture: a JSON-RPC error
 * whose code means the Guardian was alive and REFUSED this envelope. §6.4 is
 * about a decision that failed to arrive; a refusal is a decision withheld,
 * by the very component this host defers to. So a refusal resolves to `deny`
 * regardless of posture, and is still audited. Without that, a live Guardian
 * answering `-32020 evaluation failed` and a dead socket were the same kind,
 * and under the shipped default posture (`proceed`) both became `allow` --
 * a governance tool proceeding on the Guardian's own "no". See
 * REFUSAL_RPC_CODES for which codes mean that, and why the set is enumerated.
 *
 * It is NOT reached when a decision arrived. A `deny` that arrives is
 * honoured regardless of posture, and that is enforced by the caller never
 * calling this on a decision.
 *
 * §6.4 makes the audit entry a MUST for a step that proceeds without a
 * decision, and the audit sink is documented total -- it must never throw,
 * delay a decision, or change one, even when it cannot write. Those two
 * properties can disagree: when the write genuinely fails, the entry MUST
 * exist but the sink cannot make it exist. This function resolves that by
 * downgrading a `proceed` it could not audit to `deny`, with its own reason
 * code -- an unauditable bypass is not a bypass the spec permits. The sink's
 * own contract is untouched: it still never throws, never delays a decision,
 * and never changes one; the change is entirely in what this caller does
 * with a write it was told did not happen.
 *
 * Nothing here knows the policy runtime behind the wire. A delivery failure
 * is a property of the wire, and a refusal is a property of the Guardian's
 * willingness to answer this envelope -- neither is a property of whatever
 * evaluates policy on the other side of it, and nothing here names one.
 */
import type { AuditEvent, AuditSink } from "./audit-sink.ts";
import type {
  DeliveryFailureKind,
  FailureStage,
  RefusalFailureKind,
  SessionFailureKind,
  StepFailureKind,
} from "./failure-kinds.ts";
import type { AcsDecision } from "./decision-message.ts";
import { GuardianTimeoutError } from "./guardian-client.ts";
import { SessionConfigNotStoredError, type ResolvedSessionConfig } from "./handshake.ts";

// The failure taxonomies this module classifies into live in
// `./failure-kinds.ts`, shared with the audit sink that stores them, and are
// re-exported here so every importer of this module can find them without a
// second import.
export type {
  DeliveryFailureKind,
  FailureStage,
  HostFailureKind,
  RefusalFailureKind,
  SessionFailureKind,
  StepFailureKind,
} from "./failure-kinds.ts";

/** handshake.json's own default for `on_decision_failure`. */
export const DEFAULT_POSTURE = "proceed" as const;

/** Used when no handshake completed, so no timeout was negotiated either.
 * Matches the Guardian's declared default so the two agree by value. */
export const DEFAULT_TIMEOUT_MS = 5000;

/** A JSON-RPC error object, as it arrives in a response that carried no decision. */
type ErrorLike = { code?: unknown; message?: unknown };

/**
 * Connection-level `.code` values fetch can throw with, confirmed against
 * THIS runtime (Bun) rather than assumed from the WHATWG fetch spec. Bun's
 * fetch throws a plain `Error` (name "Error", not "TypeError") carrying one
 * of these on `.code` for a failure below the HTTP layer: refused, closed,
 * never opened, or a DNS lookup or TLS handshake that failed. Confirmed two
 * ways: reading Bun's own src/http/error.rs (the `Error` enum's `.name()` is
 * what becomes `.code`), and, for `ConnectionRefused` specifically,
 * provoking it directly (`fetch` against a reliably-refused port, port 1)
 * and inspecting the thrown value.
 *
 * Deliberately NOT exhaustive: Bun's TLS certificate-validation failures
 * fan out into a further ~70 more specific X.509 codes (a nested
 * `CertError` enum -- `CERT_HAS_EXPIRED`, `UNABLE_TO_GET_ISSUER_CERT`, and
 * so on) not enumerated here, because which of those actually surface as a
 * flat `.code` string (versus some other shape) is not confirmed --
 * enumerating them anyway would be exactly the kind of guess this list is
 * built to avoid. `ERR_TLS_CERT_ALTNAME_INVALID` is the one TLS-related code
 * confirmed as its own top-level enum member, so it is the one line "the TLS
 * equivalent" below commits to.
 */
const TRANSPORT_ERROR_CODES = new Set([
  "ConnectionRefused",
  "ConnectionClosed",
  "FailedToOpenSocket",
  "DNSResolveFailed",
  "DNSResolutionFailed",
  "ERR_TLS_CERT_ALTNAME_INVALID",
]);

/**
 * The JSON-RPC error codes that mean the Guardian was ALIVE and refused this
 * envelope, rather than that the wire failed. A response carrying one of
 * these is a governance outcome and fails closed regardless of posture (see
 * applyFailurePosture).
 *
 * Declared here by value rather than imported: this package has no runtime
 * dependency on the Guardian and is not about to grow one for four integers
 * -- the same arrangement DEFAULT_TIMEOUT_MS keeps with the Guardian's
 * declared default. The four are the complete set this deployment's Guardian
 * mints for a request it will not decide (packages/guardian/src/server.ts):
 *
 *   -32700  Parse error. Nothing the host sent was JSON. Answered with
 *           `id: null`, since there is no envelope to read an id out of --
 *           which is why guardian-client.ts's post() has to let an
 *           unaddressed error through before its id-correlation check, or
 *           this code could never reach this function at all.
 *   -32010  The envelope failed schema validation and the Guardian could not
 *           address a deny decision to it (no top-level id, or an id it
 *           cannot put in a response), or the body exceeded the Guardian's
 *           request cap. denyOnInvalidEnvelope converts the ADDRESSABLE
 *           steps/* cases into honoured denies Guardian-side; this closes the
 *           rest from the host's own side, which is what makes the
 *           Guardian's inability to address every deny non-load-bearing.
 *   -32011  The Guardian dispatched no handler for the method.
 *   -32020  Evaluation itself failed -- mapVerdict's own checks, a policy
 *           runtime error, or the outer net around dispatch.
 *
 * -32011 is the arguable one, so the reasoning is recorded rather than
 * assumed. A host only ever sends methods its own hookmap maps, so a Guardian
 * refusing to dispatch one is a misconfiguration of THIS deployment -- the
 * hookmap and the Guardian disagree about what is governed -- and that is not
 * a permission to proceed. The alternative reading, deliberately rejected:
 * handshake.json's `methods_evaluated` says "Methods listed by the client but
 * absent here are NOT evaluated ... Clients MAY still emit them for audit but
 * MUST treat them as ALLOW-by-default", which would make an undispatched
 * method an allow. That rule is about a method the ServerHello DECLARED it
 * would not evaluate -- negotiated coverage, known before the step -- not
 * about one the Guardian accepted at handshake and then refused at dispatch.
 * A host that read the second as the first would fail open on precisely the
 * disagreement it should surface.
 *
 * Enumerated rather than inferred ("any error object is a refusal"), for the
 * reason TRANSPORT_ERROR_CODES is: the four above are checkable against a
 * live Guardian, and client.test.ts drives each route to prove the list
 * matches what the Guardian actually sends rather than what this file
 * believes. An unrecognised code therefore stays `error_without_decision` and
 * keeps the posture. That is a genuine remaining hole -- a future Guardian
 * code would fail open under `proceed` until it is added here -- and it is
 * preferred to guessing, because widening this to every error object would
 * also fail closed on an intermediary's error the Guardian never sent.
 */
const REFUSAL_RPC_CODES = new Set([-32700, -32010, -32011, -32020]);

/**
 * Names what came back INSTEAD of a decision, for the audit entry. Total: an
 * unrecognised shape is "unknown", never a throw -- this runs while the host
 * is already handling a failure.
 *
 * Half of the `classify<Role>Failure` pair, with `classifySessionFailure`.
 * "Delivery" names the STAGE this classifier serves -- a request went out and
 * no decision came back -- and for three of its four kinds it is also the
 * diagnosis. `refused` is the one answer that is not a property of the wire
 * at all, and it lives here rather than in a sibling classifier on purpose:
 * this is the single function every no-decision outcome passes through, so
 * asking "was this a refusal?" cannot be the question a caller forgets.
 * Splitting it out would make the fail-open reachable again by omission.
 * `classifyStepFailure` below is the genuinely wider role, and it stays
 * private because nothing outside this module chooses a stage.
 *
 * The Guardian's own code travels into `message`, and that is the only place
 * it travels: `AuditEntry.failure.message` is durable and the Inspector
 * already renders it, so a reviewer reading the log sees which refusal it
 * was. A second structured copy of the same integer would have to be mirrored
 * in the Inspector's independently-declared AuditEntry for no reader.
 */
export function classifyDeliveryFailure(
  failure: unknown,
): { kind: DeliveryFailureKind | RefusalFailureKind; message: string } {
  try {
    if (failure instanceof GuardianTimeoutError) {
      return { kind: "timeout", message: failure.message };
    }
    if (failure instanceof Error) {
      // Two independent routes to "transport", because no single one is
      // reliable across runtimes: fetch does not always throw a TypeError
      // for this on the runtime this project actually runs on:
      //   1. The WHATWG fetch spec's own route: a TypeError for a network
      //      error. Other runtimes take this one, and a future Bun might.
      //   2. This runtime's actual route: a plain Error whose `.code`
      //      names a connection-level failure. Read defensively --
      //      `.code` is not a property of the `Error` type.
      const code = (failure as { code?: unknown }).code;
      const isTransport =
        failure instanceof TypeError || (typeof code === "string" && TRANSPORT_ERROR_CODES.has(code));
      return { kind: isTransport ? "transport" : "unknown", message: failure.message };
    }
    if (typeof failure === "object" && failure !== null && "code" in failure) {
      const { code, message } = failure as ErrorLike;
      // An error object means something answered: the wire worked, and the
      // question is whether what answered was the Guardian refusing this
      // envelope. `typeof code === "number"` is the guard, not a cast -- a
      // non-conformant peer can put anything on `code`, and Set.has on a
      // string that happens to read "-32020" would miss anyway.
      const refused = typeof code === "number" && REFUSAL_RPC_CODES.has(code);
      return {
        kind: refused ? "refused" : "error_without_decision",
        message: refused
          ? `guardian refused the envelope with error ${String(code)}: ${String(message)}`
          : `guardian returned error ${String(code)}: ${String(message)}`,
      };
    }
    return { kind: "unknown", message: String(failure) };
  } catch {
    return { kind: "unknown", message: "<unprintable failure>" };
  }
}

/**
 * Names which of the two session-establishment failures happened. Total, for
 * the same reason classifyDeliveryFailure is: this runs while the host is
 * already handling a failure.
 *
 * The two are distinct kinds, not one constant separated by free text, so a
 * Guardian-down session's audit entries make the occurrence that actually
 * costs something easy to find rather than burying it in a note.
 */
export function classifySessionFailure(failure: unknown): { kind: SessionFailureKind; message: string } {
  return {
    kind: failure instanceof SessionConfigNotStoredError ? failure.kind : "handshake_failed",
    message: messageOf(failure),
  };
}

export type ApplyFailurePostureInput = {
  /** Whatever the delivery attempt threw, or the JSON-RPC error it returned. */
  failure: unknown;
  /**
   * This session's config and whatever went wrong establishing it, exactly as
   * `resolveSessionConfig` answers -- the message, not its halves.
   *
   * The two are read for two unrelated purposes, and that is exactly why
   * they travel together:
   *
   *   - `config` decides the posture (its `on_decision_failure`, or the ACS
   *     default when nothing was negotiated) and, on the audit entry,
   *     `posture_source`.
   *   - `failure` never becomes this step's failure. It is recorded beside it as
   *     `session_failure`, because a session config that cannot be persisted
   *     means every hook re-negotiates and the declared posture never applies --
   *     which is how a deployment that asked to fail closed quietly fails open
   *     (see AuditEntry.session_failure).
   */
  session: ResolvedSessionConfig;
  sessionId: string;
  /** The ACS method, or null when no request was built and so none is
   * knowable. Never a host's own event name -- see AuditEntry.method. */
  method: string | null;
  rpcId: string | number | null;
  /** Required, not optional: §6.4 makes auditing non-skippable. */
  audit: AuditSink;
  /**
   * Where in the exchange this failure happened -- see FailureStage. Both
   * the classified kind and the reasoning follow from it, so that neither
   * blames a Guardian that was never contacted ("request") nor tells an
   * incident reviewer no decision arrived when one did ("render"). Defaults
   * to "delivery", which is every ordinary call site and §6.4's own case.
   */
  stage?: FailureStage;
};

/**
 * The ACS decision this function answers an absent one with -- the same
 * `AcsDecision` message every other path hands the host (decision-message.ts),
 * refined by what is additionally known about one that came from here.
 *
 * Named for the decision, not the posture: a posture is `proceed|deny` and
 * this payload is `allow|deny`, so naming the type after the posture would
 * make every reader translate one vocabulary into the other. The refinement
 * is the two facts a caller relies on:
 *
 *   - `decision` is `allow` or `deny` and never anything else, which is what
 *     lets a caller's fallback render of it be unfailing (a hookmap that
 *     loadHookmap accepted declares a renderable entry for both).
 *   - `reasoning` and `reason_codes` are always present -- a step that ran
 *     without a policy decision behind it must always say so, in prose a human
 *     reads and in a code a machine reads.
 */
export type FailureResolvedAcsDecision = AcsDecision & {
  decision: "allow" | "deny";
  reasoning: string;
  reason_codes: string[];
};

export function applyFailurePosture({
  failure,
  session,
  sessionId,
  method,
  rpcId,
  audit,
  stage = "delivery",
}: ApplyFailurePostureInput): FailureResolvedAcsDecision {
  const { config: sessionConfig, failure: sessionFailure } = session;
  const posture = sessionConfig?.on_decision_failure ?? DEFAULT_POSTURE;
  // Classified BEFORE the resolution is read, because for one kind it decides
  // the resolution. Everything else is the wire's business and the posture's;
  // a refusal is the Guardian's, and a governance tool does not proceed on it
  // -- see REFUSAL_RPC_CODES and REFUSAL_RESOLUTION.
  const classified = classifyStepFailure(stage, failure);
  const refused = classified.kind === "refused";
  // One resolution, read once, in the three vocabularies it is expressed in --
  // see RESOLUTION_BY_POSTURE.
  const { decision, outcome } = refused ? REFUSAL_RESOLUTION : RESOLUTION_BY_POSTURE[posture];

  // Computed before the audit write, and written into it: "the guardian was
  // down for this whole session" (default) and "this deployment chose to
  // fail open" (negotiated) are different incidents, and the durable record
  // -- not just the ephemeral `reasoning` string below -- has to be able to
  // tell them apart.
  const postureSource: "negotiated" | "default" = sessionConfig === undefined ? "default" : "negotiated";

  // §6.4's MUST. Wrapped because the decision must survive a sink that
  // breaks its own totality contract -- the posture is the load-bearing
  // half, the record is the accountability half, and losing the record must
  // not lose the posture.
  let audited = false;
  try {
    audited =
      audit.write({
        session_id: sessionId,
        method,
        rpc_id: rpcId,
        posture,
        posture_source: postureSource,
        outcome,
        failure: classified,
        ...(sessionFailure === undefined ? {} : { session_failure: classifySessionFailure(sessionFailure) }),
      }) === true;
  } catch {
    // The sink is documented total; if it throws anyway, there is nowhere
    // left to report it that would not have the same problem. It counts as
    // unaudited, which is the only thing the decision below needs from it.
  }

  // Honest about where the posture came from: a negotiated deployment
  // choice reads very differently from a session that never got that far.
  const postureOrigin =
    postureSource === "default"
      ? `no session was ever negotiated, so the ACS default posture (${DEFAULT_POSTURE}) applies`
      : "the session's negotiated posture applies";

  // Never names a Guardian for a request that never reached one: a
  // `host_configuration` failure is this host's own, and an audit trail
  // that blames the policy runtime for it sends an incident review to the
  // wrong process. `render` is the same misattribution read the other way
  // round -- a decision genuinely did arrive, so saying none did would send
  // that reviewer to the wrong process too, just a different wrong one.
  //
  // The "delivery" wording below is quoted verbatim in four
  // captures in the v3 runbook of the standalone repository
  // (github.com/afogel/ACS_reference_implementation, docs/demos/v3-runbook.md), reproduced
  // against a live Guardian.
  // It is not to be reworded without re-capturing them.
  const cause = refused
    ? `the guardian refused the envelope for ${method ?? "this step"} rather than deciding it ` +
      `(${classified.kind}: ${classified.message})`
    : stage === "request"
      ? `this host could not build a request for this step, so no decision was ever sought ` +
        `(${classified.kind}: ${classified.message})`
      : stage === "render"
        ? `a decision arrived from the guardian for ${method ?? "this step"} and was honoured, but this host ` +
          `could not express it (${classified.kind}: ${classified.message})`
        : `no decision arrived from the guardian for ${method ?? "this step"} (${classified.kind}: ${classified.message})`;

  const sessionNote =
    sessionFailure === undefined
      ? ""
      : ` this session's negotiated configuration could not be established or stored ` +
        `(${messageOf(sessionFailure)}), so any posture this deployment declared was unavailable to this step;`;

  // Returns before both of the two exits below, because both of them speak
  // about `on_decision_failure` -- what this deployment declared should happen
  // when a decision does not arrive -- and a refusal is a decision withheld,
  // not one lost. Saying "on_decision_failure=proceed, so this step was
  // blocked" would read as a posture contradicting itself; saying it was
  // blocked for want of an audit entry would name the wrong reason entirely.
  // It is still audited -- the write above already happened -- and an
  // unauditable refusal needs no downgrade for the same reason an unauditable
  // deny does not: the step is blocked either way, and the failed write is
  // reported by the sink's own error path.
  if (refused) {
    return {
      decision,
      reasoning:
        `${cause};${sessionNote} the guardian was reachable and answered, so this is not a delivery failure ` +
        `and on_decision_failure=${posture} does not apply -- a step the guardian would not decide is not a ` +
        "step this host may proceed with, so it was blocked.",
      reason_codes: [REFUSAL_REASON_CODE],
    };
  }

  // The audit requirement outranks the posture here, and this is the one
  // place the two can disagree. §6.4 makes the audit entry a MUST for a
  // step that proceeds without a decision, so a proceed that could not be
  // recorded is not a proceed this deployment is entitled to take: an
  // unauditable bypass is exactly the silent bypass this project exists to
  // make impossible. The sink stays total (it never threw and never will);
  // what changes is what the caller does with a failed write. A `deny`
  // needs no such downgrade -- the step is blocked either way, and the
  // failed write is already reported by the sink's own error path.
  if (posture === "proceed" && !audited) {
    return {
      decision: "deny",
      reasoning:
        `${cause};${sessionNote} ${postureOrigin} -- on_decision_failure=proceed, but the audit entry §6.4 ` +
        "requires for a step that proceeds without a decision could not be recorded, so this step was blocked " +
        "instead: a bypass that cannot be recorded is not one this deployment can take.",
      reason_codes: ["decision_failure", "audit_unavailable"],
    };
  }

  return {
    decision,
    reasoning: `${cause};${sessionNote} ${postureOrigin} -- on_decision_failure=${posture}, so this step was ${outcome}.`,
    reason_codes: [REASON_CODE_BY_STAGE[stage]],
  };
}

/**
 * The one place a posture becomes the other two vocabularies this resolution is
 * expressed in: the ACS decision the host is handed, and the outcome the audit
 * entry records.
 *
 * One declaration, read once, so the posture, the decision, and the outcome
 * agree by construction rather than by three separate encodings staying in
 * step by proximity alone.
 *
 * The three vocabularies are deliberately NOT collapsed into one; the note on
 * the posture arm's own `outcome` (audit-sink.ts) is where that was weighed
 * and why the audit rail keeps its own. Both of this table's value types are
 * read off that arm's declarations, so the table and the artifact cannot
 * drift apart.
 *
 * The ARM, not `AuditEvent` whole: that type gained a second member for a
 * step no posture was consulted for, and reading `AuditEvent["outcome"]`
 * here would let this table's values widen to include `"ungoverned"` -- a
 * word no posture can ever resolve to, admitted into the one table whose job
 * is that the posture, the decision and the outcome agree by construction.
 *
 * Consulted for every failure except a refusal, which REFUSAL_RESOLUTION
 * answers instead -- there is no posture row for it, because the deployment
 * never got to declare one.
 */
type PostureResolvedAuditEvent = Extract<AuditEvent, { outcome: "proceeded" | "blocked" }>;

const RESOLUTION_BY_POSTURE: Record<
  PostureResolvedAuditEvent["posture"],
  { decision: "allow" | "deny"; outcome: PostureResolvedAuditEvent["outcome"] }
> = {
  proceed: { decision: "allow", outcome: "proceeded" },
  deny: { decision: "deny", outcome: "blocked" },
};

/**
 * A refusal's resolution: the one that is not read out of a posture.
 *
 * `blocked` rather than a fourth outcome word, because `AuditEntry.outcome`
 * reports what became of the step and the step was blocked -- inventing
 * `refused` there would give the Inspector a badge stem to learn for a fact
 * the entry already carries twice over, in `failure.kind` and in the code
 * inside `failure.message`. A refusal-driven block stays distinguishable from
 * a posture-driven one in the log without that: `failure.kind` names it
 * outright, and `posture: "proceed"` beside `outcome: "blocked"` is a pair no
 * posture-driven entry can produce (the unauditable-proceed downgrade denies
 * only when the write failed, which is precisely when no entry exists).
 *
 * Shaped like a RESOLUTION_BY_POSTURE row, and read off the same
 * `PostureResolvedAuditEvent` arm, so the two cannot drift into disagreeing
 * about what a `blocked` step is. The ARM and not `AuditEvent` whole, for the
 * reason RESOLUTION_BY_POSTURE gives: the union's other member carries
 * `"ungoverned"`, and a refusal is a step this deployment governed and
 * blocked -- the one thing it is certainly not is ungoverned.
 */
const REFUSAL_RESOLUTION: { decision: "allow" | "deny"; outcome: PostureResolvedAuditEvent["outcome"] } = {
  decision: "deny",
  outcome: "blocked",
};

/** One reason code per stage, so the machine-readable half of the decision
 * carries the same distinction the prose does. */
const REASON_CODE_BY_STAGE: Record<FailureStage, string> = {
  delivery: "decision_failure",
  request: "host_configuration",
  render: "decision_unrenderable",
};

/** A refusal's own code, not a stage's: it can only happen at the delivery
 * stage, and `decision_failure` there would tell a machine reader that no
 * decision arrived when the Guardian's refusal is exactly what did. */
const REFUSAL_REASON_CODE = "guardian_refused";

/**
 * The classified `{kind, message}` for one step, at the stage that failed --
 * the whole role, of which delivery is one third. Only "delivery" consults the
 * failure value itself: the other two stages KNOW what happened -- the
 * failure object is the detail, not the diagnosis -- and running them
 * through classifyDeliveryFailure is what produced "unknown" for two
 * precisely-known, entirely host-side causes.
 *
 * `classifyStepFailure`, not `classifyByStage`: same `classify<Role>Failure`
 * shape as the two exported classifiers, and it names what it returns rather
 * than how it dispatches.
 */
function classifyStepFailure(stage: FailureStage, failure: unknown): { kind: StepFailureKind; message: string } {
  switch (stage) {
    case "request":
      return { kind: "host_configuration", message: messageOf(failure) };
    case "render":
      return { kind: "decision_unrenderable", message: messageOf(failure) };
    default:
      return classifyDeliveryFailure(failure);
  }
}

/** The message of whatever was thrown, without assuming it was an Error. */
function messageOf(failure: unknown): string {
  try {
    return failure instanceof Error ? failure.message : String(failure);
  } catch {
    return "<unprintable failure>";
  }
}
