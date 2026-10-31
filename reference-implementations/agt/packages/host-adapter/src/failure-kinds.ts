/**
 * The failure taxonomies one step's audit entry can name -- what went wrong on
 * the wire, what the Guardian refused, what went wrong on this side of the
 * wire, and what went wrong while establishing the session -- plus the stage
 * of the exchange each belongs to.
 *
 * A module of its own, so the writer and the classifier share one
 * declaration. `failure-posture.ts` builds these values and `audit-sink.ts`
 * is the durable boundary that stores them; sharing one declaration here
 * keeps the taxonomy `applyFailurePosture` builds from being lost at the one
 * boundary that outlives the process, which is also the only one an incident
 * review ever reads. The two modules cannot simply import from each other
 * (`failure-posture.ts` already depends on `audit-sink.ts` for the sink
 * role), so the shared vocabulary lives here, the same way
 * `decision-message.ts` holds the decision every module on this side speaks.
 *
 * These name failures of the wire, refusals by the Guardian, and faults of
 * this host. No policy-runtime vocabulary: a delivery failure is a property
 * of the wire, and a refusal is a property of the Guardian's willingness to
 * answer this envelope at all -- neither names a rule, a verdict, or
 * anything else belonging to whatever evaluates policy on the other side.
 *
 * The wire/refusal split is the load-bearing one, and it did not exist at
 * first: every no-decision outcome was a `DeliveryFailureKind`, so a
 * Guardian that was alive and refused an envelope resolved exactly like a
 * dead socket -- which under the shipped default posture (`proceed`) meant
 * `allow`. A governance tool must not proceed because the thing governing it
 * said no in a shape the host was not reading.
 */

/**
 * What went wrong ON THE WIRE: a request went out and no usable decision came
 * back, because nothing usable came back at all. §6.4's own case, and the
 * only kinds a delivery failure resolves under the negotiated posture.
 *
 * Deliberately narrow, in two directions. `host_configuration` and
 * `decision_unrenderable` are not delivery failures at all -- both are
 * precisely-known, entirely host-side causes -- so including them here would
 * mean `failure.kind` presents them under a delivery-shaped name. And
 * `refused` is not one either: something answered, so the wire worked. A type
 * that lies is a lie the type system then teaches every reader. The first two
 * live in `HostFailureKind` below, the third in `RefusalFailureKind`.
 *
 * `error_without_decision` is what is left of the JSON-RPC-error case once
 * the refusals are taken out of it: an error whose code this host does not
 * recognise as a refusal of this envelope. See isRefusalCode below
 * for which codes are recognised, and for what that leaves in this bucket.
 */
export type DeliveryFailureKind = "timeout" | "transport" | "error_without_decision" | "unknown";

/**
 * What went wrong ON THIS SIDE of the wire, when the wire was never the
 * problem. Neither of these is reachable from `classifyDeliveryFailure`: the
 * stage already knows which one happened (see `classifyStepFailure`), because
 * for these two the failure object is the detail, not the diagnosis.
 */
export type HostFailureKind =
  /**
   * The request was never sent, because this host could not build one. Its own
   * kind because "unknown" was actively misleading for it -- the cause is
   * precisely known and entirely host-side, and an audit entry that files a
   * host misconfiguration under an unknown delivery failure sends an incident
   * review to the wrong process.
   */
  | "host_configuration"
  /**
   * A decision DID arrive and was honoured in principle -- what failed was
   * this host expressing it (a decision string no hookmap entry names, or a
   * hookmap gap). Same misattribution as `host_configuration` fixed one step
   * earlier in the exchange: auditing it as "no decision arrived from the
   * guardian" tells an incident reviewer to go and look at a Guardian that
   * answered correctly, when the fault is in this host's own rendering table.
   */
  | "decision_unrenderable"
  /**
   * The request was built but this host could not sign it -- input nested
   * deeply enough to overflow canonicalisation, say. Never sent, and never
   * answered by the posture: an ACS-Core Guardian must refuse an unsigned
   * request, so this host refuses it first, the same as a refusal. Under
   * `proceed` the posture would have run a step that without HMAC is denied.
   */
  | "unsignable";

/**
 * What the Guardian did when it was ALIVE and would not answer this envelope
 * with a decision: it answered, in JSON-RPC, with an error naming its refusal.
 *
 * Its own axis rather than a fifth `DeliveryFailureKind`, because the
 * RESOLUTION differs and the type is where that difference has to be visible.
 * A delivery failure is resolved by the negotiated posture (§6.4): nothing was
 * heard, so the deployment's declared stance on silence governs. A refusal was
 * heard. Applying a `proceed` posture to it would let a governance tool
 * proceed on the Guardian's own "no" -- which is not a stance a deployment can
 * declare, because §6.4 never offered it one: it is about a decision that
 * failed to arrive, not about one that was withheld.
 *
 * One member, deliberately. What an incident reviewer needs from the record is
 * that this was a refusal rather than an accident, and WHICH refusal -- and
 * the second half is the JSON-RPC code, which travels in
 * `AuditEntry.failure.message` (see classifyDeliveryFailure, which puts it
 * there). Splitting the kind per code would carry the same fact twice and
 * hand the Inspector a vocabulary to keep in step for nothing.
 */
export type RefusalFailureKind = "refused";

/**
 * Something answered and the answer cannot be trusted: its signature failed
 * verification, or it answers a different request (its JSON-RPC id or
 * `result.request_id` does not match the one sent). A tampered deny, a
 * stripped signature, or a replayed earlier allow all land here.
 *
 * Not a delivery failure, so never answered by the posture: under `proceed`
 * an on-path attacker could otherwise turn any decision into an allow. Issue
 * #308 rules that such a reply blocks the step whatever `on_decision_failure`
 * says, and is recorded as an integrity failure, class `signature_invalid`,
 * not as a deny from the Guardian.
 */
export type IntegrityFailureKind = "signature_invalid";

/**
 * Everything `AuditEntry.failure.kind` can name about one step: the wire's
 * failures, the Guardian's refusals, and this host's own faults.
 *
 * A union rather than one widened `DeliveryFailureKind`, so the honest half
 * stays honest. A reader asking "what can a delivery failure be?" gets four
 * answers; a reader asking "what can an audit entry say about a step?" gets
 * seven; and neither question is answered with the other one's list.
 */
export type StepFailureKind = DeliveryFailureKind | RefusalFailureKind | IntegrityFailureKind | HostFailureKind;

/**
 * WHERE in the exchange the failure happened. Three materially different
 * incidents, and the audit record has to tell them apart -- an entry that
 * confuses them sends an incident review to the wrong process:
 *
 *   "delivery" -- a request went out and no usable decision came back.
 *                 §6.4's own case, and the default for every ordinary call
 *                 site.
 *   "request"  -- no request was ever built, so nothing was asked of
 *                 anything. Host-side configuration, and the reasoning must
 *                 not name a Guardian that was never contacted.
 *   "sign"     -- a request was built and this host could not sign it, so
 *                 it was never sent. Fails closed, never by posture.
 *   "render"   -- a decision arrived and was honoured in principle; this
 *                 host could not express it.
 *
 * A boolean could only express two of these, and a second boolean would
 * have admitted a combination that means nothing ("nothing was sent, and a
 * decision arrived").
 */
export type FailureStage = "delivery" | "request" | "sign" | "render";

/** What went wrong establishing this session's negotiated config, for
 * `AuditEntry.session_failure`. */
export type SessionFailureKind =
  /**
   * The handshake never came back with a ServerHello: the Guardian was
   * unreachable, timed out, or answered with a JSON-RPC error. Nothing was
   * negotiated, so there is no posture to lose -- `posture_source: "default"`
   * on the same entry already says the ACS default applied, and in a
   * Guardian-down session EVERY entry carries this.
   */
  | "handshake_failed"
  /**
   * A ServerHello arrived and this host could not keep it. Materially
   * different from the above and the reason this field is not one constant:
   * a posture WAS negotiated. It is applied to the step that negotiated it,
   * and every LATER hook in the session re-handshakes because the file the
   * next subprocess would have read is not there -- so a store that stays
   * unwritable is a deployment quietly paying a round trip per hook, and one
   * whose declared posture depends on that round trip continuing to succeed.
   */
  | "session_config_unstored"
  /**
   * A ServerHello arrived and was not a usable session config at all. No
   * posture was negotiated, so -- unlike the case above -- there is nothing
   * to apply to this step either; the ACS default governs. Its own kind
   * because the remedy is entirely different: this one is a Guardian
   * emitting the wrong shape, not a host that cannot write to its own disk.
   */
  | "server_hello_invalid";

/**
 * The JSON-RPC error codes that mean the Guardian was ALIVE and refused this
 * envelope, rather than that the wire failed. A response carrying one of
 * these is a governance outcome and fails closed regardless of posture (see
 * applyFailurePosture).
 *
 * Declared here by value rather than imported: this package has no runtime
 * dependency on the Guardian and is not about to grow one for a few integers
 * -- the same arrangement DEFAULT_TIMEOUT_MS keeps with the Guardian's
 * declared default. Besides §17.1's own codes, these are the ones this
 * deployment's Guardian mints for a request it will not decide (packages/guardian/src/server.ts):
 *
 *   -32700  Parse error. Nothing the host sent was JSON. Answered with
 *           `id: null`, since there is no envelope to read an id out of --
 *           which is why guardian-client.ts's post() has to let an
 *           unaddressed error through before its id-correlation check, or
 *           this code could never reach classifyDeliveryFailure at all.
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
 * Recognised by range, not by list. Every §17.1 code and every code this
 * Guardian mints sits in JSON-RPC's server-error range, -32000 to -32099, which
 * ACS uses for nothing but refusals. A list would fail open under `proceed` on
 * any code added after it was written, such as a retryable overload code: the
 * step would run because the host did not yet know the code. Codes outside
 * the range, like an intermediary's -32601 or -32603, stay
 * `error_without_decision` and keep the posture.
 */
export function isRefusalCode(code: unknown): boolean {
  return typeof code === "number" && (code === -32700 || (code <= -32000 && code >= -32099));
}
