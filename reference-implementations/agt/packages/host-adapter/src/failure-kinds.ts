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
 * recognise as a refusal of this envelope. See REFUSAL_RPC_CODES in
 * failure-posture.ts for why the recognised set is enumerated rather than
 * inferred, and for what that leaves in this bucket.
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
  | "decision_unrenderable";

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
 * Everything `AuditEntry.failure.kind` can name about one step: the wire's
 * failures, the Guardian's refusals, and this host's own faults.
 *
 * A union rather than one widened `DeliveryFailureKind`, so the honest half
 * stays honest. A reader asking "what can a delivery failure be?" gets four
 * answers; a reader asking "what can an audit entry say about a step?" gets
 * seven; and neither question is answered with the other one's list.
 */
export type StepFailureKind = DeliveryFailureKind | RefusalFailureKind | HostFailureKind;

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
 *   "render"   -- a decision arrived and was honoured in principle; this
 *                 host could not express it.
 *
 * A boolean could only express two of the three, and a second boolean would
 * have admitted a combination that means nothing ("nothing was sent, and a
 * decision arrived").
 */
export type FailureStage = "delivery" | "request" | "render";

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
