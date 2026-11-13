/**
 * The ACS decision message this adapter speaks, and the one deny it
 * substitutes. Kept in a module of its own so validate-decision.ts (the
 * orchestrator), decision-expiry.ts (one of the collaborators it sequences),
 * render-decision.ts (which renders one), guardian-client.ts (which receives
 * one off the wire) and failure-posture.ts (which produces one in place of an
 * absent one) can all speak the same message -- and without a `deny` that
 * means something subtly different on each side of a seam.
 *
 * One stem, with adjectives for stage. There is one public noun for "the ACS
 * decision for this step", and every refinement of it still contains that
 * noun:
 *
 *   AcsDecision                 the message as it arrives, and the type every
 *                               path hands the host
 *   ValidatedAcsDecision        after `validateDecision`'s validation and
 *                               §6.3's apply (below)
 *   FailureResolvedAcsDecision  after `applyFailurePosture` answered an
 *                               absent one (failure-posture.ts)
 *
 * A single stem keeps a reader following one decision through the stack from
 * learning a new name at every hop for a role that never actually changes; a
 * suffix here describes processing stage or origin, never a different
 * message.
 *
 * This is not an import of the Guardian's own `AcsDecision`. The Guardian
 * declares the same message (packages/guardian/src/map-verdict.ts) as a strict
 * union of the five ACS dispositions, because it is the side that *builds*
 * one. This side reads one off HTTP, so it is deliberately loose: only
 * `decision` is required, and everything else a caller touches is named by the
 * hookmap's `from:` declarations rather than assumed to exist under a fixed
 * key. The two are structurally compatible in the direction that matters (the
 * Guardian's is assignable to this one), and they share the NAME rather than
 * an import, because this package must not depend on the Guardian's type
 * graph. Same deliberate structural duplication as the Inspector's
 * AuditEntry and EnvelopeLogEntry, for the same reason.
 *
 * One noun for "the ACS decision for this step", across both sides of the
 * seam. Any later refinement should stay an adjective containing this stem
 * (`ValidatedAcsDecision`), never a parallel noun.
 *
 * ACS's decision vocabulary, nothing else.
 */

/**
 * The ACS decision for one step, as this adapter reads it. Loose on purpose --
 * see the module header: only `decision` is required.
 */
export type AcsDecision = { decision: string } & Record<string, unknown>;

/**
 * An `AcsDecision` after `validateDecision` has had its last word on it:
 * §6.3's rewrite applied under the post-validation field name the hookmap
 * renders from, and any expired ask/defer outcome already substituted.
 *
 * Two fields, one per gate, because the two gates rewrite different things. A
 * gate that decides whether a step runs carries the applied arguments the host
 * is to run instead (`applied_input`); a gate that sees what a step produced
 * carries the replacing output the host is to deliver instead
 * (`applied_output`). A decision never carries both: which one is present is a
 * property of the hook that asked, and each gate's hookmap entry names the one
 * it renders from.
 *
 * Neither is an ACS wire field. They are what a decision looks like after
 * this side has honoured it -- the post-validation names the hookmap's
 * `from:` declarations point at, so a host renders an applied rewrite
 * rather than the `modifications` object that described it. Rendering the
 * `modifications` object itself would report a rewrite that never actually
 * took effect.
 */
export type ValidatedAcsDecision = AcsDecision & {
  applied_input?: Record<string, unknown>;
  applied_output?: Record<string, unknown>;
};

/**
 * Denies with `reason_codes` set to exactly `[code]` -- every fail-closed
 * substitution across these modules reports one specific reason, never a
 * general one, so an audit reader can tell the mandatory cases apart.
 *
 * Here rather than in one of the two modules that call it, because both do:
 * decision-expiry.ts denies an ask or defer whose window it cannot read, and
 * validate-decision.ts denies a rewrite that could not be honoured. A copy per
 * module is a `deny` free to drift on what it carries, in the one direction
 * that matters -- a deny whose `reason_codes` a machine reads.
 */
export function deny(reasoning: string, code: string): ValidatedAcsDecision {
  return { decision: "deny", reasoning, reason_codes: [code] };
}
