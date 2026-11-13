/**
 * validateDecision is the host's (the Observed Agent's) last word on an
 * arriving decision, sequencing three mandatory fail-closed cases.
 *
 * The work itself belongs to collaborators this module is told about. What
 * is left here is knowing which one an arriving decision is for, and being
 * the only place that says what their answers mean as a decision:
 *
 * 1. `modify` -- decision-modify.ts applies §6.3's rewrite if it can be
 *    honoured as written, and denies if it cannot. Never a best-effort
 *    partial apply and never a reported-but-unapplied one.
 * 2. `ask` -- decision-expiry.ts substitutes an expired one with its
 *    `ask_details.timeout_disposition`.
 * 3. `defer` -- decision-expiry.ts substitutes an expired one with its
 *    `defer_details.timeout_decision`.
 *
 * The three are peers, all reading as three of one thing. Each is
 * `resolve<Disposition>(decision, ...) -> ValidatedAcsDecision`, each never
 * throws, and each lives in a module beside the knowledge it needs -- so
 * "all three fail closed" is one property checked one way, rather than
 * three seams with three shapes.
 *
 * The module's own name says only "validate", which says nothing about
 * *applying* a rewrite to a tool call's arguments or *substituting* a
 * decision for an expired one -- both are things a reader has to know its
 * collaborators do. What this module contains is a switch and nothing else.
 *
 * No resolver names a decision it was not given: `resolveModify` is the only
 * translation from "this rewrite cannot be honoured" to "deny", and
 * decision-expiry.ts's two resolvers are the only substitutions of an expired
 * outcome. Everything else that arrives leaves untouched.
 *
 * No branch here may alter an arriving `deny` -- switching on `decision`
 * below, `deny` has no `case` of its own, so it falls through to the
 * untouched pass-through
 * along with every decision this module doesn't specifically validate.
 * `allow` is the same pass-through, including a warn-derived allow's
 * non-empty `policy_references` -- the only thing distinguishing it from a
 * plain allow, so nothing here may drop or rebuild it.
 *
 * That constraint is also why this stays a `switch` rather than a table of
 * handlers keyed by decision: the `default` arm *is* the constraint, and a
 * reader checking that nothing can touch an arriving `deny` should be able
 * to see every arm that touches anything without leaving the function.
 *
 * This module knows ACS's decision vocabulary, nothing else -- no
 * policy-runtime vocabulary. What each collaborator knows is stated in its
 * own header.
 */

import type { AcsDecision, ValidatedAcsDecision } from "./decision-message.ts";
import { resolveAsk, resolveDefer } from "./decision-expiry.ts";
import { resolveModify } from "./decision-modify.ts";
import type { HostOutputLocation } from "./result-output.ts";

export type { ValidatedAcsDecision };

export type ValidateDecisionContext = {
  /** Wall-clock time elapsed since this decision was requested, in
   * milliseconds. Compared by decision-expiry.ts against
   * `ask_details.timeout_seconds` (seconds, converted there) and
   * `defer_details.resolution_timeout_ms` (already milliseconds) -- the two
   * fields use different units, and getting that conversion wrong would make
   * an expiry test pass for the wrong reason. */
  elapsedMs: number;
  /**
   * The ACS-side document a `modify` decision's `modifications` pointers
   * address, and are applied to. Unused by every other decision.
   *
   * Named for the gate that decides whether a step RUNS, where the document IS
   * the tool-call arguments that went out on the wire -- `buildEnvelope`'s
   * `modificationDocumentOf` answers with exactly those there. At a gate that sees
   * what a step PRODUCED the pointers address the result payload instead
   * (`/outputs/0/value` names nothing in an arguments bag; there isn't one at
   * that step), so that is the document, and `outputLocation` below is what
   * carries the applied result the rest of the way.
   */
  modificationDocument: Record<string, unknown>;
  /**
   * Present only at a gate whose ACS payload is a PROJECTION of an output object
   * the host already holds -- i.e. a result gate. It says where to project the
   * applied document back to, and its presence is what makes the applied rewrite
   * land in `applied_output` rather than `applied_input`.
   *
   * Two fields rather than one because the two gates rewrite different things,
   * and one gate's applied result is not usable at the other: an arguments bag
   * is a tool input, a projected output object is a tool result. See
   * `ValidatedAcsDecision`.
   */
  outputLocation?: HostOutputLocation;
};

/**
 * Sequences the three mandatory fail-closed cases: each recognized decision
 * goes to the collaborator that owns it, and the result is what the host
 * renders.
 *
 * `deny` and every decision besides `modify`/`ask`/`defer` fall through to
 * the pass-through branch untouched.
 */
export function validateDecision(decision: AcsDecision, context: ValidateDecisionContext): ValidatedAcsDecision {
  const { elapsedMs, modificationDocument, outputLocation } = context;

  switch (decision.decision) {
    case "modify":
      return resolveModify(decision, modificationDocument, outputLocation);

    case "ask":
      return resolveAsk(decision, elapsedMs);

    case "defer":
      return resolveDefer(decision, elapsedMs);

    default:
      return decision;
  }
}
