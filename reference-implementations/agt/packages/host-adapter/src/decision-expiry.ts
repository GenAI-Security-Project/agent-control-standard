/**
 * The two expiry substitutions §6 makes mandatory for the *host* (the
 * Observed Agent). validate-decision.ts sequences them rather than owning
 * them:
 *
 * 1. An expired `ask` falls back to `ask_details.timeout_disposition`,
 *    defaulting to `deny`.
 * 2. An expired `defer` falls back to `defer_details.timeout_decision`,
 *    defaulting to `deny`.
 *
 * Both timeout defaults land on `deny`, deliberately the opposite of
 * `on_decision_failure`'s default of `proceed` (§6.4, and see
 * failure-posture.ts): a Guardian that flagged a concern (ASK or DEFER) and
 * then failed to resolve it is a different failure than one that never
 * answered at all, and the two must not collapse to the same posture.
 *
 * Both resolvers compare `elapsedMs` against `>` (strictly greater than) the
 * timeout, not `>=`: a decision that resolves in exactly the negotiated
 * window has not expired, and the boundary belongs to the decision that
 * arrived, not to expiry. Both boundaries are pinned by their own test.
 *
 * The two timeouts are NOT in the same unit, and nothing about their names
 * makes that survive a careless edit: `ask_details.timeout_seconds` is
 * seconds and is converted here, `defer_details.resolution_timeout_ms` is
 * already milliseconds and must not be. Dropping the ASK conversion leaves
 * every obvious test still passing (1s against 2000ms reads "expired" either
 * way), which is why validate-decision.test.ts carries a case chosen to read
 * the opposite way without it -- 500ms against a 1-second timeout.
 *
 * Neither resolver may turn an arriving decision into anything but its own
 * substitution: an `ask` or `defer` inside its window is returned as it
 * arrived, by identity, not rebuilt.
 *
 * This module knows ACS's ask_details and defer_details shapes, nothing
 * else -- no policy-runtime vocabulary.
 */

import { deny, type AcsDecision, type ValidatedAcsDecision } from "./decision-message.ts";

/**
 * Substitutes an expired `ask` with its `ask_details.timeout_disposition`,
 * defaulting to `deny`; returns the decision untouched while it is still
 * inside its window.
 *
 * An `ask_details` that carries no numeric `timeout_seconds` is a deny of
 * its own rather than a pass-through: the host cannot tell when the window
 * closes, so it cannot tell whether it has closed, and an ASK whose expiry
 * is unknowable must not be handed to the host as a live question.
 */
export function resolveAsk(decision: AcsDecision, elapsedMs: number): ValidatedAcsDecision {
  const askDetails = decision.ask_details;
  if (
    typeof askDetails !== "object" ||
    askDetails === null ||
    typeof (askDetails as Record<string, unknown>).timeout_seconds !== "number"
  ) {
    return deny("ask decision is missing valid ask_details (approver, question, timeout_seconds)", "ask_details_invalid");
  }
  const details = askDetails as Record<string, unknown>;
  const timeoutMs = (details.timeout_seconds as number) * 1000;
  if (elapsedMs > timeoutMs) {
    const disposition = details.timeout_disposition === "allow" ? "allow" : "deny";
    return {
      decision: disposition,
      reasoning: `ask expired after ${elapsedMs}ms (timeout ${timeoutMs}ms); falling back to timeout_disposition=${disposition}`,
      reason_codes: ["ask_expired"],
    };
  }
  return decision;
}

/**
 * Substitutes an expired `defer` with its `defer_details.timeout_decision`,
 * defaulting to `deny`; returns the decision untouched while it is still
 * inside its window.
 *
 * Both routes out of an expired defer are a `deny`, including the one
 * `timeout_decision: "ask"` names -- see the branch itself for why an ask this
 * host cannot make well-formed is denied rather than emitted.
 *
 * `resolution_timeout_ms` is already milliseconds -- the missing `* 1000`
 * below is deliberate and is the difference between this resolver and
 * `resolveAsk`, not an omission.
 *
 * A `defer_details` that carries no numeric `resolution_timeout_ms` denies
 * for the same reason an unreadable `ask_details` does.
 */
export function resolveDefer(decision: AcsDecision, elapsedMs: number): ValidatedAcsDecision {
  const deferDetails = decision.defer_details;
  if (
    typeof deferDetails !== "object" ||
    deferDetails === null ||
    typeof (deferDetails as Record<string, unknown>).resolution_timeout_ms !== "number"
  ) {
    return deny(
      "defer decision is missing valid defer_details (reason, resolution_method, resolution_timeout_ms)",
      "defer_details_invalid",
    );
  }
  const details = deferDetails as Record<string, unknown>;
  const timeoutMs = details.resolution_timeout_ms as number;
  if (elapsedMs > timeoutMs) {
    if (details.timeout_decision === "ask") {
      // defer-details.json permits `timeout_decision: "ask"`, and this host
      // cannot carry it out. Denying closed rather than substituting one is the
      // only honest answer available here.
      //
      // What the obvious substitution would produce: an `ask` requires
      // `ask_details` -- response-envelope.json makes it conditionally required
      // on the decision, and ask-details.json requires `approver`, `question`
      // and `timeout_seconds` inside it. `defer_details` carries none of the
      // three. So substituting here would emit `{decision: "ask"}` with no
      // details at all: a message ACS's own schema rejects, and one this
      // module's PEER would reject too -- `resolveAsk` denies exactly that
      // shape as `ask_details_invalid`. Nothing re-enters `validateDecision`
      // after a substitution, so a malformed ask would go straight to the
      // host's renderer, never asked again.
      //
      // Inventing the missing fields would be worse than denying: `approver`
      // is an identity -- who is permitted to answer this question -- and
      // there is no honest value for it here. A host that fabricates one has
      // forged the load-bearing field of an approval request, in a
      // governance tool, to avoid saying "I cannot ask this". That the
      // resulting ASK would then be approved by whoever the fabrication
      // happened to name is the whole objection.
      //
      // Its own reason code, not `defer_expired`: an operator reading this
      // needs to know the deployment declared an escalation their Guardian did
      // not supply the means to make, which is a configuration fault to fix
      // and not merely a window that closed.
      return deny(
        `defer expired after ${elapsedMs}ms (timeout ${timeoutMs}ms) and declares ` +
          `timeout_decision=ask, but defer_details carries no approver, question or timeout_seconds for the ` +
          `ask_details an ACS ask requires -- so this host has no well-formed question to raise and denies instead`,
        "defer_ask_unaskable",
      );
    }
    return {
      decision: "deny",
      reasoning: `defer expired after ${elapsedMs}ms (timeout ${timeoutMs}ms); falling back to timeout_decision=deny`,
      reason_codes: ["defer_expired"],
    };
  }
  return decision;
}
