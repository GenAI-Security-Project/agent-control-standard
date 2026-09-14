/**
 * The message this Guardian sends back: an ACS final result, as
 * response-envelope.json's `AcsResult` defines it.
 *
 * Structured as the decision PLUS the correlation fields rather than as a flat
 * list of its own, because that is what it is: one ACS decision addressed to
 * one request. Spreading `AcsDecision` in keeps a single source for the
 * decision's own shape (map-verdict.ts), so a field added there cannot fail to
 * be sendable from here. Typing it at all is what makes the outbound half of
 * this seam as checked as the inbound one, where `validateEnvelope` narrows
 * each arrival: without it, nothing confirms the envelope fields ACS requires
 * beside the decision are present and belong to this request.
 *
 * `request_id` is the ACS correlation id from `params.request_id`, NOT the
 * JSON-RPC `id`. The two are equal for every envelope `buildEnvelope` sends,
 * and they are still different fields: the transport correlates by one and ACS
 * correlates by the other, and response-envelope.json requires this one on the
 * result object itself.
 */
import type { AcsDecision } from "./map-verdict.ts";

export type AcsFinalResult = {
  /** response-envelope.json's discriminator. v0.1 emits only "final". */
  type: "final";
  acs_version: string;
  request_id: string;
} & AcsDecision;

/**
 * Builds the final result for one request from the decision reached for it.
 *
 * Here rather than inline at the call site so the three correlation fields are
 * read off the envelope's own params in exactly one place: an answer carrying
 * some other request's `request_id` is a decision the host will either fail to
 * correlate or, worse, correlate to the wrong step.
 */
export function finalResult(
  params: { acs_version: string; request_id: string },
  decision: AcsDecision,
): AcsFinalResult {
  return {
    type: "final",
    acs_version: params.acs_version,
    request_id: params.request_id,
    ...decision,
  };
}
