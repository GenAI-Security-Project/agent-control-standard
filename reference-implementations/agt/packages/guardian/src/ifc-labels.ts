/**
 * This module performs the round trip AGT's spec asks a host to perform and
 * declines to standardize itself: persisting the labels a verdict returns,
 * and supplying them back on the next step.
 *
 * AGT's `verdict.schema.json` says the core "stores and propagates nothing"
 * and requires the host to persist returned labels and re-supply them. This
 * is exactly that requirement -- ACS provenance carrying the IFC labels AGT
 * delegates to the host, made concrete. It is not a criticism of AGT; it
 * fills a role AGT explicitly delegates.
 *
 * Named for IFC, not for a gate: this Guardian has its own result gate
 * (`post_tool_call`), so "result labels" would read as that gate's own
 * labels rather than as AGT's IFC tags.
 *
 * Where the first label comes from is not this module's concern, and that is
 * a property of ACS v0.1.0 itself rather than of this module. AGT propagates
 * labels it is given and originates none -- `policy/lib/agt_ifc.rego` is the
 * IFC module this deployment's bundle actually evaluates
 * (`policy/lib/agt_default.rego` imports `data.agt.ifc`, never the upstream
 * `agent_control_specification.lib.ifc` that sibling `policy/lib/ifc.rego`
 * packages, which the AGT host SDKs do not populate), and its own
 * `propagated_labels(labels)` returns `[]` for an empty input rather than
 * inventing one. And `specification/v0.1.0/provenance.json` defines
 * `provenance_id`, `origin`, `source_id` and `derived_from`, and no member a
 * sensitivity label could be read from. So a session's first labels are
 * deployment-supplied, not read off the wire or derived by this code.
 */
import type { IfcLabels, SessionContextStore } from "./session-context-store.ts";

/**
 * Persist what a verdict returned. `undefined` means the verdict carried no
 * `result_labels` member at all -- a policy that never ran the IFC gate --
 * and leaves what the session already had. An explicitly empty array is a
 * different answer: the gate ran and propagated nothing, so the session's
 * labels are cleared. Conflating the two would make a session that once
 * touched secret data look secret forever.
 *
 * This distinction is this function's whole job, and it is why persisting
 * labels is more than a forwarding call: whether a verdict carried
 * `undefined` or `[]` is a fact about the verdict, so reading it belongs
 * here, next to the verdict. What happens once it is read is the store's
 * business: this function hands the store a labels array through
 * `replaceIfcLabels`, never the whole provenance record to edit.
 */
export function persistIfcLabels(
  store: SessionContextStore,
  sessionId: string,
  labels: IfcLabels | undefined,
): void {
  if (labels === undefined) return;
  store.replaceIfcLabels(sessionId, labels);
}

/**
 * Read them back for the next snapshot. `IfcLabels` is `readonly`, so the
 * snapshot assembler that receives this cannot write through it into the
 * stored provenance record; the store copies on the way out as well, which
 * is what holds even if a caller casts the readonly away.
 */
export function supplySourceLabels(store: SessionContextStore, sessionId: string): IfcLabels {
  return store.sourceLabels(sessionId);
}
