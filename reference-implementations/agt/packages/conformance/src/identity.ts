/**
 * Recomputes AGT's action identity instead of taking its word for it, and
 * reports what that identity actually binds to.
 *
 * MEASURED, not read from AGT's docs: the identity is the SHA-256 of the
 * key-sorted, whitespace-free JSON of the policy input, prefixed "sha256:".
 * `enforced_identity` is the same hash after replacing `policy_target.value`
 * alone with `verdict.transform.value` -- the snapshot's own copy of that leaf
 * is not updated. Both reproduce exactly against the pinned SDK.
 *
 * MEASURED AT BOTH TRANSFORM-CAPABLE POINTS, not assumed to agree because one
 * was checked. mapping.yaml gives a `modifications` rule to `pre_tool_call`
 * and `post_tool_call` alike, and `policy/lib/agt_default.rego`'s
 * `redact_verdict` reads `input.policy_target.value` without consulting
 * `input.intervention_point` -- so the pinned bundle's stock redact rule can
 * fire at either gate, and the binding question is a real question at both.
 * Driven independently (`test/identity.test.ts`), the request gate resolves
 * `policy_target` too, identically to the result gate -- not forced to agree,
 * found to.
 *
 * The second half is the finding, and it is why this cell resolves
 * guardian-only rather than expressed. AGT's enforced identity binds to the
 * policy target it rewrote, not to the document the host will execute; making
 * those agree is the adapter's job, and ACS v0.1.0 carries no field to check
 * it with. `identity` occurs four times, across two files, in the whole
 * v0.1.0 spec directory -- three inside `session-start.json` (the
 * `user_identity` field name and two prose uses in its own description) and
 * one more in prose inside `skill-register.json` -- and none of the four is
 * this. The nearest miss is
 * `context-entry.json`'s `request_hash` (context-entry.json:21-24): SHA-256
 * of the JCS-canonicalised request envelope params. It does not name what
 * this check measures either -- it is not wire-transmitted (context-
 * entry.json:5, "not transmitted in full on the wire") and it commits to the
 * request as received, not to the policy target after AGT's own
 * modifications.
 *
 * A RECOMPUTATION, which is why this takes the policy input and the transform
 * and nothing else. AGT also returns `transformedPolicyTarget`, its own
 * already-transformed value; `AgtEvidence` deliberately does not carry it,
 * because a check handed AGT's answer has a way to agree with AGT without
 * computing anything.
 */
import { createHash } from "node:crypto";
import type { AgtEvidence, EvidenceBridge, InterventionSnapshot } from "agt-bridge";
import { AGT_POINTS, type CellStatus, type CoverageCell } from "./cells.ts";

/** `boundTo === "policy_target"`: the measured, real behaviour against the
 * pinned SDK at both transform-capable points (see the file comment). */
const BOUND_TO_POLICY_TARGET =
  "ACS v0.1.0 carries no action-identity field on any of its 44 schemas, so a wire consumer cannot bind an " +
  "approval to the action that executed; AGT's enforced identity binds to the policy target it rewrote, not " +
  "to the document the host applies modifications to";

/** `boundTo === "snapshot"`: never produced by the pinned SDK (both measured
 * gates bind `policy_target`), but a real outcome `resolveBinding` computes
 * and would return if AGT's binding ever changed -- so its cell states what
 * would actually have been seen, not the policy-target finding by default. */
const BOUND_TO_SNAPSHOT =
  "AGT's enforced identity in this run binds to the snapshot leaf policy_target.path addresses -- the document " +
  "the host will actually execute after the rewrite -- rather than to policy_target.value alone; ACS v0.1.0 " +
  "still carries no action-identity field on any of its 44 schemas for a wire consumer to check it against";

/** `boundTo === "unattributable"`: a transform WAS reported, both candidates
 * were constructed and hashed, and neither matched -- a comparison that ran
 * and failed. Kept apart from `NO_REWRITE` below on purpose: no candidate is
 * ever constructed when there is no transform to substitute, so claiming
 * "does not match" a comparison that never ran would be an overclaim this
 * reason string must not make. */
const BOUND_TO_UNATTRIBUTABLE =
  "AGT's enforced identity does not match a hash of the policy input with policy_target.value replaced by the " +
  "reported transform, nor one with the snapshot leaf policy_target.path addresses replaced the same way -- " +
  "this check cannot attribute it to either document";

/** `boundTo === "no_rewrite"`: AGT reported no transform at all, so there is
 * no candidate to construct and no comparison to run -- distinct from
 * `unattributable`, where a comparison ran and failed. */
const NO_REWRITE =
  "AGT reported no transform for this policy input: there is no rewritten document to attribute its enforced " +
  "identity to, and this check made no policy_target/snapshot comparison -- input and enforced identity are " +
  "equal by construction, not because either candidate was tested and matched";

/**
 * One evaluation's two answers, kept apart because they are two
 * measurements: `input` is whether AGT's input-identity hash reproduces from
 * the policy input it reported, `enforced` is which document its enforced
 * identity turned out to cover. Neither implies the other, and a single flat
 * record wearing one name made it read as though it did.
 */
export type IdentityFinding = {
  /** The AGT intervention point this finding was measured at. Validated
   * against `AGT_POINTS` in `measureIdentity` (the only place a point
   * arrives from a caller), so a finding can never carry one AGT does not
   * have. */
  point: string;
  input: InputIdentityCheck;
  enforced: EnforcedBindingCheck;
};

/** `checkInputIdentity`'s answer: did AGT's own input identity reproduce? */
export type InputIdentityCheck = { recomputed: boolean; identity: string };

/** `checkEnforcedBinding`'s answer: which document does the enforced
 * identity cover?
 *
 * `policy_target` / `snapshot`: a transform was reported and one of the two
 * candidates this check constructs matched. `unattributable`: a transform
 * was reported and neither candidate matched. `no_rewrite`: no transform was
 * reported, so no candidate was ever constructed. Four distinct situations,
 * not three -- `unattributable` and `no_rewrite` look similar (neither names
 * a document) but differ in whether a comparison was attempted at all, and
 * `coverageCellsFromIdentity` gives each its own reason. */
export type EnforcedBindingCheck = {
  identity: string;
  boundTo: "policy_target" | "snapshot" | "unattributable" | "no_rewrite";
};

/** Canonical JSON, then SHA-256. Key-sorted at every depth and free of
 * whitespace -- measured against the pinned SDK, not assumed. */
export function canonicalIdentity(policyInput: unknown): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(sortKeys(policyInput))).digest("hex")}`;
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as object).sort()) {
      out[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

/**
 * One evaluation, both questions. The bridge is asked once and the two
 * checks below read the same evidence, so they cannot disagree about which
 * run they describe -- which is why this is not two functions each fetching
 * their own.
 *
 * The point is validated here, the only place one arrives from a caller, and
 * is recorded on the finding rather than threaded separately to the
 * projection: a point passed alongside the finding it describes can disagree
 * with it at the call site, and recording it makes that unrepresentable.
 */
export async function measureIdentity(
  bridge: EvidenceBridge,
  point: string,
  snapshot: InterventionSnapshot,
): Promise<IdentityFinding> {
  if (!AGT_POINTS.includes(point)) {
    throw new Error(`cannot measure an intervention point AGT does not have: ${JSON.stringify(point)} is not one of ${AGT_POINTS.join(", ")}`);
  }

  const evidence = await bridge.evaluateWithEvidence(point, snapshot);
  return { point, input: checkInputIdentity(evidence), enforced: checkEnforcedBinding(evidence) };
}

/**
 * Does AGT's input identity reproduce from the policy input it reported?
 * Says nothing about where the enforced identity landed -- that is
 * `checkEnforcedBinding`'s separate answer.
 */
export function checkInputIdentity(evidence: AgtEvidence): InputIdentityCheck {
  return {
    recomputed: canonicalIdentity(evidence.policyInput) === evidence.inputIdentity,
    identity: evidence.inputIdentity,
  };
}

type PolicyInputShape = { policy_target: { path: string; value: unknown }; snapshot: unknown };

/** Checks the two fields `resolveBinding` needs before casting, so a policy
 * input that ever lacked them fails with a message naming this check and
 * what it expected, instead of a bare `TypeError` from the mutation below.
 * Unreached against the pinned SDK's five-member policy input document --
 * legibility for whoever hits it first, not a case this check has observed. */
function policyTargetShape(policyInput: unknown): PolicyInputShape {
  const candidate = policyInput as Partial<PolicyInputShape> | null;
  const target = candidate?.policy_target as Partial<PolicyInputShape["policy_target"]> | undefined;
  if (candidate === null || typeof candidate !== "object" || typeof target?.path !== "string" || !("snapshot" in candidate)) {
    throw new Error(
      `cannot resolve which document AGT's enforced identity binds to: the policy input it reported has ` +
        `no policy_target.path / snapshot pair to substitute into (got ${JSON.stringify(policyInput)})`,
    );
  }
  return candidate as PolicyInputShape;
}

/**
 * Sets the leaf `policy_target.path` addresses inside an already-cloned
 * snapshot. AGT's own JSONPath-lite dialect for this field, measured against
 * the pinned bundle's two live `modifications` rows (mapping.yaml): dotted
 * field access plus an optional trailing `[N]` array index per segment, e.g.
 * "$.tool_call.args.command" and "$.tool_result.outputs[0].value".
 *
 * NOT host-adapter's hookmap-path notation. That one is a different dialect,
 * deliberately scoped to hookmaps and nothing about ACS, hosts, or policy
 * (hookmap-path.ts's own comment), and it does not support the array index
 * AGT's result-gate path needs. Reusing it here
 * would couple this check to a notation owned by a different layer for a
 * different reason; this is AGT's dialect, walked by this check alone.
 */
function setAtPolicyTargetPath(snapshot: unknown, path: string, value: unknown): void {
  const segments: (string | number)[] = [];
  for (const part of path.replace(/^\$\.?/, "").split(".")) {
    const match = /^([^[\]]+)((?:\[\d+\])*)$/.exec(part);
    const name = match?.[1];
    const indices = match?.[2];
    if (name === undefined || indices === undefined) {
      throw new Error(`cannot walk policy_target.path segment ${JSON.stringify(part)} of ${JSON.stringify(path)}`);
    }
    segments.push(name);
    for (const index of indices.match(/\d+/g) ?? []) segments.push(Number(index));
  }
  const last = segments.at(-1);
  if (last === undefined) {
    throw new Error(`cannot walk policy_target.path ${JSON.stringify(path)}: it has no segments`);
  }

  let current: unknown = snapshot;
  for (let i = 0; i < segments.length - 1; i++) {
    const segment = segments[i];
    if (segment === undefined || current === null || typeof current !== "object") {
      throw new Error(`cannot walk policy_target.path ${JSON.stringify(path)}: segment ${i} is not an object in the snapshot`);
    }
    current = (current as Record<string | number, unknown>)[segment];
  }
  if (current === null || typeof current !== "object") {
    throw new Error(`cannot walk policy_target.path ${JSON.stringify(path)}: its parent is not an object in the snapshot`);
  }
  (current as Record<string | number, unknown>)[last] = value;
}

/**
 * Which document AGT's enforced identity actually covers, decided by
 * recomputing each candidate rather than by reading AGT's description of it.
 *
 * Four outcomes, not three collapsed into one: `no_rewrite` short-circuits
 * before either candidate is built (there is nothing to substitute), while
 * `policy_target` / `snapshot` / `unattributable` all construct and hash
 * both candidates and differ only in which, if either, matched. The
 * short-circuit and the ran-and-failed comparison are different data -- one
 * never compared anything, the other compared and found no match -- so they
 * get different names, and `coverageCellsFromIdentity` gives each a reason
 * true of only it.
 *
 * Exported beside `checkInputIdentity`: same evidence, a different question,
 * and each answerable and testable without the other.
 */
export function checkEnforcedBinding(evidence: AgtEvidence): EnforcedBindingCheck {
  return { identity: evidence.enforcedIdentity, boundTo: resolveBoundTo(evidence) };
}

function resolveBoundTo(evidence: {
  policyInput: unknown;
  inputIdentity: string;
  enforcedIdentity: string;
  verdict: { transform?: { value: unknown } };
}): EnforcedBindingCheck["boundTo"] {
  const transformed = evidence.verdict.transform?.value;
  if (transformed === undefined) {
    // No rewrite: MEASURED here, not merely asserted in prose -- an allow at
    // post_tool_call reproduces input === enforced identity (both
    // sha256:bcdd184c..., against the pinned bundle, for a tool_result value
    // no rule rewrites -- test/identity.test.ts's own no-rewrite case). A
    // mismatch would mean AGT computed a different enforced identity without
    // reporting a transform, which this check surfaces loudly rather than
    // folding silently into "no_rewrite". No candidate is constructed below
    // this point in this branch -- there is nothing to substitute a missing
    // transform value into.
    if (evidence.enforcedIdentity !== evidence.inputIdentity) {
      throw new Error(
        `AGT reported no transform, but inputIdentity (${evidence.inputIdentity}) and enforcedIdentity ` +
          `(${evidence.enforcedIdentity}) differ -- the no-rewrite invariant this check measured does not hold`,
      );
    }
    return "no_rewrite";
  }

  const input = policyTargetShape(evidence.policyInput);

  const policyTargetCandidate = structuredClone(input);
  policyTargetCandidate.policy_target.value = transformed;
  if (canonicalIdentity(policyTargetCandidate) === evidence.enforcedIdentity) {
    return "policy_target";
  }

  const snapshotCandidate = structuredClone(input);
  setAtPolicyTargetPath(snapshotCandidate.snapshot, input.policy_target.path, transformed);
  if (canonicalIdentity(snapshotCandidate) === evidence.enforcedIdentity) {
    return "snapshot";
  }

  return "unattributable";
}

function boundToCell(boundTo: EnforcedBindingCheck["boundTo"]): { status: CellStatus; reason: string } {
  switch (boundTo) {
    case "policy_target":
      return { status: "guardian_only", reason: BOUND_TO_POLICY_TARGET };
    case "snapshot":
      return { status: "guardian_only", reason: BOUND_TO_SNAPSHOT };
    case "unattributable":
      return { status: "unexpressed", reason: BOUND_TO_UNATTRIBUTABLE };
    case "no_rewrite":
      return { status: "unexpressed", reason: NO_REWRITE };
  }
}

/**
 * The projection stage -- named for being one, rather than for a measurement
 * it does not perform. It turns one finding into the `transform` column's
 * cell at the point the finding was actually measured at (`finding.point`,
 * validated against `AGT_POINTS` in `measureIdentity` -- the only place a
 * point arrives from a caller). Not a second parameter here: a point
 * threaded in separately from the finding it is supposed to describe can
 * disagree with it at the call site just as easily as a hard-coded constant
 * can disagree with reality inside this function:
 * `coverageCellsFromIdentity(await measureIdentity(bridge, "pre_tool_call",
 * s), "post_tool_call")` would type-check and mislabel the cell. Recording
 * the point on the finding itself makes that divergence unrepresentable.
 *
 * The two measurements are read in order, not merged: `input.recomputed`
 * false resolves the cell on its own, because a binding computed from an
 * unreproducible input identity is not evidence of anything. Only when it
 * held is `enforced.boundTo` asked, and its four outcomes get four
 * different, independently true reasons rather than one claim repeated
 * across all of them -- `unattributable` and `no_rewrite` look alike
 * (neither names a document) but are not the same claim: one says a
 * comparison ran and found no match, the other says no comparison was
 * possible, and conflating them would misstate both.
 */
export function coverageCellsFromIdentity(finding: IdentityFinding): CoverageCell[] {
  if (!finding.input.recomputed) {
    return [
      {
        point: finding.point,
        verdict: "transform",
        status: "unexpressed",
        reason: "AGT's input identity could not be reproduced from the policy input it reported",
        measuredBy: ["action identity"],
      },
    ];
  }
  return [
    {
      point: finding.point,
      verdict: "transform",
      ...boundToCell(finding.enforced.boundTo),
      measuredBy: ["action identity"],
    },
  ];
}
