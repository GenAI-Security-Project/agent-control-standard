/**
 * How THIS deployment builds a policy bridge -- the manifest it evaluates and
 * the annotator that manifest declares, in one place.
 *
 * It exists because the recipe is not `createBridge(manifestPath)`. A bridge
 * for `policy/manifest.yaml` must carry an annotator, and a caller who forgets
 * does not get a bridge with a missing feature: it gets one that denies EVERY
 * call in the deployment -- benign ones included -- with
 * `runtime_error:annotation_failed`, a total deny wearing a reason that reads
 * like a policy decision. Measured. Six callers outside this package build
 * bridges against that manifest, and the two in the conformance harness are
 * the sharpest case: a harness that builds the recipe itself is measuring a
 * replica, and the day this deployment declares a second annotator or takes
 * another `createBridge` option, the replica silently stops being the thing it
 * claims to measure.
 *
 * So the recipe is a function, not a convention. `startGuardian` calls it and
 * so does everything else; `packages/guardian/package.json` publishes it at
 * the `guardian/deployment` subpath. Deliberately NOT in this package's barrel
 * -- that surface is the governance verbs, and this is deployment wiring; see
 * `./index.ts`'s own header, which states the same answer for the envelope-log
 * sink.
 *
 * Separate from `./server.ts` for a second reason: a caller that only needs a
 * bridge should not have to load the HTTP server, its schema registry and its
 * envelope log to get one.
 */
import { createBridge, type Annotator, type EvidenceBridge, type PolicyBridge } from "agt-bridge";
import { annotateEgressDestination } from "./annotate-egress.ts";

/**
 * The annotators this Guardian can answer for, routed by the name the manifest
 * declared.
 *
 * A name this has nothing for THROWS, and that is deliberate even though AGT
 * turns it into a deny on every call in the deployment. It is wrong on every
 * call: a manifest declaring an annotator whose value never arrives is
 * evaluating policy against an annotation that is permanently absent. Failing
 * loudly and immediately is better than running silently unannotated, and the
 * failure is found on the first request rather than in an incident review.
 */
export const dispatchGuardianAnnotator: Annotator = (name, config, preliminary) => {
  if (name === "egress") {
    return annotateEgressDestination(name, config, preliminary);
  }
  throw new Error(
    `this Guardian has no annotator named ${JSON.stringify(name)} -- the manifest declares one it cannot ` +
      `supply a value for`,
  );
};

/**
 * A bridge built the way this deployment builds one.
 *
 * `annotator` chooses WHICH annotator, never WHETHER: omitted means the
 * built-in `dispatchGuardianAnnotator`, and there is no way to ask for none.
 * That is the whole point -- see this module's header for what a bridge with
 * no dispatcher does to a manifest that declares one.
 *
 * Answers both of `createBridge`'s roles, unchanged. The Guardian takes the
 * `PolicyBridge` half and the conformance harness takes the `EvidenceBridge`
 * half; narrowing here would make this function unusable for one of them.
 */
export function createDeploymentBridge(manifestPath: string, annotator?: Annotator): PolicyBridge & EvidenceBridge {
  return createBridge(manifestPath, { annotator: annotator ?? dispatchGuardianAnnotator });
}
