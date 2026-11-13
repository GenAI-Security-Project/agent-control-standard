import { AgentControl, type JsonValue } from "agent-control-specification";
import { publishOpaPath } from "./opa-path.ts";

export type AgtVerdict = {
  decision: "allow" | "deny" | "warn" | "escalate" | "transform";
  reason?: string;
  message?: string;
  transform?: { path: string; value: unknown };
  result_labels?: string[];
};

/**
 * What any snapshot is, structurally: the policy input document, as JSON.
 *
 * A constraint, not a message. Each intervention point has its own snapshot
 * shape (AGT-SNAPSHOT-1.0.md §2.5), which is the assembling caller's knowledge
 * rather than this bridge's, so `PolicyBridge` is parameterised by the
 * snapshot its holder actually sends and this alias is only the bound on that
 * parameter. Used directly as a parameter type it would widen a named snapshot
 * back to "any object" at the one seam it was built to cross.
 */
export type InterventionSnapshot = Record<string, unknown>;

/**
 * What AGT reports about its own evaluation, as distinct from what it decided.
 * A verdict is an answer about this step; these are facts about how the answer
 * was reached.
 *
 * `policyInput` is `unknown` on purpose. It is AGT's five-member policy input
 * document, and this package will not name a shape it does not own -- the
 * conformance harness validates it against AGT's own schema at the pinned ref,
 * which is a stronger check than a hand-written mirror of it here and cannot
 * drift from upstream without the check saying so.
 *
 * `transformedPolicyTarget` is deliberately absent even though the SDK returns
 * it. The one caller recomputes the enforced identity from `policyInput` and
 * `verdict.transform.value`; handing it AGT's own already-transformed target
 * would give the check a way to agree with AGT without recomputing anything,
 * which is the one thing a recomputation check must not have.
 */
export type AgtEvidence = {
  verdict: AgtVerdict;
  policyInput: unknown;
  inputIdentity: string;
  enforcedIdentity: string;
};

/**
 * The role the Guardian depends on: something you can tell to evaluate a
 * snapshot at an intervention point, which answers with a verdict.
 *
 * AGT stays out of the name deliberately -- the Guardian depends on this role,
 * not on AGT, and an invariant test keeps that honest in the other direction
 * by holding AGT's vocabulary out of the Guardian. `Policy` says which bridge,
 * since "bridge" alone would not survive a second one.
 *
 * `evaluate` answers with the verdict itself, not a result object carrying it:
 * the SDK's `inputIdentity`, `enforcedIdentity` and `transformedPolicyTarget`
 * describe its own evaluation rather than this step's outcome, and are
 * confirmed against the SDK in this package's own test.
 *
 * `evaluateWithEvidence` is deliberately NOT here. Production's `evaluateStep`
 * tells `evaluate` and nothing else, so a role carrying both would make every
 * Guardian stand-in -- `StartGuardianOptions.bridge` is typed against this --
 * answer a measurement question production never asks. That is `EvidenceBridge`
 * below, which the conformance harness depends on and the Guardian does not.
 *
 * The snapshot type parameter lets a holder declare which messages it sends
 * (`PolicyBridge<AgtPreToolCallSnapshot>`) and be checked against that shape.
 * `createBridge` answers with both roles, since it can do both jobs.
 */
export type PolicyBridge<S extends InterventionSnapshot = InterventionSnapshot> = {
  evaluate(point: string, snapshot: S): Promise<AgtVerdict>;
};

/**
 * The role the conformance harness depends on: the same evaluation, answered
 * wide enough to measure rather than to decide by.
 *
 * Separate from `PolicyBridge` rather than an extension of it, because the two
 * have disjoint callers -- nothing in the Guardian asks for evidence, and the
 * harness's identity check has no use for a bare verdict. `createBridge`
 * implements both and derives `evaluate` from this one, so there is exactly
 * one path into the SDK and the narrow answer is provably a projection of the
 * wide one.
 */
export type EvidenceBridge<S extends InterventionSnapshot = InterventionSnapshot> = {
  evaluateWithEvidence(point: string, snapshot: S): Promise<AgtEvidence>;
};

/**
 * A host-supplied annotator, called by name for every `annotators.<name>`
 * entry a manifest's intervention point declares via `annotations`. Its
 * return value lands at `input.annotations.<name>` for policy to read --
 * this is the only way `annotations` reaches policy input at all (five
 * other placements were tried against the snapshot and all were dropped;
 * see the drift manifest's own header). Deliberately a plain function, not
 * the SDK's own `AnnotatorDispatcher` interface: that shape is an
 * AGT-specific type this package's own callers should not have to import.
 * This bridge carries no host-specific code, and by the same token should
 * not force a host-shaped caller to reach into AGT's types either.
 */
export type Annotator = (name: string, config: unknown, preliminary: unknown) => unknown;

export type CreateBridgeOptions = {
  annotator?: Annotator;
};

/**
 * Construct once at boot, then call `evaluate` once per decision. Stateless:
 * nothing is retained between `evaluate()` calls.
 *
 * Answers with both roles. A caller takes the one it needs -- the Guardian a
 * `PolicyBridge`, the conformance harness an `EvidenceBridge` -- and neither
 * has to implement the other's message to stand in for it.
 */
export function createBridge(manifestPath: string, options?: CreateBridgeOptions): PolicyBridge & EvidenceBridge {
  if (manifestPath.includes("/./")) {
    throw new Error(
      `manifest path contains "/./": ${manifestPath}. AGT joins this verbatim and OPA ` +
        `then drops the bundle's data document, silently disabling policy.`,
    );
  }

  // Adapts the caller's plain function into the SDK's AnnotatorDispatcher
  // shape ({ dispatch(...) }), wrapped in `async` so a throw inside the
  // caller's function -- synchronous or not -- always arrives at the SDK
  // as a rejected promise rather than a synchronous exception escaping this
  // call directly. The SDK's own dispatcher contract already turns a throw
  // or a rejected promise into its own `runtime_error:annotation_failed`
  // fail-closed verdict; this wrapping is what makes sure every failure
  // shape actually reaches that handling, rather than some throwing one way
  // this project happens to exercise today and some other way it doesn't.
  const annotatorDispatcher = options?.annotator
    ? {
        // The cast at the return is the one place this function's result
        // meets the SDK's own `JsonValue`-shaped contract -- `Annotator`
        // itself stays `unknown` so nothing about AGT's types leaks into
        // this option's public shape. A caller returning something that
        // genuinely isn't JSON-shaped (a function, a class instance) is a
        // caller bug this cast does not catch; it exists to satisfy the
        // SDK's declared parameter type, not to validate the return value.
        async dispatch(name: string, config: unknown, preliminary: unknown): Promise<JsonValue> {
          return (await options.annotator!(name, config, preliminary)) as JsonValue;
        },
      }
    : undefined;

  // Before the runtime exists, not after: the SDK resolves its bundled opa
  // when the runtime is constructed, but under Bun that resolution never
  // reaches the native core that spawns it, and every evaluation would deny
  // on runtime_error:policy_invocation_failed -- see opa-path.ts's header.
  // Throws when no opa can be reached at all, so a process that cannot
  // evaluate policy gets no bridge rather than one that denies everything.
  publishOpaPath();

  const control = AgentControl.fromPath(manifestPath, annotatorDispatcher);

  return {
    async evaluateWithEvidence(point: string, snapshot: InterventionSnapshot): Promise<AgtEvidence> {
      const result = await control.evaluateInterventionPoint(point as never, snapshot as never);
      return {
        verdict: result.verdict as AgtVerdict,
        policyInput: result.policyInput,
        // Non-null asserted rather than defaulted: the SDK declares both
        // optional, and a default would let a binding that stopped
        // reporting them read as a successful measurement of an empty
        // string. AGT's Node binding sets both on every result, and this
        // package's own test pins that, so their absence would be a change
        // upstream rather than a case to paper over here.
        inputIdentity: result.inputIdentity!,
        enforcedIdentity: result.enforcedIdentity!,
      };
    },
    async evaluate(point: string, snapshot: InterventionSnapshot): Promise<AgtVerdict> {
      return (await this.evaluateWithEvidence(point, snapshot)).verdict;
    },
  };
}
