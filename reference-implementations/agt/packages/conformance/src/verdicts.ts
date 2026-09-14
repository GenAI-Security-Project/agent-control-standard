/**
 * AGT verdict -> ACS decision -> AGT verdict, at every intervention point,
 * asserting the verdict that comes back is the one that went in.
 *
 * The forward leg is `mapVerdict`, the runtime's own -- so this measures what
 * the Guardian does rather than what mapping.yaml says it should. The reverse
 * leg is derived from the same declaration by `invertVerdicts` below, and
 * that is the part worth stating: an inverse written by hand here would agree
 * with mapping.yaml because the same hand wrote both, and would go on
 * agreeing after mapping.yaml changed. A round trip through two independent
 * spellings of one table is not a round trip.
 *
 * The mapping is not injective. `allow` and `warn` both become ACS `allow`,
 * discriminated by whether `policy_references` is non-empty: `warn` is allow
 * with a non-empty one. But mapVerdict synthesizes policy_references from
 * verdict.reason for any decision that carries one (map-verdict.ts,
 * unconditionally) -- not only where require_policy_references is declared.
 * A real, reason-carrying `deny` or `escalate` (policy/lib/agt_default.rego
 * synthesizes a `pattern_reason`, defaulting to "pattern_blocked", for deny)
 * therefore produces non-empty policy_references too, and that emptiness
 * means nothing there: deny and escalate are each the only AGT verdict on
 * their ACS decision, so nothing needs discriminating from anything else.
 * The inverse keys emptiness only where mapping.yaml sends more than one AGT
 * verdict to the same ACS decision -- `allow`'s group today -- and keys
 * every other decision by itself.
 *
 * `defer` has no AGT verdict behind it at all and therefore never appears
 * here: this walks AGT's five, not ACS's.
 *
 * WHAT A FAILED ROUND TRIP RESOLVES TO. `contract_violated`, not
 * `unexpressed`: a verdict that goes in and does not come back is this tree's
 * declaration being wrong about itself, and it is the one thing here that
 * fails `bun run conformance` (exit-code.ts's rule, and `cells.ts`'s
 * `CellStatus` for the distinction). `unexpressed` is kept for the answers
 * that are about ACS -- a point ACS v0.1.0 carries no method for, a transform
 * this table declares it has no target for -- because failing on those would
 * make an honest gap indistinguishable from a defect and press the matrix
 * towards being all-expressed.
 */
import { mapVerdict, resolvePolicyTargetArgument, type AcsDecision, type Mapping } from "guardian";
import type { AgtVerdict } from "agt-bridge";
import { everyCell, type CoverageCell } from "./cells.ts";

/** The `warn` column's own reason. Attached to `warn` at every point with a
 * non-null acs_method (six of the eight), because the fact it states -- no
 * v0.1.0 method payload carries a field a drift score could be derived from
 * -- holds at all six, not only the request gate. */
const WARN_GUARDIAN_ONLY =
  "AGT's only stock warn gate reads input.annotations.drift_score, which reaches the policy input from a " +
  "manifest-declared annotator and never from the snapshot; no ACS v0.1.0 method payload carries a field a " +
  "drift score could be derived from, so the Guardian must originate it";

/** A tool name `mapping.yaml`'s `by_tool` table deliberately does not carry,
 * so this round trip reads the declared default rather than one tool's row.
 * Passing a real tool name would make the measurement depend on which tools
 * happen to be registered. */
const CONFORMANCE_PROBE_TOOL = "conformance_probe";

/**
 * Inverts mapping.yaml's `verdicts` table: ACS decision -> AGT verdict. Two
 * key grammars, by design and not by accident: a decision reached by exactly
 * one AGT verdict is keyed by the decision alone (e.g. `"deny"`); a decision
 * two or more verdicts share is keyed by
 * `` `${decision}|${require_policy_references === true}` `` (e.g.
 * `"allow|true"`), because only there does emptiness have anything to
 * discriminate.
 *
 * A caller looks up the bare decision first and falls back to the qualified
 * key -- `inverse.get(decision) ?? inverse.get(\`${decision}|${hasReferences}\`)`
 * -- exactly as `roundTrip` below does. This is the whole contract of the
 * returned `Map`, stated here because `invertVerdicts` is re-exported from
 * `src/index.ts` and a caller outside this file has no other place to read
 * it from.
 */
export function invertVerdicts(mapping: Mapping): Map<string, string> {
  // How many AGT verdicts land on each ACS decision. A count of one means
  // the decision alone already answers "which AGT verdict was this" --
  // emptiness has nothing to add and must not be asked to discriminate a
  // group of one, or a real, reason-carrying deny or escalate (see the file
  // comment) would misread as an inversion failure that isn't one.
  const decisionCounts = new Map<string, number>();
  for (const rule of Object.values(mapping.verdicts)) {
    decisionCounts.set(rule.decision, (decisionCounts.get(rule.decision) ?? 0) + 1);
  }

  const inverse = new Map<string, string>();
  for (const [agtVerdict, rule] of Object.entries(mapping.verdicts)) {
    const key =
      decisionCounts.get(rule.decision) === 1
        ? rule.decision
        : `${rule.decision}|${rule.require_policy_references === true}`;
    const existing = inverse.get(key);
    if (existing !== undefined) {
      // Two AGT verdicts on one ACS decision with no discriminator between
      // them: picking either would make the answer depend on YAML key order,
      // which is the same reason resolveInterventionPoint throws on an
      // ambiguous table rather than taking the first row.
      throw new Error(
        `mapping.yaml's verdicts table maps both "${existing}" and "${agtVerdict}" to ACS ` +
          `"${rule.decision}" with the same policy_references requirement, so the mapping is not invertible`,
      );
    }
    inverse.set(key, agtVerdict);
  }
  return inverse;
}

export function checkVerdicts(mapping: Mapping): CoverageCell[] {
  const inverse = invertVerdicts(mapping);
  return everyCell().map(({ point, verdict }) => ({
    point,
    verdict,
    ...applyWarnDriftScoreFinding(verdict, roundTrip(verdict, point, mapping, inverse)),
    measuredBy: ["verdict round trip"],
  }));
}

/**
 * The second step, and deliberately not part of the round trip above.
 *
 * `warn` round-trips exactly like the other four -- AGT `warn` becomes ACS
 * `allow` with a non-empty `policy_references` and reads back as `warn`. What
 * makes its column `guardian_only` is a different finding altogether: the
 * stock gate reads a drift score no v0.1.0 payload carries. Folding that into
 * `roundTrip` put a coverage finding inside a function named for a round
 * trip, so a reader had to know that one of its five verdicts was answering
 * a second question.
 *
 * Applied only where the round trip held, which the `expressed` test below
 * is: a `warn` that failed to invert is `contract_violated` for that reason
 * and a `warn` at a point ACS cannot reach is `unexpressed` for that one, and
 * this must not overwrite either with a milder status -- the drift-score
 * finding is about a mapping that works.
 */
function applyWarnDriftScoreFinding(
  verdict: string,
  roundTripResult: { status: CoverageCell["status"]; reason?: string },
): { status: CoverageCell["status"]; reason?: string } {
  if (verdict !== "warn" || roundTripResult.status !== "expressed") return roundTripResult;
  return { status: "guardian_only", reason: WARN_GUARDIAN_ONLY };
}

function roundTrip(
  verdict: string,
  point: string,
  mapping: Mapping,
  inverse: Map<string, string>,
): { status: CoverageCell["status"]; reason?: string } {
  // mapVerdict does not consult acs_method -- it answers "what ACS decision
  // would this AGT verdict become AT this point", which is a real question
  // for a point mapping.yaml wires to a method and a fiction for one it does
  // not. pre_model_call and post_model_call carry acs_method: null: no ACS
  // method ever resolves to either (resolveInterventionPoint has nothing to
  // return), so no verdict fired there could reach a wire consumer to
  // round-trip through. Left unguarded, mapVerdict would answer every
  // non-transform verdict at these points as if the round trip held --
  // reporting a round trip the runtime is never asked to perform -- so this
  // reads the same row the intervention-point check reads and stops before
  // asking the question.
  const row = mapping.intervention_points[point];
  if (row === undefined) {
    // NOT a gap in ACS, so not `unexpressed`: the axes are read off AGT's own
    // SDK (cells.ts), and mapping.yaml declares a row for every point AGT
    // names -- marking one ACS v0.1.0 cannot reach with `acs_method: null`
    // and a note, which is a declaration. No row at all is the table failing
    // to cover its own subject, a finding about this tree.
    return {
      status: "contract_violated",
      reason: `mapping.yaml's intervention_points table has no row for AGT point "${point}"`,
    };
  }
  if (row.acs_method === null) {
    return {
      status: "unexpressed",
      reason: row.note ?? "mapping.yaml declares no ACS method for this point",
    };
  }

  // A verdict AGT would actually emit for this decision, not a stub shaped
  // by this check. The pinned bundle's stock emitters, verdict by verdict:
  //   allow      {"decision":"allow"[,"result_labels":[...]]}                    (policy/lib/ifc.rego:104)      -- no reason, no message
  //   deny       reason + message                                               (policy/lib/patterns.rego:103-107, policy/lib/ifc.rego:81-85)
  //   escalate   reason + message                                               (policy/lib/approval.rego:24-31)
  //   warn       reason + message                                               (policy/lib/drift.rego:27-31)
  //   transform  {"decision":"transform","reason":"redaction_applied","transform":{...}} (policy/lib/redact.rego:38-47) -- reason, no message
  // `allow` and `transform` are both exceptions to "every verdict gets a
  // message" -- one by omitting reason too, the other by omitting only
  // message. `message` is what field_synthesis.reasoning reads, `reason` is
  // what field_synthesis.reason_codes and .policy_references both read, and
  // `transform` is what the modifications rule reads. A probe that gave a
  // verdict a field its stock emitter does not send would measure this
  // harness's own construction instead of the table.
  const agt: AgtVerdict = {
    decision: verdict as AgtVerdict["decision"],
    ...(verdict === "allow" ? { result_labels: ["probe"] } : { reason: "conformance_probe" }),
    ...(verdict === "deny" || verdict === "escalate" || verdict === "warn" ? { message: "conformance probe" } : {}),
    ...(verdict === "transform"
      ? { transform: { path: "$policy_target", value: "probe" } }
      : {}),
  };

  // WHICH THROWS ARE FINDINGS, and the declaration is what tells them apart.
  // A verdict mapping.yaml sends to ACS `modify` can only be built where the
  // point's own row declares a `modifications` rule, and mapping.yaml says so
  // in the table itself: a row without one "cannot express a transform at
  // all, and mapVerdict throws for one rather than answering with a MODIFY
  // the host has nothing to apply". That throw is the declaration being read
  // back truthfully -- ACS has no target for this rewrite here -- and
  // mapVerdict is still ASKED rather than short-circuited on the table,
  // because a refusal MEASURED at the runtime is the evidence and the table
  // is only what says which of two things the refusal means. A throw anywhere
  // else is the runtime failing at a mapping the table claims it can express,
  // which is a finding rather than a gap.
  const declaresNoTarget =
    mapping.verdicts[verdict]?.decision === "modify" && row.modifications === undefined;

  let acs: AcsDecision;
  try {
    acs = mapVerdict(agt, mapping, point, resolvePolicyTargetArgument(mapping, point, CONFORMANCE_PROBE_TOOL));
  } catch (error) {
    // mapVerdict's own sentence, either way: it names the row and the rule it
    // could not find better than a reason written here would, and rewriting
    // it would put a second spelling of the runtime's refusal in this file.
    const reason = error instanceof Error ? error.message : String(error);
    return declaresNoTarget ? { status: "unexpressed", reason } : { status: "contract_violated", reason };
  }

  const hasReferences = (acs.policy_references?.length ?? 0) > 0;
  // A decision reached by exactly one AGT verdict inverts on the decision
  // alone (see invertVerdicts); only a decision two verdicts share needs the
  // emptiness-qualified key.
  const back = inverse.get(acs.decision) ?? inverse.get(`${acs.decision}|${hasReferences}`);
  if (back !== verdict) {
    // A round trip through the runtime and back out of the table that does
    // not return what went in: the declaration is broken, not the
    // specification silent. This is the case the exit rule exists to fail on
    // (exit-code.ts) -- it read `unexpressed` here for as long as the two
    // classes shared one name, which made the instrument unable to fail on
    // its own headline finding.
    return {
      status: "contract_violated",
      reason: `AGT "${verdict}" becomes ACS "${acs.decision}", which reads back as "${back ?? "nothing"}"`,
    };
  }

  return { status: "expressed" };
}
