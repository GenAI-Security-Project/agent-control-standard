/**
 * Two assemblers, one per gate, each converting a validated ACS request
 * envelope into the AGT snapshot for the intervention point that answers its
 * method, shaped per AGT-SNAPSHOT-1.0.md §2.5:
 *
 *   assemblePreToolCallSnapshot   steps/toolCallRequest -> pre_tool_call
 *   assemblePostToolCallSnapshot  steps/toolCallResult  -> post_tool_call
 *
 * Siblings, not one function with two modes. §2.5 gives each point its own
 * snapshot shape, and these two share no member but `envelope.budgets`: one
 * carries the arguments a step was asked to run, the other the outputs it
 * produced. A single assembler reading `payload.arguments` OR `payload.outputs`
 * depending on what it found would be back to the union type the narrowing
 * exists to prevent, and would accept an envelope of either method when each
 * snapshot shape belongs to only one.
 *
 * `assemblePreToolCallSnapshot` keeps its original name rather than being
 * renamed to match its sibling: its parameter type already says which
 * envelope it takes, and `assemblePostToolCallSnapshot` names the wire's noun
 * for the other one.
 *
 * Envelope-only: both read nothing but the envelope handed to them -- no
 * session state, no chain hash, no prior decisions, no intent. The result
 * gate carries no `tool_call.args` for the same reason and one more: the
 * result payload has none to carry, and synthesizing them from the
 * originating request would be inventing state this module does not have.
 */

/**
 * The envelope types are re-exported from validate-envelope.ts, so there is
 * exactly one envelope shape rather than two that could silently diverge, and
 * existing imports of `ToolCallRequestEnvelope` from this module keep
 * working.
 *
 * These names mean what they say: the method-narrowed view of a validated ACS
 * request, each reachable only through its own predicate
 * (`isToolCallRequest`, `isToolCallResult`). Each function below takes
 * exactly one of them, so no signature here accepts a `handshake/hello` it
 * would read `params.payload.tool.name` off.
 */
import type { ToolCallRequestEnvelope, ToolCallResultEnvelope } from "./validate-envelope.ts";
export type { ToolCallRequestEnvelope, ToolCallResultEnvelope };

/**
 * The labels themselves, from the module that declares what they are. An
 * `import type`, which is erased at compile time: this module still links
 * against nothing in `session-context.ts` and still knows nothing about where
 * session state is kept. What it gains is the one name the labels already have
 * everywhere else, instead of a fourth spelling declared locally.
 */
import type { IfcLabels } from "./session-context.ts";

/**
 * AGT's `envelope.budgets` counters -- the ONE member the two snapshots below
 * share, so the one thing they name with a shared type. Sharing the member's
 * type is not sharing the snapshots': each still declares its own members, and
 * neither is assignable to the other.
 *
 * All four counters are always present and always real numbers: budgets.rego
 * fails closed on a present-but-wrong-typed counter, and that hazard belongs
 * to every gate, not just the request one.
 */
export type AgtSnapshotBudgets = {
  tool_call_count: number;
  token_count: number;
  elapsed_seconds: number;
  cost_usd: number;
};

/** A fresh set of zeroed counters. A function rather than a shared constant so
 * no two snapshots can ever alias the same budgets object. */
function zeroedBudgets(): AgtSnapshotBudgets {
  return { tool_call_count: 0, token_count: 0, elapsed_seconds: 0, cost_usd: 0 };
}

/**
 * The one snapshot leaf every tool's policy target is copied to.
 *
 * `policy/manifest.yaml`'s pre_tool_call `policy_target` names this, and
 * mapping.yaml's `policy_target_argument` names the per-tool argument it is
 * copied FROM. The `acs_` stem marks it as this side's construct rather than
 * something a host sent, which is what stops a reader taking it for an
 * argument some tool declared.
 */
export const POLICY_TARGET_LEAF = "acs_policy_target";

/**
 * Where AGT reads the source labels, and why the shorter path is wrong.
 * `policy/lib/agt_ifc.rego` resolves `input.snapshot.input.ifc.source_labels`;
 * `policy/lib/agt_ifc_test.rego` pins that the upstream library's
 * `input.snapshot.ifc.source_labels` reads as `[]` against an AGT host's
 * snapshot. Nested, therefore, and never hoisted to the snapshot root.
 *
 * The copy is what keeps a snapshot from being a writable window onto the
 * label store. The store copies on the way out too; both hold, because the two
 * arrays this copy separates belong to different owners.
 */
function ifcMember(sourceLabels: IfcLabels): { ifc: { source_labels: string[] } } {
  return { ifc: { source_labels: [...sourceLabels] } };
}

/**
 * The AGT `pre_tool_call` snapshot.
 *
 * Named for the intervention point it is the snapshot FOR, because that is what
 * fixes its shape -- AGT-SNAPSHOT-1.0.md §2.5 gives each point its own. A
 * `post_tool_call` snapshot would be a sibling type beside this one, not a
 * widening of it.
 *
 * `args` stays `Record<string, unknown>` on purpose: those are the tool's own
 * arguments, unwrapped from ACS's `{value, provenance}` shape, and their keys
 * are the tool's business rather than this project's.
 *
 * `input.ifc.source_labels` carries this session's IFC labels, nested under
 * `input` because `policy/lib/agt_ifc.rego` reads
 * `input.snapshot.input.ifc.source_labels` -- never `ifc` at the snapshot
 * root, which its own test pins as reading `[]`.
 */
export type AgtPreToolCallSnapshot = {
  envelope: { budgets: AgtSnapshotBudgets };
  tool_call: {
    name: string;
    args: Record<string, unknown>;
    id: string;
    /**
     * ACS's own `raw_command`, and ALWAYS present -- the empty string when the
     * wire carried none.
     *
     * Not a convenience. A manifest-declared annotator's `annotations.<name>
     * .from` path must resolve or AGT denies the entire call with
     * runtime_error:path_missing BEFORE dispatching the annotator -- measured,
     * with zero annotator calls -- so a snapshot that omitted this member for
     * tools with no shell command would turn every one of those calls into a
     * total deny wearing a runtime-error reason. An empty string resolves, and
     * the annotator answers no destination for it, which is the behaviour that
     * was wanted.
     */
    raw_command: string;
  };
  input: { ifc: { source_labels: string[] } };
};

/**
 * The AGT `post_tool_call` snapshot, standing beside `AgtPreToolCallSnapshot`
 * rather than widening it with optional members. Named for its own
 * intervention point, for the same reason its twin is.
 *
 * Every member is load-bearing, and there are only three:
 *   - `envelope.budgets`     the one member both snapshots carry.
 *   - `tool_call.name`       synthesized from the result payload's
 *                            `tool.name`. ACS's result payload has no
 *                            `tool_call` member of its own, and AGT resolves
 *                            the manifest's `tool_name_from` before any
 *                            policy runs -- a snapshot without a name fails
 *                            closed with `runtime_error:path_missing` on
 *                            every call (test/redaction.test.ts pins it).
 *   - `tool_result.outputs`  what policy/manifest.yaml's post_tool_call point
 *                            targets, at `$.tool_result.outputs[0].value`.
 *                            Every output is carried, and that target names
 *                            index 0 -- so a step returning several outputs
 *                            has its first one evaluated and the rest
 *                            carried but unexamined. That is the manifest's
 *                            declaration, not this assembler's choice;
 *                            widening it is a manifest change with its own
 *                            policy consequences.
 *
 * Three members absent on purpose, each for its own reason:
 *   - `tool_call.args`  the result payload has none. Carrying the
 *                       originating call's arguments forward would be
 *                       inventing state this module does not have.
 *   - `tool_call.id`    not because no id is on the wire -- `params.request_id`
 *                       is required by request-envelope.json at every step,
 *                       and the request gate uses exactly that field for its
 *                       own `tool_call.id`. But at this step that field
 *                       identifies this result message, not the call that
 *                       produced it. The originating call's id arrives only
 *                       as the optional `request_id_ref`, so an id here
 *                       would name the wrong request, and nothing here
 *                       correlates the two.
 *   - `exit_status`     required by hooks/tool-call-result.json, validated
 *                       on the way in, and deliberately not forwarded: AGT's
 *                       snapshot for this point (test/redaction.test.ts pins
 *                       the shape the stock bundle evaluates) has no place
 *                       for it, and no stock rule reads it.
 *
 * `outputs` items are `{value}` alone -- ACS's `{value, provenance}` wrapper does
 * not survive into a snapshot, the same rule the request side applies to its
 * arguments, and `value` stays `unknown` because what a tool produced is the
 * tool's business rather than this project's.
 */
export type AgtPostToolCallSnapshot = {
  envelope: { budgets: AgtSnapshotBudgets };
  tool_call: { name: string };
  tool_result: { outputs: { value: unknown }[] };
  input: { ifc: { source_labels: string[] } };
};

export function assemblePreToolCallSnapshot(
  envelope: ToolCallRequestEnvelope,
  sourceLabels: IfcLabels,
  policyTargetArgument: string | undefined,
): AgtPreToolCallSnapshot {
  const { payload, request_id } = envelope.params;

  if (policyTargetArgument === undefined) {
    throw new Error(
      `mapping.yaml declares no policy_target_argument for the request gate, so there is no argument to ` +
        `copy to the "${POLICY_TARGET_LEAF}" leaf policy/manifest.yaml targets`,
    );
  }

  // Unwrap every argument. AGT reads raw values -- args.command has to be a
  // plain string for the stock pattern check's is_string guard, for instance --
  // so the ACS {value, provenance} wrapper does not survive into the snapshot.
  const args: Record<string, unknown> = {};
  for (const [key, wrapper] of Object.entries(payload.arguments)) {
    args[key] = wrapper.value;
  }

  // Loudly, never silently. A tool genuinely sending an argument by this name
  // would have its own value replaced by the policy target and never
  // evaluated -- so the collision is reported here, where a manifest or
  // hookmap author can still act on it.
  if (Object.hasOwn(args, POLICY_TARGET_LEAF)) {
    throw new Error(
      `tool ${JSON.stringify(payload.tool.name)} sent an argument named ${JSON.stringify(POLICY_TARGET_LEAF)}, ` +
        `which is the leaf this Guardian writes its policy target to -- one of the two would have to be ` +
        `overwritten, and neither may be`,
    );
  }

  // A tool whose declared policy-target argument is not among its arguments is
  // a registration fault, not a policy decision. Throwing names the tool and
  // the argument; leaving the leaf undefined would reach AGT as
  // runtime_error:path_missing, which reads like a policy decision and says
  // nothing about which declaration is wrong.
  if (!Object.hasOwn(args, policyTargetArgument)) {
    throw new Error(
      `mapping.yaml reads tool ${JSON.stringify(payload.tool.name)}'s policy target from argument ` +
        `${JSON.stringify(policyTargetArgument)}, but this call sent no such argument ` +
        `(it sent: ${Object.keys(args).join(", ") || "none"})`,
    );
  }
  args[POLICY_TARGET_LEAF] = args[policyTargetArgument];

  return {
    // budgets.rego fails closed on a present-but-wrong-typed counter, so
    // these are always real zeros, never undefined/null.
    envelope: { budgets: zeroedBudgets() },
    tool_call: {
      name: payload.tool.name,
      args,
      id: request_id,
      raw_command: payload.raw_command ?? "",
    },
    input: ifcMember(sourceLabels),
  };
}

export function assemblePostToolCallSnapshot(
  envelope: ToolCallResultEnvelope,
  sourceLabels: IfcLabels,
): AgtPostToolCallSnapshot {
  const { payload } = envelope.params;

  return {
    envelope: { budgets: zeroedBudgets() },
    // Synthesized, and load-bearing: see AgtPostToolCallSnapshot above.
    tool_call: { name: payload.tool.name },
    // Unwrap every output, exactly as the request side unwraps every argument:
    // AGT reads the raw value at $.tool_result.outputs[0].value, and the ACS
    // {value, provenance} wrapper does not survive into the snapshot.
    tool_result: { outputs: payload.outputs.map((output) => ({ value: output.value })) },
    input: ifcMember(sourceLabels),
  };
}
