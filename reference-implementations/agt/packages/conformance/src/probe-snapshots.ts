/**
 * The two snapshots the conformance probes evaluate, built by the Guardian's
 * own assemblers from validated ACS envelopes rather than written by hand, so
 * the harness measures what the Guardian would send to AGT, not a replica of it.
 *
 * The fixtures are the REDACTABLE / REDACTABLE_COMMAND shapes
 * `test/identity.test.ts` drives: a real transform at both transform-capable
 * gates, so the enforced-identity cells report the measured `guardian_only`
 * finding rather than the no-rewrite case a benign fixture would report.
 */
import {
  assemblePostToolCallSnapshot,
  assemblePreToolCallSnapshot,
  isToolCallRequest,
  isToolCallResult,
  loadMapping,
  POLICY_TARGET_LEAF,
  resolvePolicyTargetArgument,
  validateEnvelope,
} from "guardian";
import type { InterventionSnapshot } from "agt-bridge";

const MAPPING_PATH = "mapping.yaml";
const SOURCE_LABELS = ["public"];
const METADATA = { agent_id: "conformance-probe", session_id: "5b7a6e2a-6a2e-4b7a-9f2e-6a6d2e6a9a22" };

const REQUEST = validateEnvelope({
  jsonrpc: "2.0",
  method: "steps/toolCallRequest",
  id: "probe-pre",
  params: {
    acs_version: "0.1.0",
    request_id: "b3e1c9f0-3b21-4b7a-9f2e-6a6d2e6a9a11",
    timestamp: "2026-09-09T14:02:11Z",
    metadata: METADATA,
    payload: {
      tool: { name: "Bash" },
      arguments: { command: { value: "echo ghp_ONLYINCOMMAND999" } },
      raw_command: "echo ghp_ONLYINCOMMAND999",
    },
  },
});

const RESULT = validateEnvelope({
  jsonrpc: "2.0",
  method: "steps/toolCallResult",
  id: "probe-post",
  params: {
    acs_version: "0.1.0",
    request_id: "c4f2d0a1-4c32-4c8b-a03f-7b7e3f7b0b33",
    timestamp: "2026-09-09T14:02:12Z",
    metadata: METADATA,
    payload: {
      tool: { name: "Bash" },
      outputs: [{ value: "TOKEN=ghp_ONLYINOUTPUT999\n" }],
      exit_status: "success",
    },
  },
});

function preToolCallSnapshot(): InterventionSnapshot {
  if (!isToolCallRequest(REQUEST)) throw new Error("probe request is not a steps/toolCallRequest");
  const target = resolvePolicyTargetArgument(loadMapping(MAPPING_PATH), "pre_tool_call", "Bash");
  const snapshot = assemblePreToolCallSnapshot(REQUEST, SOURCE_LABELS, target);
  // AGT's pre_tool_call policy_target reads this leaf. Without it the probes
  // would fail later with a bare TypeError, so name the missing field here.
  const args = (snapshot as { tool_call: { args: Record<string, unknown> } }).tool_call.args;
  if (typeof args[POLICY_TARGET_LEAF] !== "string") {
    throw new Error(
      `assemblePreToolCallSnapshot did not write tool_call.args.${POLICY_TARGET_LEAF} ` +
        `(expected the "${target}" argument as a string), so AGT has no policy target to evaluate`,
    );
  }
  return snapshot;
}

function postToolCallSnapshot(): InterventionSnapshot {
  if (!isToolCallResult(RESULT)) throw new Error("probe result is not a steps/toolCallResult");
  return assemblePostToolCallSnapshot(RESULT, SOURCE_LABELS);
}

export const PRE_TOOL_CALL_SNAPSHOT: InterventionSnapshot = preToolCallSnapshot();
export const POST_TOOL_CALL_SNAPSHOT: InterventionSnapshot = postToolCallSnapshot();
