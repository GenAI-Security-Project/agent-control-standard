/**
 * The intervention-point check's schema leg. `checkInterventionPoints`
 * (intervention-points.ts) measures whether mapping.yaml's declared method
 * round-trips through the runtime's own resolver; this measures a different
 * question about the same table -- whether the policy input the Guardian
 * actually constructs on the way there is a document AGT itself would
 * accept, checked against AGT's own `policy-input.schema.json` rather than a
 * hand-written mirror of it kept in this repo. This check couples only to a
 * declared contract surface, since a copy of that surface authored here
 * could drift from upstream without this check saying so.
 *
 * `packages/agt-bridge/test/bridge.test.ts` already asserts the
 * constructed policy input has exactly the five members
 * `policy-input.schema.json` names (`additionalProperties: false` over
 * `intervention_point`, `policy_target`, `snapshot`, `annotations`, `tool`)
 * -- a shape assertion against a hand-written list. This is what turns it
 * into a check against AGT's real contract.
 *
 * SCOPED TO THE TWO POINTS THE GUARDIAN ACTUALLY CONSTRUCTS ONE FOR:
 * `pre_tool_call` and `post_tool_call` -- the only two AGT intervention
 * points this codebase has a real snapshot assembler for at all
 * (`packages/guardian/src/assemble-snapshot.ts`'s `assemblePreToolCall-
 * Snapshot` / `assemblePostToolCallSnapshot`), and the same two points the
 * enforced-identity check measures for the identical reason. "The policy
 * input the Guardian would send" is only a real question at these two; AGT's
 * other six points have no snapshot shape anywhere in this codebase to
 * construct one for, and inventing a plausible-looking one here would
 * measure this harness's own guess rather than the Guardian's real
 * behaviour (see e.g. verdicts.ts's own header on the same point).
 *
 * DOES NOT FETCH. Mirrors `scripts/verify-pin.sh`'s own pattern exactly: a
 * shell script (`scripts/run-conformance.sh`) clones AGT at the pinned ref
 * into a scratch temp dir and hands the path in by
 * `PINNED_AGT_CLONE`; this module self-skips -- returns `{ran: false}`,
 * never throws -- when that variable is absent, so `bun test` (which never
 * sets it) always exercises every check that does not need the network and
 * never performs one.
 *
 * PINNED, NOT UPSTREAM, and the distinction matters. This clone is
 * `agt.lock`'s locked ref -- the contract this repository is built against,
 * not AGT's moving `main`. A separate name is reserved for `main`
 * (`UpstreamSurfaces` beside `PinnedSurfaces`, both defined in `surfaces.ts`),
 * and both now live in this package: `upstream-watch.ts`'s upstream contract
 * watch reads one clone of each. A differ told "upstream" twice is exactly
 * the failure that split was written to prevent, so this one says which ref
 * it means.
 *
 * A THROW, not a resolved finding, when a constructed policy input actually
 * FAILS validation -- the same choice `failure-domains.ts`'s
 * `assertEvaluationFailsClosed` makes for a broken invariant: this is not a
 * matrix cell (there is no verdict axis for a policy input; it is the same
 * document regardless of which verdict AGT eventually returns for it), and a
 * bridge that constructs a wire-invalid document is a real defect this
 * check must not fold into a quietly-published "did not validate" line.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import type { EvidenceBridge, InterventionSnapshot } from "agt-bridge";
import { POLICY_TARGET_LEAF } from "guardian";

/** Names the variable `scripts/run-conformance.sh` sets after cloning AGT at
 * `agt.lock`'s pinned ref -- read here, and printed in the skip reason below,
 * so a reader of the runner's own output does not have to go and find the
 * name in this file to reproduce the leg locally. */
export const PINNED_AGT_CLONE_ENV = "PINNED_AGT_CLONE";

/** Confirmed present at `agt.lock`'s pinned ref. Relative to the clone root
 * `PINNED_AGT_CLONE` names. */
const SCHEMA_RELATIVE_PATH = "policy-engine/spec/schema/wire/policy-input.schema.json";

/** Representative snapshots at the two points this leg covers -- the same
 * REDACTABLE / REDACTABLE_COMMAND shapes `test/identity.test.ts` drives
 * through the real bridge for the identical reason: real fixtures that
 * exercise AGT's transform path, not minimal stubs shaped by this check.
 * Order is this module's own reporting order. */
const PROBE_SNAPSHOTS: [point: "pre_tool_call" | "post_tool_call", snapshot: InterventionSnapshot][] = [
  [
    "pre_tool_call",
    {
      envelope: { budgets: { tool_call_count: 0, token_count: 0, elapsed_seconds: 0, cost_usd: 0 } },
      tool_call: {
        name: "Bash",
        // POLICY_TARGET_LEAF is the leaf assemble-snapshot.ts copies a
        // tool's own policy-target argument to; policy/manifest.yaml's
        // pre_tool_call point targets that leaf, not `command` directly.
        args: { command: "echo ghp_ONLYINCOMMAND999", [POLICY_TARGET_LEAF]: "echo ghp_ONLYINCOMMAND999" },
        // The same point's `annotations.egress.from` names this member, and
        // an annotation's `from` is a liveness precondition: unresolved, AGT
        // denies the whole call on runtime_error:path_missing, and the
        // document this leg is meant to validate is never produced.
        raw_command: "echo ghp_ONLYINCOMMAND999",
        id: "t1",
      },
      input: { ifc: { source_labels: ["public"] } },
    },
  ],
  [
    "post_tool_call",
    {
      envelope: { budgets: { tool_call_count: 0, token_count: 0, elapsed_seconds: 0, cost_usd: 0 } },
      tool_call: { name: "Bash" },
      tool_result: { outputs: [{ value: "TOKEN=ghp_ONLYINOUTPUT999\n" }] },
      input: { ifc: { source_labels: ["public"] } },
    },
  ],
];

export type SchemaLegResult =
  | { ran: false; reason: string }
  | { ran: true; points: string[] };

/**
 * Compiles AGT's own schema file out of `upstreamClone` -- never a schema
 * kept in this repo. `strictRequired: false` and `allowUnionTypes: true` are
 * the same two Ajv strict-mode opt-outs `packages/guardian/src/validate-
 * envelope.ts`'s `buildAjv` documents, needed here for a DIFFERENT
 * construct in AGT's schema for the same underlying reason: `$defs.snapshot`'s
 * `anyOf` branches (`{"required": ["agent"]}`, etc.) each declare no
 * `properties` of their own for the key they require -- the sibling
 * `agent`/`input`/... properties live on the enclosing `snapshot` schema, not
 * inside each branch -- which is Ajv's strictRequired check tripping on a
 * schema whose `required` and sibling `properties` are both real and both
 * satisfied, not a genuine authoring mistake in AGT's schema; `allowUnion-
 * Types` because `policy_target.kind` is typed `["string", "null"]`. Neither
 * check is a validation-SEMANTICS check -- confirmed by running these exact
 * settings against the schema fetched from the pinned ref and both probe
 * snapshots below: both validate `true`, not merely "this schema compiles".
 */
function buildValidator(cloneDir: string) {
  const schemaPath = join(cloneDir, SCHEMA_RELATIVE_PATH);
  const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
  const ajv = new Ajv2020({ strict: true, allErrors: true, strictRequired: false, allowUnionTypes: true });
  addFormats(ajv);
  return ajv.compile(schema);
}

/**
 * The validation this file's header describes, run against whichever AGT
 * clone `cloneDir` names. The clone lives in a parameter rather than an
 * environment read, because this repository now asks the question of two
 * different clones: `checkPolicyInputSchema`, below, still reads
 * `PINNED_AGT_CLONE_ENV` itself and delegates here with the pinned clone;
 * the upstream contract watch calls this directly with a clone of `main`.
 * THROWS on a validation failure -- see this file's header for why that is
 * the correct answer rather than a resolved finding.
 */
export async function checkPolicyInputSchemaAt(bridge: EvidenceBridge, cloneDir: string): Promise<SchemaLegResult> {
  const validate = buildValidator(cloneDir);
  const points: string[] = [];
  for (const [point, snapshot] of PROBE_SNAPSHOTS) {
    const evidence = await bridge.evaluateWithEvidence(point, snapshot);
    if (!validate(evidence.policyInput)) {
      throw new Error(
        `schema leg: the policy input the Guardian would send at "${point}" failed AGT's own ` +
          `policy-input.schema.json (${SCHEMA_RELATIVE_PATH}) -- ${JSON.stringify(validate.errors)}`,
      );
    }
    points.push(point);
  }
  return { ran: true, points };
}

/** The pinned-ref question, which is the one the conformance run asks. */
export async function checkPolicyInputSchema(bridge: EvidenceBridge): Promise<SchemaLegResult> {
  const pinnedClone = process.env[PINNED_AGT_CLONE_ENV];
  if (!pinnedClone) {
    return {
      ran: false,
      reason:
        `${PINNED_AGT_CLONE_ENV} is not set -- run \`bun run conformance\` (scripts/run-conformance.sh clones ` +
        `AGT at agt.lock's pinned ref and sets it) to run this leg; \`bun test\` alone never performs the fetch`,
    };
  }
  return checkPolicyInputSchemaAt(bridge, pinnedClone);
}
