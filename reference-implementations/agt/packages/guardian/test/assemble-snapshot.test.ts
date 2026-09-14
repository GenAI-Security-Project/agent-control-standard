import { describe, expect, it } from "bun:test";
import { createDeploymentBridge } from "../src/deployment-bridge.ts";
import {
  assemblePostToolCallSnapshot,
  assemblePreToolCallSnapshot,
  POLICY_TARGET_LEAF,
  type ToolCallRequestEnvelope,
  type ToolCallResultEnvelope,
} from "../src/assemble-snapshot.ts";
import { isToolCallRequest, isToolCallResult, validateEnvelope } from "../src/validate-envelope.ts";
import type { IfcLabels } from "../src/session-context.ts";

/**
 * Both assemblers require a labels argument -- required, not optional, so an
 * omitted one cannot silently read as "no labels". Tests below that do not
 * care about labels pass this constant, so none of their own assertions
 * about envelope-derived members are affected by adding it. Tests further
 * down that need an explicit "no labels" case reuse this same constant
 * rather than declaring a second one with an identical value.
 *
 * Named for what it is: an empty label list, not the absence of session
 * state. The Guardian's own session seed supplies `["public"]` by default,
 * since the stock gate denies a zero-label flow outright, so a real session
 * snapshot never carries labels this empty. What it actually is is a value
 * these two assemblers accept and pass through unexamined, which is exactly
 * why every test that doesn't care about labels can carry it.
 */
const EMPTY_SOURCE_LABELS: IfcLabels = [];

function makeEnvelope(overrides: {
  toolName?: string;
  args?: Record<string, { value: unknown; provenance?: unknown }>;
  requestId?: string;
} = {}): ToolCallRequestEnvelope {
  const {
    toolName = "run_shell",
    args = { command: { value: "ls -la", provenance: { source: "user" } } },
    requestId = "8f14e45f-ceea-467e-bd5f-1d4d9a4e0c8f",
  } = overrides;

  return {
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: 1,
    params: {
      acs_version: "0.1.0",
      request_id: requestId,
      timestamp: "2026-08-09T12:00:00Z",
      metadata: {
        agent_id: "agent-1",
        session_id: "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
        session_state: { chain_hash: "deadbeef" },
      },
      payload: {
        tool: { name: toolName },
        arguments: args,
      },
    },
  } as unknown as ToolCallRequestEnvelope;
}

describe("assemblePreToolCallSnapshot", () => {
  it("maps params.payload.tool.name to tool_call.name, and unwraps each argument's .value into tool_call.args, dropping provenance", () => {
    const envelope = makeEnvelope({
      toolName: "run_shell",
      args: {
        command: { value: "rm -rf /", provenance: { source: "user", timestamp: "2026-08-09T12:00:00Z" } },
      },
    });

    const snapshot = assemblePreToolCallSnapshot(envelope, EMPTY_SOURCE_LABELS, "command");

    expect(snapshot.tool_call.name).toBe("run_shell");
    expect(snapshot.tool_call.args).toEqual({ command: "rm -rf /", [POLICY_TARGET_LEAF]: "rm -rf /" });
  });

  // AGT's stock pattern check reads input.policy_target.value and
  // requires is_string. A surviving {value:...} wrapper (or a non-string)
  // makes the check silently never fire, and everything is allowed.
  it("keeps tool_call.args.command a STRING, not a nested wrapper or object", () => {
    const envelope = makeEnvelope({ args: { command: { value: "rm -rf /" } } });

    const snapshot = assemblePreToolCallSnapshot(envelope, EMPTY_SOURCE_LABELS, "command");

    expect(typeof snapshot.tool_call.args.command).toBe("string");
    expect(snapshot.tool_call.args.command).toBe("rm -rf /");
  });

  it("always emits envelope.budgets with all four counters zeroed, even though the envelope says nothing about budgets", () => {
    const envelope = makeEnvelope();

    const snapshot = assemblePreToolCallSnapshot(envelope, EMPTY_SOURCE_LABELS, "command");

    expect(snapshot.envelope).toEqual({
      budgets: { tool_call_count: 0, token_count: 0, elapsed_seconds: 0, cost_usd: 0 },
    });
  });

  it("carries params.request_id onto tool_call.id", () => {
    const envelope = makeEnvelope({ requestId: "2c3e4f50-1234-4abc-9def-000000000000" });

    const snapshot = assemblePreToolCallSnapshot(envelope, EMPTY_SOURCE_LABELS, "command");

    expect(snapshot.tool_call.id).toBe("2c3e4f50-1234-4abc-9def-000000000000");
  });

  // Envelope-only: nothing is read from session state. Session id, chain
  // hash, and every other session-derived key must not survive into the
  // snapshot.
  it("reads nothing but the envelope: no session-derived key appears anywhere in the output", () => {
    const envelope = makeEnvelope();

    // No cast: assemblePreToolCallSnapshot returns a named snapshot message now, so what
    // these read is the type it declares rather than an anonymous dict.
    const snapshot = assemblePreToolCallSnapshot(envelope, EMPTY_SOURCE_LABELS, "command");

    expect(Object.keys(snapshot).sort()).toEqual(["envelope", "input", "tool_call"]);
    expect(Object.keys(snapshot.envelope)).toEqual(["budgets"]);
    expect(Object.keys(snapshot.tool_call).sort()).toEqual(["args", "id", "name", "raw_command"]);

    const serialized = JSON.stringify(snapshot);
    for (const forbidden of ["session_id", "session_state", "chain_hash", "agent_id", "metadata", "intent", "1b9d6bcd"]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  // The high-value integration test: this is the first point in the build
  // where the two halves (guardian's snapshot assembly, agt-bridge's real
  // OPA evaluation) meet.
  it("feeds a realistic rm -rf / envelope through the real AGT bridge and gets denied", async () => {
    const envelope = makeEnvelope({
      toolName: "run_shell",
      args: { command: { value: "rm -rf /", provenance: { source: "user" } } },
    });

    // NOT `EMPTY_SOURCE_LABELS`: IFC deny outranks every other gate
    // (policy/lib/agt_default.rego's header), so a zero-label snapshot denies
    // on `ifc_clearance_violation` before the pattern rule this test is named
    // for ever runs -- and the assertion below would then pass for `echo hi`
    // just as readily, leaving the `rm -rf /` fixture decorative. The
    // `["public"]` label is what the Guardian's own session seed supplies.
    const snapshot = assemblePreToolCallSnapshot(envelope, ["public"], "command");
    // Built the way the deployment builds one, which is the way startGuardian
    // does: this bridge stands in for a real Guardian, and a bridge missing
    // this deployment's annotator denies every request-gate call on
    // runtime_error:annotation_failed -- measured, benign calls included.
    const bridge = createDeploymentBridge("policy/manifest.yaml");
    const verdict = await bridge.evaluate("pre_tool_call", snapshot);

    // The reason, not the decision alone. Both an annotator-less bridge and an
    // unlabelled snapshot also answer `deny` here, so pinning the decision by
    // itself would not distinguish the pattern gate firing from evaluation
    // failing somewhere above it.
    expect(verdict).toMatchObject({ decision: "deny", reason: "destructive_shell_command_blocked" });
  });
});

/**
 * A raw steps/toolCallResult envelope, as JSON, exactly as it arrives on the
 * wire -- and taken through the real door on the way in: validateEnvelope,
 * then the isToolCallResult narrowing. Not a cast. A result envelope does not
 * typecheck against `assemblePreToolCallSnapshot`'s parameter, and a cast that hid that
 * would hide the one property this pair of assemblers exists for.
 *
 * `metadata.agent_id` is here because request-envelope.json's Metadata $def
 * requires it. Going through validateEnvelope rather than around it is what
 * makes that a compile-and-run fact rather than a detail a cast could skip.
 */
function rawResultEnvelope(
  overrides: { toolName?: string; outputs?: { value: unknown; provenance?: unknown }[] } = {},
): unknown {
  const { toolName = "Bash", outputs = [{ value: "TOKEN=ghp_ABCDEF123456" }] } = overrides;

  return {
    jsonrpc: "2.0",
    method: "steps/toolCallResult",
    id: "r1",
    params: {
      acs_version: "0.1.0",
      request_id: "6ba59b01-1493-4f4c-af22-8a36eeca4651",
      timestamp: "2026-08-11T00:00:00Z",
      metadata: { agent_id: "agent-1", session_id: "6c616a11-495a-4f05-878a-c1bfaa29f0e5" },
      payload: { tool: { name: toolName }, exit_status: "success", outputs },
    },
  };
}

function makeResultEnvelope(
  overrides: { toolName?: string; outputs?: { value: unknown; provenance?: unknown }[] } = {},
): ToolCallResultEnvelope {
  const validated = validateEnvelope(rawResultEnvelope(overrides));
  if (!isToolCallResult(validated)) {
    throw new Error(`validateEnvelope returned a non-result envelope: ${validated.method}`);
  }
  return validated;
}

/** The request-side twin of `rawResultEnvelope`, for the both-directions
 * assertions below: two predicates, and neither may answer the other's
 * method. */
function rawRequestEnvelope(): unknown {
  return {
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: 1,
    params: {
      acs_version: "0.1.0",
      request_id: "8f14e45f-ceea-467e-bd5f-1d4d9a4e0c8f",
      timestamp: "2026-08-11T00:00:00Z",
      metadata: { agent_id: "agent-1", session_id: "6c616a11-495a-4f05-878a-c1bfaa29f0e5" },
      payload: { tool: { name: "Bash" }, arguments: { command: { value: "ls -la" } } },
    },
  };
}

// The post_tool_call half of the pair: its own envelope type, its own
// predicate, its own snapshot type, its own assembler. Nothing in this block
// reads or widens the pre_tool_call half -- the two snapshots share no
// member but envelope.budgets.
describe("assemblePostToolCallSnapshot -- the post_tool_call sibling", () => {
  it("assembles the post-tool snapshot, synthesizing tool_call.name", () => {
    const snapshot = assemblePostToolCallSnapshot(makeResultEnvelope(), EMPTY_SOURCE_LABELS);

    // tool_call.name is synthesized from payload.tool.name. ACS's result
    // payload has no tool_call member of its own, and AGT resolves
    // tool_name_from before policy runs -- without this the whole gate fails
    // closed on every call, pinned in test/redaction.test.ts.
    expect(snapshot).toEqual({
      envelope: { budgets: { tool_call_count: 0, token_count: 0, elapsed_seconds: 0, cost_usd: 0 } },
      tool_call: { name: "Bash" },
      tool_result: { outputs: [{ value: "TOKEN=ghp_ABCDEF123456" }] },
      input: { ifc: { source_labels: [] } },
    });
  });

  // The wire cannot supply the arguments at this step, and pretending
  // otherwise, by carrying the request's args forward, would be inventing
  // state this module does not have. Correlation would run through
  // request_id_ref, which nothing here reads.
  it("carries no tool_call.args -- the result payload has none to carry", () => {
    const snapshot = assemblePostToolCallSnapshot(makeResultEnvelope(), EMPTY_SOURCE_LABELS);

    expect("args" in snapshot.tool_call).toBe(false);
    expect(Object.keys(snapshot.tool_call)).toEqual(["name"]);
    expect(Object.keys(snapshot).sort()).toEqual(["envelope", "input", "tool_call", "tool_result"]);
  });

  // The same rule the request side applies to its arguments: AGT reads raw
  // values -- policy_target "$.tool_result.outputs[0].value" -- and ACS's
  // {value, provenance} wrapper does not survive into the snapshot.
  it("drops each output's provenance, keeping the raw value alone", () => {
    const snapshot = assemblePostToolCallSnapshot(
      makeResultEnvelope({
        outputs: [{ value: "TOKEN=ghp_ABCDEF123456", provenance: { provenance_id: "p1", origin: "tool_output" } }],
      }),
      EMPTY_SOURCE_LABELS,
    );

    expect(snapshot.tool_result.outputs).toEqual([{ value: "TOKEN=ghp_ABCDEF123456" }]);
  });

  // budgets.rego fails closed on a present-but-wrong-typed counter, and that
  // hazard is not specific to the request gate.
  it("always emits envelope.budgets with all four counters zeroed, as real zeros", () => {
    const snapshot = assemblePostToolCallSnapshot(makeResultEnvelope(), EMPTY_SOURCE_LABELS);

    for (const counter of Object.values(snapshot.envelope.budgets)) {
      expect(typeof counter).toBe("number");
    }
    expect(snapshot.envelope).toEqual({
      budgets: { tool_call_count: 0, token_count: 0, elapsed_seconds: 0, cost_usd: 0 },
    });
  });

  // One predicate per assembler, asserted in BOTH directions: a predicate
  // that answers `true` too readily is invisible otherwise. This is the
  // assertion that fails if the two predicates are ever replaced by one that
  // answers for both methods.
  it("answers no to a request envelope, and isToolCallRequest answers no to a result envelope", () => {
    const request = validateEnvelope(rawRequestEnvelope());
    const result = validateEnvelope(rawResultEnvelope());

    expect(isToolCallRequest(request)).toBe(true);
    expect(isToolCallResult(request)).toBe(false);

    expect(isToolCallResult(result)).toBe(true);
    expect(isToolCallRequest(result)).toBe(false);
  });

  // The precondition this assembler reads unconditionally: outputs. The
  // result payload's schema (hooks/tool-call-result.json) is checked by
  // validateEnvelope for this method exactly as the request payload's is for
  // its own, so assembly is never reached with the member ABSENT -- which is
  // as far as the schema goes, and no further: see the empty-array case below.
  it("is never reached with outputs absent: validateEnvelope rejects the payload first", () => {
    const raw = rawResultEnvelope() as { params: { payload: Record<string, unknown> } };
    delete raw.params.payload.outputs;

    expect(() => validateEnvelope(raw)).toThrow(/\/params\/payload\/outputs/);
  });

  // hooks/tool-call-result.json sets no `minItems`, so `outputs: []` is a
  // schema-VALID result payload: it passes validateEnvelope, narrows, and
  // reaches this assembler, which assembles an empty outputs array honestly
  // rather than inventing an element. AGT then finds nothing at
  // $.tool_result.outputs[0].value and fails CLOSED. Pinned because it is
  // wire-reachable and because "empty output" is exactly the shape someone
  // might later be tempted to answer with an allow -- a tenth fail-open.
  it("assembles an empty outputs array, and AGT fails closed on it", async () => {
    const snapshot = assemblePostToolCallSnapshot(makeResultEnvelope({ outputs: [] }), EMPTY_SOURCE_LABELS);
    expect(snapshot.tool_result.outputs).toEqual([]);

    const bridge = createDeploymentBridge("policy/manifest.yaml");
    const verdict = await bridge.evaluate("post_tool_call", snapshot);

    expect(verdict.decision).toBe("deny");
    expect(verdict.reason).toBe("runtime_error:path_missing");
  });

  // The high-value integration test, the result-gate twin of the pre-tool one
  // above: this snapshot is fed to the real AGT bridge at the point
  // mapping.yaml names for this method, and the stock redact rule fires. It
  // also proves the synthesized tool_call.name is doing its job -- without it
  // AGT answers deny/runtime_error:path_missing instead of a transform.
  //
  // NOT `EMPTY_SOURCE_LABELS`: this is the one test in this file that actually
  // reaches AGT's live IFC config through the real bridge, so it needs the
  // label the Guardian's own session seed would have supplied. IFC deny
  // outranks every other gate in
  // `agt_default.rego`'s severity ranking (its own header: "IFC deny >
  // confidence deny > budget deny > content_hash deny > egress deny >
  // pattern deny > drift warn > allow"), so a zero-label snapshot here would
  // deny with `ifc_clearance_violation` before the redact rule this test is
  // actually about ever runs.
  it("feeds a secret-bearing output through the real AGT bridge and gets the redaction transform", async () => {
    const snapshot = assemblePostToolCallSnapshot(makeResultEnvelope(), ["public"]);
    const bridge = createDeploymentBridge("policy/manifest.yaml");

    const verdict = await bridge.evaluate("post_tool_call", snapshot);

    expect(verdict.decision).toBe("transform");
    expect(verdict.reason).toBe("redaction_applied");
    expect(verdict.transform?.value).toBe("TOKEN=[REDACTED]");
  });
});

// The request-side and result-side envelope builders above, aliased under
// the names the session-state tests below use. Not new envelope-building
// logic -- makeEnvelope() and makeResultEnvelope() already build exactly
// what these need with no arguments.
const requestEnvelope = (): ToolCallRequestEnvelope => makeEnvelope();
const resultEnvelope = (): ToolCallResultEnvelope => makeResultEnvelope();

describe("session state in the snapshot", () => {
  it("puts source labels where AGT's stock IFC library actually reads them", () => {
    const snapshot = assemblePreToolCallSnapshot(requestEnvelope(), ["confidential"], "command");
    // policy/lib/agt_ifc.rego: input.snapshot.input.ifc.source_labels.
    // Its own test pins that input.snapshot.ifc.source_labels reads as [].
    expect(snapshot.input.ifc.source_labels).toEqual(["confidential"]);
    expect((snapshot as Record<string, unknown>).ifc).toBeUndefined();
  });

  it("carries an empty list rather than omitting the member", () => {
    const snapshot = assemblePreToolCallSnapshot(requestEnvelope(), EMPTY_SOURCE_LABELS, "command");
    expect(snapshot.input.ifc.source_labels).toEqual([]);
  });

  it("injects into the result gate's assembler too, once, in its own function", () => {
    const snapshot = assemblePostToolCallSnapshot(resultEnvelope(), ["secret"]);
    expect(snapshot.input.ifc.source_labels).toEqual(["secret"]);
  });

  it("copies the labels, so a snapshot cannot be edited through the caller's array", () => {
    const labels = ["secret"];
    const snapshot = assemblePreToolCallSnapshot(requestEnvelope(), labels, "command");
    labels.push("public");
    expect(snapshot.input.ifc.source_labels).toEqual(["secret"]);
  });

  it("leaves every pre-existing member of both snapshots exactly as it was", () => {
    const pre = assemblePreToolCallSnapshot(requestEnvelope(), EMPTY_SOURCE_LABELS, "command");
    // requestEnvelope() is makeEnvelope() under its alias here, and
    // makeEnvelope()'s own default toolName is "run_shell" (see its
    // definition above) -- not "Bash", which is resultEnvelope()'s default.
    expect(pre.tool_call.name).toBe("run_shell");
    expect(pre.envelope.budgets).toEqual({ tool_call_count: 0, token_count: 0, elapsed_seconds: 0, cost_usd: 0 });
    const post = assemblePostToolCallSnapshot(resultEnvelope(), EMPTY_SOURCE_LABELS);
    expect(post.tool_result.outputs).toHaveLength(1);
    expect((post as Record<string, unknown>).tool_call).toEqual({ name: "Bash" });
  });
});

/**
 * A request envelope built from an arbitrary tool name and arguments bag,
 * for the leaf/raw-command tests below. Named `toolCallRequestEnvelope`
 * rather than `requestEnvelope` -- that name is already bound above, as the
 * alias four IFC-label tests use, and this helper answers a different need:
 * an arbitrary tool shape rather than always `run_shell`/`command`.
 */
function toolCallRequestEnvelope(
  toolName: string,
  args: Record<string, unknown>,
  rawCommand?: string,
): ToolCallRequestEnvelope {
  const payload: Record<string, unknown> = {
    tool: { name: toolName },
    arguments: Object.fromEntries(Object.entries(args).map(([k, v]) => [k, { value: v }])),
  };
  if (rawCommand !== undefined) payload.raw_command = rawCommand;
  return {
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id: 1,
    params: {
      acs_version: "0.1.0",
      request_id: "11111111-1111-4111-8111-111111111111",
      timestamp: "2026-08-18T00:00:00Z",
      metadata: { session_id: "22222222-2222-4222-8222-222222222222" },
      payload,
    },
  } as unknown as ToolCallRequestEnvelope;
}

describe("one fixed snapshot leaf, whatever the tool calls its argument", () => {
  it("copies the named argument's value to the leaf the manifest targets", () => {
    const snapshot = assemblePreToolCallSnapshot(
      toolCallRequestEnvelope("WebFetch", { url: "https://docs.anthropic.com/x" }),
      ["public"],
      "url",
    );
    expect(snapshot.tool_call.args[POLICY_TARGET_LEAF]).toBe("https://docs.anthropic.com/x");
  });

  it("leaves the tool's own argument in place beside it", () => {
    const snapshot = assemblePreToolCallSnapshot(
      toolCallRequestEnvelope("WebFetch", { url: "https://docs.anthropic.com/x" }),
      ["public"],
      "url",
    );
    expect(snapshot.tool_call.args.url).toBe("https://docs.anthropic.com/x");
  });

  it("does the same for a shell tool, from the same one declaration", () => {
    const snapshot = assemblePreToolCallSnapshot(
      toolCallRequestEnvelope("Bash", { command: "echo hi" }),
      ["public"],
      "command",
    );
    expect(snapshot.tool_call.args[POLICY_TARGET_LEAF]).toBe("echo hi");
  });

  it("refuses a tool that already sends an argument by the leaf's own name, rather than overwriting it", () => {
    expect(() =>
      assemblePreToolCallSnapshot(
        toolCallRequestEnvelope("Bash", { command: "echo hi", [POLICY_TARGET_LEAF]: "something the host sent" }),
        ["public"],
        "command",
      ),
    ).toThrow(/acs_policy_target/);
  });

  it("refuses a call missing the argument its policy target was declared to live in", () => {
    expect(() =>
      assemblePreToolCallSnapshot(toolCallRequestEnvelope("Bash", { script: "echo hi" }), ["public"], "command"),
    ).toThrow(/"command"/);
  });

  it("refuses to assemble at all when the mapping declares no argument for this gate", () => {
    expect(() =>
      assemblePreToolCallSnapshot(toolCallRequestEnvelope("Bash", { command: "echo hi" }), ["public"], undefined),
    ).toThrow(/policy_target_argument/);
  });
});

describe("the raw command is always on the snapshot, present or empty", () => {
  it("carries what the envelope sent", () => {
    const snapshot = assemblePreToolCallSnapshot(
      toolCallRequestEnvelope("Bash", { command: "curl https://exfil.test/x" }, "curl https://exfil.test/x"),
      ["public"],
      "command",
    );
    expect(snapshot.tool_call.raw_command).toBe("curl https://exfil.test/x");
  });

  // A manifest-declared annotator's own `from` path must resolve or AGT denies
  // the whole call on runtime_error:path_missing before the annotator is ever
  // dispatched -- measured, with zero annotator calls. An absent raw_command
  // would therefore make every fetch a total deny wearing a runtime-error
  // reason.
  it("carries an empty string when the envelope sent none", () => {
    const snapshot = assemblePreToolCallSnapshot(
      toolCallRequestEnvelope("WebFetch", { url: "https://docs.anthropic.com/x" }),
      ["public"],
      "url",
    );
    expect(snapshot.tool_call.raw_command).toBe("");
  });
});
