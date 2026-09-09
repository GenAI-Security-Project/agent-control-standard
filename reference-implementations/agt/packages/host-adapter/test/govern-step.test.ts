import { describe, expect, it } from "bun:test";
import type { AuditEvent, AuditSink } from "../src/audit-sink.ts";
import type { Hookmap, HookmapRequestHookEntry, HookmapResultHookEntry } from "../src/build-envelope.ts";
import { governStep, governsTool, type GovernedStep } from "../src/govern-step.ts";
import { GuardianTimeoutError, type DecisionOrFailure, type GuardianClient } from "../src/guardian-client.ts";
import type { ResolvedSessionConfig } from "../src/handshake.ts";
import type { SessionConfig } from "../src/session-config.ts";

/**
 * `governStep` lives outside any host shim, so a second host reuses it
 * without reproducing its fail-open guarantees -- those are documented once,
 * in govern-step.ts's own header, rather than restated here to go stale
 * separately. So the properties are pinned here, at the collaborator, and
 * not only end to end through one host's subprocess
 * (hosts/claude-code/test/posture.test.ts, which still proves the whole thing
 * against a real Guardian).
 *
 * A deliberately synthetic hookmap, naming no real host's fields: this
 * function is host-agnostic, and a test written against the shipped Claude Code
 * hookmap would not catch it quietly becoming otherwise.
 */
const ON_STEP: HookmapRequestHookEntry = {
  acs_method: "steps/toolCallRequest",
  tool_name: "$.tool_name",
  arguments: "$.tool_input",
  // A hook's decisions belong to the hook, so this fixture's one gate
  // carries its own block.
  decisions: {
    allow: { output: { outcome: { value: "go" }, note: { from: "reasoning", type: "string" } } },
    deny: { output: { outcome: { value: "stop" }, note: { from: "reasoning", type: "string" } } },
  },
};

const hookmap: Hookmap = { host: "test-host", hooks: { OnStep: ON_STEP } };

const payload = { session_id: "sess-1", tool_name: "Bash", tool_input: { command: "ls -la" } };

/**
 * A result gate on the same synthetic host: a gate that sees what a step
 * produced, and therefore the one kind of gate where a decision has to be able
 * to replace an output. Its `outputs` block is what makes it one -- read off the
 * entry's shape, never off the event name.
 *
 * `text` is prose and `truncated` is a flag, deliberately side by side, because
 * the property under test is which of the two a replacement can be built for.
 */
const ON_RESULT: HookmapResultHookEntry = {
  acs_method: "steps/toolCallResult",
  tool_name: "$.tool_name",
  outputs: { from: "$.step_result.text", within: "$.step_result" },
  exit_status: { literal: "success" },
  decisions: {
    allow: { output: { outcome: { value: "go" } } },
    deny: { output: { outcome: { value: "stop" }, replacing_output: { from: "applied_output" } } },
    // The withholdings a result gate has beyond `deny`. Declared, because an
    // entry a hookmap does not declare is a render throw and a posture's
    // answer to it -- which is a different property, pinned elsewhere in this
    // file. What these two are here to pin is that an ask and a defer reaching
    // this kind of gate carry the replacement their entry renders from, the
    // same as a deny: this synthetic host has no more idea what to do with a
    // question about a formed output than a real one does.
    ask: { output: { outcome: { value: "stop" }, replacing_output: { from: "applied_output" } } },
    defer: { output: { outcome: { value: "stop" }, replacing_output: { from: "applied_output" } } },
    // And the other kind of replacement: a rewrite delivers, so its entry says
    // "go" while carrying one. The pair is what makes it possible to tell a
    // withholding from a redaction in the rendered output below.
    modify: { output: { outcome: { value: "go" }, replacing_output: { from: "applied_output" } } },
  },
};

const resultPayload = {
  session_id: "sess-1",
  tool_name: "Bash",
  step_result: { text: "TOKEN=ghp_ABCDEF123456", truncated: false },
};

function recordingSink(): { sink: AuditSink; events: AuditEvent[] } {
  const events: AuditEvent[] = [];
  return {
    sink: {
      path: "test",
      write: (event) => {
        events.push(event);
        return true;
      },
    },
    events,
  };
}

/**
 * The posture arm of a recorded event, or a throw naming what turned up
 * instead. `governStep` writes both arms -- a posture answering a failure,
 * and a `tools` skip -- so the assertions that read `failure` or
 * `session_failure` have to say which one they mean, and a test whose entry
 * came back the other kind should fail as itself rather than as a confusing
 * `undefined` diff.
 */
function postureEventAt(events: AuditEvent[], index: number): Extract<AuditEvent, { outcome: "proceeded" | "blocked" }> {
  const event = events[index];
  if (event === undefined || event.outcome === "ungoverned") {
    throw new Error(`expected a posture-resolved audit entry at [${index}], got ${JSON.stringify(event)}`);
  }
  return event;
}

const NEGOTIATED = (posture: "proceed" | "deny"): SessionConfig => ({
  timeout_config: { default_ms: 5000 },
  on_decision_failure: posture,
});

/** A Guardian that answers every request with `answer`, and never posts. */
function answering(answer: DecisionOrFailure): GuardianClient {
  return {
    requestDecision: () => Promise.resolve(answer),
    post: () => Promise.reject(new Error("governStep must not use the wire primitive")),
  };
}

/**
 * `scopedTool` is spelled as its own optional override rather than folded into
 * a partial `GovernStepInput`, because absent is a case under test in its own
 * right: Claude Code's shim never passes it, and a gate that declares a
 * `tools` list refuses a caller that does not. A helper that always supplied
 * one would make both of those unreachable from this suite.
 */
type Overrides = {
  hookmap?: Hookmap;
  hookEventName?: string;
  payload?: Record<string, unknown>;
  scopedTool?: string;
};

/** `governStep`, with this suite's fixtures as the defaults. */
function governRaw(
  guardian: GuardianClient,
  audit: AuditSink,
  session: ResolvedSessionConfig = { config: NEGOTIATED("proceed"), failure: undefined },
  overrides: Overrides = {},
): Promise<GovernedStep> {
  return governStep({
    hookEventName: overrides.hookEventName ?? "OnStep",
    payload: overrides.payload ?? payload,
    hookmap: overrides.hookmap ?? hookmap,
    guardian,
    session,
    sessionId: "sess-1",
    audit,
    scopedTool: overrides.scopedTool,
  });
}

/**
 * The same call, narrowed to the steps this gate actually governs.
 *
 * `governStep` has a third way out: a step whose tool the gate's own `tools`
 * list does not name comes back `{stage: "ungoverned", decision: null}` --
 * and none of the fixtures above declares a `tools` list, so no test using
 * this helper can produce one. Asked here, once, rather than at each of the
 * assertions below that read `.decision`: those tests are about what
 * happened to a decision, and making every one of them narrow a case its
 * fixture cannot reach would be noise that hides the one thing they are each
 * about. The tests that are about the skip call `governRaw` and assert on
 * the whole discriminated union.
 */
async function govern(
  guardian: GuardianClient,
  audit: AuditSink,
  session: ResolvedSessionConfig = { config: NEGOTIATED("proceed"), failure: undefined },
  overrides: Overrides = {},
): Promise<Exclude<GovernedStep, { stage: "ungoverned" }>> {
  const governed = await governRaw(guardian, audit, session, overrides);
  if (governed.stage === "ungoverned") {
    throw new Error(
      `govern(): this fixture's gate declares no "tools" list, so it governs every tool -- an "ungoverned" ` +
        `answer here means the skip fired on a hookmap that never scoped itself, which is a defect in ` +
        `governStep and not a case for this helper's caller to handle`,
    );
  }
  return governed;
}

describe("governStep — a decision that arrived", () => {
  it("renders it and reports the guardian as the stage, auditing nothing", async () => {
    const { sink, events } = recordingSink();
    const governed = await govern(
      answering({ decisionArrived: true, decision: { decision: "deny", reasoning: "blocked by policy" } }),
      sink,
    );

    expect(governed.stage).toBe("honoured");
    expect(governed.decision.decision).toBe("deny");
    expect(governed.output).toEqual({ outcome: "stop", note: "blocked by policy" });
    // Nothing failed to be delivered, so nothing is recorded as a failure.
    expect(events).toEqual([]);
  });

  // A decision that arrives always outranks the posture: the posture here is
  // `deny`, so a step answered by the posture would be blocked -- and this
  // arriving `allow` must still be honoured. The mirror case (an arriving deny
  // under a `proceed` posture) is pinned end to end in posture.test.ts.
  it("outranks the negotiated posture, in both directions", async () => {
    const { sink, events } = recordingSink();
    const governed = await govern(
      answering({ decisionArrived: true, decision: { decision: "allow" } }),
      sink,
      { config: NEGOTIATED("deny"), failure: undefined },
    );

    expect({ stage: governed.stage, decision: governed.decision.decision }).toEqual({
      stage: "honoured",
      decision: "allow",
    });
    expect(events).toEqual([]);
  });

  // validateDecision runs on the arriving decision, and its substitutions
  // are decisions, not failures: an expired `ask` becomes its own timeout
  // disposition rather than reaching the posture. The stage stays
  // "honoured" because a decision did arrive and was honoured.
  it("puts it through the host's own validation without changing the stage", async () => {
    const { sink, events } = recordingSink();
    const governed = await govern(
      answering({
        decisionArrived: true,
        decision: {
          decision: "ask",
          ask_details: { approver: "security-team", question: "run this?", timeout_seconds: 0 },
        },
      }),
      sink,
    );

    expect({ stage: governed.stage, decision: governed.decision.decision }).toEqual({
      stage: "honoured",
      decision: "deny",
    });
    expect(events).toEqual([]);
  });
});

describe("governStep — the three failure stages name three different incidents", () => {
  // "request": nothing was ever asked of anything, so the audit reasoning
  // must not blame a Guardian that was never contacted. This wiring -- a
  // build failure is the request stage -- is pinned directly here, at the
  // collaborator, rather than only derived by inspecting a local variable's
  // state inside a catch block somewhere else.
  it("files a request that could not be built under \"request\", and never reaches the Guardian", async () => {
    const { sink, events } = recordingSink();
    const governed = await govern(
      answering({ decisionArrived: true, decision: { decision: "allow" } }),
      sink,
      { config: NEGOTIATED("proceed"), failure: undefined },
      // A hookmap path that does not resolve against this payload:
      // buildEnvelope throws. A hook with no hookmap entry at all is a
      // different case, entirely outside the posture's reach -- see the test
      // below.
      { hookmap: { ...hookmap, hooks: { OnStep: { ...ON_STEP, tool_name: "$.no_such_field" } } } },
    );

    expect(governed.stage).toBe("request");
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      posture: "proceed",
      posture_source: "negotiated",
      outcome: "proceeded",
      // Never an ACS method, because none was ever determined.
      method: null,
      rpc_id: null,
      failure: { kind: "host_configuration" },
    });
    expect(governed.decision.reasoning).toContain("no decision was ever sought");
  });

  // Every render (the arriving decision's and the posture's) goes through the
  // hook's own decisions block, so a hook the hookmap does not map has
  // nothing to express either answer through.
  //
  // So it throws before this step is asked about or audited, and the caller
  // answers it the way it answers a hookmap that will not load (exit 2).
  it("throws, auditing nothing, for a hook this hookmap does not map -- it cannot express an answer for one", async () => {
    const { sink, events } = recordingSink();

    await expect(
      govern(answering({ decisionArrived: true, decision: { decision: "allow" } }), sink, undefined, {
        hookEventName: "NotInTheHookmap",
      }),
    ).rejects.toThrow(/no entry for hook "NotInTheHookmap"/);

    // Nothing proceeded, so nothing claims to have proceeded.
    expect(events).toEqual([]);
  });

  // The guard's one real hole: `hookEventName` is host-supplied -- it
  // arrives on the host's stdin -- and `hooks["toString"]` resolves to an
  // inherited Object.prototype function, which is not `undefined`. With a
  // bare index the guard passes for a prototype-named event, buildEnvelope
  // throws (a function is not a hook entry), the posture writes
  // `outcome: "proceeded"`, and only then does renderDecision throw -- the exact
  // durable false record the guard exists to prevent, reachable without touching
  // the hookmap at all. Asserted on the audit log rather than only on the throw,
  // because both spellings throw and only one of them audits.
  //
  // Mutation-tested: with `hasOwnProperty` reverted to a bare index, this case
  // fails on `events` (one "proceeded" entry) while the plain unmapped-hook case
  // above still passes.
  it.each(["toString", "constructor", "valueOf", "__proto__"])(
    "throws, auditing nothing, for the prototype-named hook %p -- a bare index would have let it through",
    async (hookEventName) => {
      const { sink, events } = recordingSink();

      await expect(
        govern(answering({ decisionArrived: true, decision: { decision: "allow" } }), sink, undefined, {
          hookEventName,
        }),
      ).rejects.toThrow(/governStep: hookmap has no entry for hook/);

      expect(events).toEqual([]);
    },
  );

  it("files no decision arriving under \"delivery\", carrying the failure the client reported", async () => {
    const { sink, events } = recordingSink();
    const governed = await govern(answering({ decisionArrived: false, failure: new GuardianTimeoutError(120) }), sink);

    expect(governed.stage).toBe("delivery");
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      outcome: "proceeded",
      method: "steps/toolCallRequest",
      failure: { kind: "timeout" },
    });
    expect(postureEventAt(events, 0).failure.message).toContain("120ms");
    expect(events[0]?.rpc_id).toBeString();
  });

  // A refusal is a delivery-stage event like any other -- nothing here
  // branches on it, which is the property the module header claims -- but it
  // is not a delivery FAILURE, so the posture must not answer it. The posture
  // here is `proceed`, deliberately: under `deny` this passes unfixed, and the
  // rendered output is the half a host actually writes.
  it("blocks a refused step under a proceed posture, and renders the deny", async () => {
    const { sink, events } = recordingSink();
    const governed = await govern(
      answering({ decisionArrived: false, failure: { code: -32020, message: "evaluation failed" } }),
      sink,
    );

    expect(governed.stage).toBe("delivery");
    expect(governed.decision.decision).toBe("deny");
    expect(governed.output).toEqual({ outcome: "stop", note: governed.decision.reasoning });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      posture: "proceed",
      outcome: "blocked",
      method: "steps/toolCallRequest",
      failure: { kind: "refused" },
    });
  });

  // "render": a decision did arrive and was honoured in principle; only this
  // host's expression of it failed. Auditing that as "no decision arrived" would
  // send an incident reviewer to a Guardian that answered correctly.
  it("files a decision this hookmap cannot express under \"render\", and still produces an output", async () => {
    const { sink, events } = recordingSink();
    const governed = await govern(answering({ decisionArrived: true, decision: { decision: "quarantine" } }), sink);

    expect(governed.stage).toBe("render");
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ outcome: "proceeded", failure: { kind: "decision_unrenderable" } });
    expect(governed.decision.reasoning).toMatch(/a decision arrived .* and was honoured/i);
    // The posture's own decision is renderable by construction, so there is
    // always something on the way out.
    expect(governed.output).toEqual({ outcome: "go", note: governed.decision.reasoning });
  });
});

/**
 * A fail-open closed from the side that prevents it. A `deny` at a result
 * gate withholds by carrying a replacement for the output, and building that
 * replacement can fail: a leaf that is not prose is a leaf no replacement can
 * be expressed for. Asked at the render instead, that failure would arrive
 * with the decision already in hand and land in the render stage's catch, so
 * the delivery posture would answer it -- under `proceed`, the full
 * unredacted output delivered, the Guardian's deny dropped, and an audit
 * entry saying the decision "was honoured". With `outputs.from` on a boolean
 * leaf and a Guardian answering `deny`, that route produces exit 0,
 * `outcome: "proceeded"`, `failure.kind: "decision_unrenderable"`.
 *
 * So it is asked before a decision is sought, and the assertions below are
 * about the order as much as the refusal: a Guardian that was never called
 * and an audit log with nothing in it are what make "no decision was
 * dropped" a property of the control flow rather than of the message.
 */
describe("governStep — a result gate whose named output no replacement can be built for", () => {
  /** A Guardian that would answer `deny`, and records whether it was ever asked.
   * The deny matters: it is the decision that would have been dropped. */
  function askedGuardian(): { guardian: GuardianClient; asked: () => number } {
    let asks = 0;
    return {
      guardian: {
        requestDecision: () => {
          asks += 1;
          return Promise.resolve({
            decisionArrived: true,
            decision: { decision: "deny", reasoning: "secret in output" },
          } satisfies DecisionOrFailure);
        },
        post: () => Promise.reject(new Error("governStep must not use the wire primitive")),
      },
      asked: () => asks,
    };
  }

  const resultHookmap = (from: string): Hookmap => ({
    host: "test-host",
    hooks: { OnResult: { ...ON_RESULT, outputs: { from, within: "$.step_result" } } },
  });

  it("refuses before the Guardian is asked, under a posture that would otherwise have proceeded", async () => {
    const { sink, events } = recordingSink();
    const { guardian, asked } = askedGuardian();

    await expect(
      govern(guardian, sink, { config: NEGOTIATED("proceed"), failure: undefined }, {
        hookEventName: "OnResult",
        payload: resultPayload,
        // Present, resolvable, and a flag: the envelope builds, the decision
        // arrives, and nothing can be patched in its place.
        hookmap: resultHookmap("$.step_result.truncated"),
      }),
    ).rejects.toThrow(/no replacement can be built for the output its hookmap entry names/);

    // The two assertions the message cannot make: nothing was asked, so no
    // decision existed to be dropped, and nothing was audited, so no entry
    // claims a step proceeded.
    expect(asked()).toBe(0);
    expect(events).toEqual([]);
  });

  // The refusal has to be about the leaf and not about the gate: a result gate
  // whose named leaf is prose governs exactly as before, and its deny withholds.
  it("lets a gate whose named leaf is prose govern, and its deny still withholds", async () => {
    const { sink, events } = recordingSink();
    const { guardian, asked } = askedGuardian();

    const governed = await govern(guardian, sink, undefined, {
      hookEventName: "OnResult",
      payload: resultPayload,
      hookmap: resultHookmap("$.step_result.text"),
    });

    expect({ stage: governed.stage, decision: governed.decision.decision }).toEqual({
      stage: "honoured",
      decision: "deny",
    });
    // The whole object, because a replacement missing a sibling field is the one
    // a host discards while delivering the original.
    expect(governed.output).toEqual({
      outcome: "stop",
      replacing_output: { text: "[OUTPUT WITHHELD BY POLICY]", truncated: false },
    });
    expect({ asked: asked(), events }).toEqual({ asked: 1, events: [] });
  });

  // The failure that stays with the posture, and the distinction that keeps the
  // refusal above from swallowing it: a payload that does not carry what the
  // hookmap describes is `buildEnvelope`'s report, at stage "request", where a
  // host firing one hook for several tools is the deployment's own negotiated
  // question rather than a broken deployment.
  it("leaves a payload that carries no such leaf to the posture, at stage \"request\"", async () => {
    const { sink, events } = recordingSink();
    const { guardian, asked } = askedGuardian();

    const governed = await govern(guardian, sink, undefined, {
      hookEventName: "OnResult",
      payload: { session_id: "sess-1", tool_name: "Bash", step_result: { truncated: false } },
      hookmap: resultHookmap("$.step_result.text"),
    });

    expect(governed.stage).toBe("request");
    expect(asked()).toBe(0);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ outcome: "proceeded", failure: { kind: "host_configuration" } });
  });
});

/**
 * The dispositions a result gate cannot carry out, and the reason they belong
 * here rather than only in one host's suite: nothing about "an output that
 * already exists cannot be held pending, and cannot be asked about" is specific
 * to a host. A gate that decides whether a step RUNS answers an ask by asking
 * and a defer by waiting; a gate that sees what a step PRODUCED has neither
 * move available, so both are withholdings there, and a withholding carries a
 * shape-preserving replacement of the output or it withholds nothing.
 *
 * The shape of the fail-open this closes: with these two treated as deliveries,
 * a host's mapping either has no entry for them -- so the render throws, the
 * render stage catches, and a `proceed` posture delivers the very output a
 * Guardian raised a question about, audited as a decision that could not be
 * rendered -- or it has an entry that renders a block with an empty wrapper,
 * which reports a withholding and performs none. Both are the same delivery.
 *
 * `NEGOTIATED("proceed")` is the posture throughout, deliberately: it is the
 * one under which the gap was a delivery, so a `deny` posture here would let
 * these tests pass on the unfixed code.
 *
 * Both fixtures are WELL-FORMED and UNEXPIRED, which is what makes them reach a
 * render as an ask and a defer at all. `validateDecision` substitutes a deny for
 * either one whose window it cannot read or has already passed, and a deny
 * withholds through machinery that was never in question -- so a bare
 * `{decision: "ask"}` here would pass against the unfixed rule and pin nothing.
 */
describe("governStep — an ask or a defer at a gate where the step has already run", () => {
  const resultHookmap: Hookmap = { host: "test-host", hooks: { OnResult: ON_RESULT } };

  const withheld = { outcome: "stop", replacing_output: { text: "[OUTPUT WITHHELD BY POLICY]", truncated: false } };

  it("withholds the output for an ask inside its window, honoured rather than postured", async () => {
    const { sink, events } = recordingSink();
    const governed = await govern(
      answering({
        decisionArrived: true,
        decision: {
          decision: "ask",
          reasoning: "a human should see this output first",
          ask_details: { approver: "security-team", question: "release this?", timeout_seconds: 300 },
        },
      }),
      sink,
      { config: NEGOTIATED("proceed"), failure: undefined },
      { hookEventName: "OnResult", payload: resultPayload, hookmap: resultHookmap },
    );

    // "honoured" and still an ask: the decision that arrived is not rewritten
    // into a deny -- what changes is only what it renders as, which is the
    // mapping's business. An audit entry here would mean a posture answered.
    expect({ stage: governed.stage, decision: governed.decision.decision }).toEqual({
      stage: "honoured",
      decision: "ask",
    });
    // The whole object, because a replacement missing a sibling field is the one
    // a host discards while delivering the original.
    expect(governed.output).toEqual(withheld);
    expect(events).toEqual([]);
  });

  it("withholds the output for a defer inside its window, having nowhere to hold it", async () => {
    const { sink, events } = recordingSink();
    const governed = await govern(
      answering({
        decisionArrived: true,
        decision: {
          decision: "defer",
          reasoning: "waiting on an out-of-band approval",
          defer_details: {
            reason: "awaiting change ticket",
            resolution_method: "external",
            resolution_timeout_ms: 300_000,
          },
        },
      }),
      sink,
      { config: NEGOTIATED("proceed"), failure: undefined },
      { hookEventName: "OnResult", payload: resultPayload, hookmap: resultHookmap },
    );

    expect({ stage: governed.stage, decision: governed.decision.decision }).toEqual({
      stage: "honoured",
      decision: "defer",
    });
    expect(governed.output).toEqual(withheld);
    expect(events).toEqual([]);
  });

  // The other side of the same rule, and the one that would fail if "withholds"
  // had been written as "everything but allow": a `modify` delivers a
  // replacement it built itself, and must not have it overwritten by the
  // withholding one. Without this, a rule that withheld for `modify` too would
  // pass every test above while silently turning every redaction into a
  // withholding -- the output replaced by a policy marker instead of by the
  // redacted text the Guardian asked for.
  it("leaves a modify's own replacement alone", async () => {
    const { sink, events } = recordingSink();
    const governed = await govern(
      answering({
        decisionArrived: true,
        decision: {
          decision: "modify",
          reasoning: "redaction_applied",
          modifications: { redactions: [{ path: "/outputs/0/value", replacement: "TOKEN=[REDACTED]" }] },
        },
      }),
      sink,
      { config: NEGOTIATED("proceed"), failure: undefined },
      { hookEventName: "OnResult", payload: resultPayload, hookmap: resultHookmap },
    );

    expect(governed.stage).toBe("honoured");
    expect(governed.output).toEqual({
      outcome: "go",
      replacing_output: { text: "TOKEN=[REDACTED]", truncated: false },
    });
    expect(events).toEqual([]);
  });
});

describe("governStep — the session's failure travels beside the step's own", () => {
  it("records both, under their own kinds, without merging them", async () => {
    const { sink, events } = recordingSink();
    await govern(answering({ decisionArrived: false, failure: new GuardianTimeoutError(5000) }), sink, {
      config: NEGOTIATED("deny"),
      failure: new Error("Unable to connect. Is the computer able to access the url?"),
    });

    expect(events[0]).toMatchObject({
      posture: "deny",
      posture_source: "negotiated",
      outcome: "blocked",
      failure: { kind: "timeout" },
      session_failure: { kind: "handshake_failed" },
    });
  });

  it("applies the ACS default when no config was negotiated at all", async () => {
    const { sink, events } = recordingSink();
    const governed = await govern(answering({ decisionArrived: false, failure: new Error("dead") }), sink, {
      config: undefined,
      failure: undefined,
    });

    expect(governed.decision.decision).toBe("allow");
    expect(events[0]).toMatchObject({ posture: "proceed", posture_source: "default", outcome: "proceeded" });
    expect(postureEventAt(events, 0).session_failure).toBeUndefined();
  });

  // §6.4's MUST outranks the posture: a fail-open proceed that could not be
  // recorded is a silent bypass, so it becomes a deny. Every path out of
  // governStep that has no decision goes through the one function that enforces
  // this, which is what makes it unskippable rather than remembered.
  it("blocks rather than proceeding when the entry could not be written", async () => {
    const unwritable: AuditSink = { path: "test", write: () => false };
    const governed = await govern(answering({ decisionArrived: false, failure: new Error("dead") }), unwritable);

    expect(governed.decision.decision).toBe("deny");
    expect(governed.decision.reason_codes).toEqual(["decision_failure", "audit_unavailable"]);
    expect(governed.output).toEqual({ outcome: "stop", note: governed.decision.reasoning });
  });
});

/**
 * `tools` is shared hookmap vocabulary this package shape-checks
 * (`assertToolsWellFormed`) and normalises (`normalizeTools`). Which tool a
 * gate governs is `governsTool`'s question, and `governStep` asks it before
 * it does anything else -- a third host written from an existing shim that
 * skipped this check would govern every tool regardless of the list, and the
 * envelope that follows is one the deployment's policy configuration cannot
 * express a target for, answered by the negotiated posture.
 *
 * Both shims also ask it a call earlier, which is what makes an out-of-scope
 * tool cost no session validation and no handshake either -- that half is
 * pinned in each host's own suite (hosts/opencode/test/request-gate.test.ts
 * and result-gate.test.ts). What is pinned here is the half a shim cannot
 * provide: that a shim which never asks still skips.
 *
 * Which tool it asks about is the caller's to say. Every scoped case below
 * therefore tells `governStep` its tool, the way a shim that already scoped
 * on one does; the untold cases are the two that matter on their own -- a
 * gate declaring no list (Claude Code's, which has nothing to tell) and a
 * gate declaring one (refused outright, in its own describe block below).
 */
describe("governStep — a gate governs only the tools its hookmap entry names", () => {
  /**
   * A Guardian that fails the test by being asked at all, and an audit sink
   * that records what it was told. Both assertions are about absence, so both
   * collaborators have to be able to report a call that should not happen.
   */
  function unaskedGuardian(): { guardian: GuardianClient; asked: () => number } {
    let asks = 0;
    return {
      guardian: {
        requestDecision: () => {
          asks += 1;
          return Promise.resolve({
            decisionArrived: true,
            decision: { decision: "allow" },
          } satisfies DecisionOrFailure);
        },
        post: () => Promise.reject(new Error("governStep must not use the wire primitive")),
      },
      asked: () => asks,
    };
  }

  /** The request-gate fixture, scoped to one tool name the payloads below can miss. */
  const scoped = (tools: string[]): Hookmap => ({
    host: "test-host",
    hooks: { OnStep: { ...ON_STEP, tools } },
  });

  it("returns an empty output for a tool the list does not name, contacting no Guardian and auditing the skip", async () => {
    const { sink, events } = recordingSink();
    const { guardian, asked } = unaskedGuardian();

    const governed = await governRaw(guardian, sink, undefined, { hookmap: scoped(["Write"]), scopedTool: "Bash" });

    // The whole answer, asserted as one object rather than field by field:
    // an empty output is what a host applies (no keys to write, no keys to
    // merge), `null` is what says no decision was sought, and "ungoverned"
    // is what a caller narrows on.
    expect(governed).toEqual({ output: {}, decision: null, stage: "ungoverned" });
    // No round trip -- there is nothing to ask about a step this gate
    // declines to govern.
    expect(asked()).toBe(0);
    // But it IS recorded, and the whole entry is asserted rather than only
    // its outcome. A skip is not a failure, so this must not read as one:
    // no `failure`, no `posture`, no `posture_source`, because none of the
    // three happened. What it must carry is the pair that makes hookmap
    // drift readable -- the tool that arrived and the list that declined it
    // -- since a `tools` list that stops matching the names a host sends
    // otherwise presents as a quiet session rather than an ungoverned one.
    expect(events).toEqual([
      {
        session_id: "sess-1",
        // The gate's own ACS method, not the host's "OnStep": this log's
        // readers know ACS and nothing else.
        method: "steps/toolCallRequest",
        rpc_id: null,
        outcome: "ungoverned",
        ungoverned: { tool: "Bash", tools: ["Write"] },
      },
    ]);
  });

  it("governs a tool the list does name", async () => {
    const { sink, events } = recordingSink();
    const { guardian, asked } = unaskedGuardian();

    const governed = await governRaw(guardian, sink, undefined, {
      hookmap: scoped(["Bash", "Write"]),
      scopedTool: "Bash",
    });

    expect(governed.stage).toBe("honoured");
    // Nothing audited: a governed step whose decision arrived is neither a
    // fail-open nor a skip. This is the control that keeps the entry above
    // from being something every call writes.
    expect({ asked: asked(), events }).toEqual({ asked: 1, events: [] });
  });

  /**
   * Claude Code's own case, and the reason this is a separate test rather
   * than an assumption: hosts/claude-code/claude-code.hookmap.yaml declares
   * no `tools` key at either of its gates, because each has its own
   * settings.json matcher already scoping it -- `^(Bash|WebFetch)$` at the
   * request gate, `^Bash$` at the result gate. What this row measures is
   * that pair
   * reaching `governStep` and coming back governed -- not that `governsTool`
   * reads an absent list correctly, which it never gets asked here (see the
   * told companion test below, which is where that half is pinned).
   *
   * Untold, and that is half the point: Claude Code's shim passes no
   * `scopedTool`, because there is no list for it to be scoped against. So
   * this fixture declares no `tools` and tells nothing, which is exactly the
   * pair Claude Code presents -- and the refusal that a caller must name a
   * tool for a scoped gate must not fire on it. (The same pair against Claude
   * Code's real hookmap, both gates, is pinned in
   * hosts/claude-code/test/hook.test.ts.)
   */
  it("governs every tool when the entry declares no tools list at all", async () => {
    const { sink, events } = recordingSink();
    const { guardian, asked } = unaskedGuardian();

    const governed = await governRaw(guardian, sink, undefined, {
      // Deliberately a name nothing anywhere lists: the claim is "every
      // tool", not "the ones some other fixture happens to name".
      payload: { ...payload, tool_name: "a-tool-no-hookmap-in-this-repo-names" },
    });

    expect(governed.stage).toBe("honoured");
    expect({ asked: asked(), events }).toEqual({ asked: 1, events: [] });
  });

  /**
   * The told half of the same claim, and it exists because the untold test
   * above does not measure what its own comment says. That comment warns
   * against "a skip that treated an absent list as 'no tools'" -- but with
   * nothing told, the skip short-circuits on `scopedTool !== undefined` and
   * `governsTool` is never reached, so mutating it to exactly that wrong form
   * (`tools !== undefined && tools.includes(tool)`) leaves the test above
   * passing. That mutation fails three tests in this file, none of them the
   * one warning about it.
   *
   * Told, with no list declared, `governsTool` is consulted and has to answer
   * "governs" for a name no hookmap anywhere lists. That is the assertion the
   * warning was always describing, and it dies under that mutation.
   */
  it("governs a told tool when the entry declares no tools list — the predicate is reached and answers true", async () => {
    const { sink, events } = recordingSink();
    const { guardian, asked } = unaskedGuardian();

    const UNLISTED = "a-tool-no-hookmap-in-this-repo-names";
    // The predicate directly, so the mutation is caught even if the skip's own
    // short-circuit is ever restructured again.
    expect(governsTool(hookmap, "OnStep", UNLISTED)).toBe(true);

    const governed = await governRaw(guardian, sink, undefined, {
      payload: { ...payload, tool_name: UNLISTED },
      scopedTool: UNLISTED,
    });

    expect(governed.stage).toBe("honoured");
    expect({ asked: asked(), events }).toEqual({ asked: 1, events: [] });
  });

  /**
   * A tool name the hookmap's own path cannot read is unreadable, not out of
   * scope -- it is not a scoping question at all, which is what this table
   * measures. Nothing scopes off the payload: the caller tells `governStep`
   * which tool it checked, so an unreadable `tool_name` can no longer produce
   * a skip by any route, and what remains is whatever `buildEnvelope` makes
   * of it.
   *
   * All three cases are covered because "whatever already handles it" is not
   * one mechanism: an absent or non-string name is a `buildEnvelope` throw
   * the posture answers, audited; an empty name is not -- `buildEnvelope`
   * checks the type and not the length, so the step is asked about and
   * governed. That distinction is pinned here so it stays a property of the
   * code rather than of a paragraph.
   *
   * The told tool is listed in every row, deliberately: the gate governs
   * this step on the caller's own word, so any row that is not governed or
   * audited is a step this gate said it governs and then dropped.
   */
  it("does not skip a step whose tool name the hookmap's path cannot read — unreadable is not out of scope", async () => {
    const rows: Record<string, unknown>[] = [];
    for (const [label, toolName] of [
      ["absent", undefined],
      ["a non-string", 42],
      ["the empty string", ""],
    ] as const) {
      const { sink, events } = recordingSink();
      const { guardian, asked } = unaskedGuardian();
      const payload: Record<string, unknown> = { session_id: "sess-1", tool_input: { command: "ls -la" } };
      if (toolName !== undefined) {
        payload.tool_name = toolName;
      }

      const governed = await governRaw(guardian, sink, undefined, {
        hookmap: scoped(["Bash"]),
        payload,
        scopedTool: "Bash",
      });

      // What each audit entry says, not merely that there is one: asserting
      // only `{outcome: "proceeded", failure: {kind: "host_configuration"}}`
      // for a single case would leave "an entry was written" pinned while
      // its contents stayed free, which is the half that says the incident
      // was filed correctly. A posture that audited the wrong outcome, or
      // blamed a Guardian never contacted, would pass a weaker assertion.
      rows.push({
        label,
        stage: governed.stage,
        asked: asked(),
        // `in`, not `?.`: `failure` is a field of one arm of `AuditEvent`,
        // so a skip entry has no such property rather than an undefined one
        // -- and this table is asserting that none of these rows IS a skip.
        audited: events.map((event) => ({
          outcome: event.outcome,
          failureKind: "failure" in event ? event.failure.kind : null,
        })),
      });
    }

    // Not one of them is `stage: "ungoverned"` with nothing asked and nothing
    // audited, which is the single shape this test exists to refuse.
    expect(rows).toEqual([
      // The posture answers a request that could not be built, and records it
      // as a host-side configuration fault -- never as a delivery failure,
      // because no Guardian was contacted for it to be one.
      {
        label: "absent",
        stage: "request",
        asked: 0,
        audited: [{ outcome: "proceeded", failureKind: "host_configuration" }],
      },
      {
        label: "a non-string",
        stage: "request",
        asked: 0,
        audited: [{ outcome: "proceeded", failureKind: "host_configuration" }],
      },
      // Governed, not skipped and not faulted: `buildEnvelope` accepts an
      // empty string, so this step is really asked about. (Against a live
      // Guardian and this repo's own shipped configuration that answer is a
      // deny -- `runtime_error:tool_unknown` -- which is why leaving it
      // governed is better than refusing it here. See
      // `GovernStepInput.scopedTool`.)
      { label: "the empty string", stage: "honoured", asked: 1, audited: [] },
    ]);
  });

  /**
   * Why an empty told tool is refused rather than passed through:
   * `governsTool` answers `false` for an empty name against any declared
   * list, so a caller that told `""` would have a step this gate governs
   * skipped silently and unaudited -- the same fail-open shape the told-tool
   * rule exists to close. The predicate's answer is pinned first, because it
   * is what makes the refusal necessary rather than decorative.
   */
  it("refuses an empty told tool, because the predicate would silently skip one", async () => {
    expect(governsTool(scoped(["Bash"]), "OnStep", "")).toBe(false);

    const { sink, events } = recordingSink();
    const { guardian, asked } = unaskedGuardian();

    await expect(
      governRaw(guardian, sink, undefined, { hookmap: scoped(["Bash"]), scopedTool: "" }),
    ).rejects.toThrow(/named no scoped tool \(scopedTool is ""\)/);
    // Nothing asked and nothing audited: this is a refusal, not a fail-open
    // wearing an audit entry.
    expect({ asked: asked(), events }).toEqual({ asked: 0, events: [] });
  });

  /**
   * The ordering, and the reason the skip is the first thing `governStep`
   * does rather than merely an early one: `assertOutputIsReplaceable`
   * refuses a result-gate payload whose named leaf no replacement can be
   * built for -- a loud, blocking stop, correctly, for a step this gate
   * governs. But on opencode an unlisted tool's payload is exactly that
   * shape: that gate's `outputs`/`exit_status` are written for the one tool
   * it lists, and every other tool's `metadata` carries something else
   * (opencode.hookmap.yaml's own measurement table). Asked after that
   * refusal, an out-of-scope tool would stop the deployment instead of being
   * skipped.
   */
  it("skips before the result gate's own refusal, so an unlisted tool costs no stop", async () => {
    const { sink, events } = recordingSink();
    const { guardian, asked } = unaskedGuardian();

    const governed = await governRaw(guardian, sink, undefined, {
      hookEventName: "OnResult",
      // Present, resolvable, and a flag -- the payload shape the test above
      // this describe block proves is a blocking stop when the gate governs
      // the tool.
      hookmap: {
        host: "test-host",
        hooks: {
          OnResult: {
            ...ON_RESULT,
            outputs: { from: "$.step_result.truncated", within: "$.step_result" },
            tools: ["Write"],
          },
        },
      },
      payload: resultPayload,
      scopedTool: "Bash",
    });

    expect(governed).toEqual({ output: {}, decision: null, stage: "ungoverned" });
    // Skipped, not stopped -- and the skip is recorded, naming the result
    // gate's own ACS method so a reviewer can tell WHICH gate declined.
    expect(asked()).toBe(0);
    expect(events).toEqual([
      {
        session_id: "sess-1",
        method: "steps/toolCallResult",
        rpc_id: null,
        outcome: "ungoverned",
        ungoverned: { tool: "Bash", tools: ["Write"] },
      },
    ]);
  });
});

/**
 * `governStep` follows tell, don't ask: it takes the tool name the caller
 * says, rather than re-deriving one by resolving the hookmap entry's
 * `tool_name` path against the payload. The two sources can disagree -- a
 * hookmap pointing `tool_name` at something other than the tool (say, at the
 * command) would make a shim proceed while this function silently skipped
 * the step as `"ungoverned"`, with no Guardian request, no decision, and no
 * audit entry.
 *
 * The fixtures below make the two sources disagree on purpose, which is the
 * only way to tell "scoped on what it was told" from "scoped on what it
 * derived": every earlier test in this file uses a hookmap where the two agree,
 * and would pass under either rule.
 */
describe("governStep — the tool it scopes on is the one it was told", () => {
  function unaskedGuardian(): { guardian: GuardianClient; asked: () => number } {
    let asks = 0;
    return {
      guardian: {
        requestDecision: () => {
          asks += 1;
          return Promise.resolve({
            decisionArrived: true,
            decision: { decision: "allow" },
          } satisfies DecisionOrFailure);
        },
        post: () => Promise.reject(new Error("governStep must not use the wire primitive")),
      },
      asked: () => asks,
    };
  }

  /**
   * The divergent gate: `tool_name` points at the command, not at the tool.
   * Against `payload` that resolves to `"ls -la"` while the step's real tool is
   * `"Bash"` -- the same shape as opencode's own fail-open risk
   * (`tool_name: $.args.command` beside `tools: [bash]`), in this suite's own
   * synthetic vocabulary.
   */
  const diverging = (tools: string[]): Hookmap => ({
    host: "test-host",
    hooks: { OnStep: { ...ON_STEP, tool_name: "$.tool_input.command", tools } },
  });

  it("governs a told tool the list names, even where the hookmap's own tool_name path resolves to something else", async () => {
    const { sink, events } = recordingSink();
    const { guardian, asked } = unaskedGuardian();

    const governed = await governRaw(guardian, sink, undefined, {
      hookmap: diverging(["Bash"]),
      scopedTool: "Bash",
    });

    // Told, this is a step the gate really governs. Scoping on the
    // tool_name path instead of the caller's own word would silently drop
    // it as `"ungoverned"` -- now with an audit entry naming a tool the gate
    // does govern, which is a false record rather than merely a missing one.
    expect(governed.stage).toBe("honoured");
    expect({ asked: asked(), events }).toEqual({ asked: 1, events: [] });
  });

  it("skips a told tool the list does not name, even where the hookmap's own tool_name path resolves to one it does", async () => {
    const { sink, events } = recordingSink();
    const { guardian, asked } = unaskedGuardian();

    // The list names what `tool_name` resolves to, and not what the caller
    // says it scoped on. A gate still asking the payload would govern this
    // step; one asking the caller skips it.
    const governed = await governRaw(guardian, sink, undefined, {
      hookmap: diverging(["ls -la"]),
      scopedTool: "Bash",
    });

    expect(governed).toEqual({ output: {}, decision: null, stage: "ungoverned" });
    expect(asked()).toBe(0);
    // The record names the tool the CALLER scoped on and the list as the
    // hookmap declares it -- never the name `tool_name` happens to resolve
    // to, which is the second source `scopedTool` exists to remove.
    expect(events).toEqual([
      {
        session_id: "sess-1",
        method: "steps/toolCallRequest",
        rpc_id: null,
        outcome: "ungoverned",
        ungoverned: { tool: "Bash", tools: ["ls -la"] },
      },
    ]);
  });

  /**
   * The rule that makes this structural rather than optional: a third host
   * that scopes in its own shim and leaves `governStep` to work the tool out
   * again independently gets a loud failure here instead of a silent
   * divergence. Decidable from the hookmap entry and the call's own
   * arguments, with no payload consulted: the entry says this gate governs
   * some tools and not others, and the caller has not said which tool this
   * step is.
   */
  it("refuses a gate that declares a tools list when the caller named no tool, asking and auditing nothing", async () => {
    const { sink, events } = recordingSink();
    const { guardian, asked } = unaskedGuardian();

    await expect(governRaw(guardian, sink, undefined, { hookmap: diverging(["Bash"]) })).rejects.toThrow(
      /declares a "tools" list.*named no scoped tool/s,
    );
    expect({ asked: asked(), events }).toEqual({ asked: 0, events: [] });
  });

  /**
   * This refusal is not answerable by the negotiated posture, which is what
   * keeps it from being a fail-open of its own. `governStep` answers a
   * stage-"request" fault with §6.4's `on_decision_failure`, and under
   * `proceed` -- the ACS default, and what this deployment ships -- that is
   * an ungoverned step that proceeds, audited. A refusal that landed inside
   * that `try` would let the exact call it exists to reject run the tool
   * anyway.
   *
   * The contrast is measured in the same test rather than asserted, because
   * "this throw escapes" means nothing without a throw at the same gate, under
   * the same session, that does not: the second half drives a payload
   * `buildEnvelope` cannot read a tool name from, and gets back a proceeded,
   * audited step instead of a rejection.
   */
  it("raises that refusal outside every try a posture is consulted from — under both negotiated postures", async () => {
    for (const posture of ["proceed", "deny"] as const) {
      const { sink, events } = recordingSink();
      const { guardian, asked } = unaskedGuardian();
      const session: ResolvedSessionConfig = { config: NEGOTIATED(posture), failure: undefined };

      await expect(governRaw(guardian, sink, session, { hookmap: diverging(["Bash"]) })).rejects.toThrow(
        /named no scoped tool/,
      );
      // No `GovernedStep` came back at all, so there is no output for a host
      // to write and nothing for a posture to have answered -- and, under
      // `proceed`, no audit entry claiming a step proceeded.
      expect({ posture, asked: asked(), events }).toEqual({ posture, asked: 0, events: [] });
    }

    // The same gate, the same negotiated `proceed`, and a fault that is the
    // posture's to answer: `buildEnvelope` cannot read a tool name from this
    // payload, so the step proceeds and is audited. Without this row, a
    // refusal that never reached any posture-answerable code would pass the
    // assertions above for the wrong reason.
    const { sink, events } = recordingSink();
    const { guardian, asked } = unaskedGuardian();
    const governed = await governRaw(guardian, sink, undefined, {
      hookmap: diverging(["Bash"]),
      scopedTool: "Bash",
      payload: { session_id: "sess-1", tool_input: {} },
    });

    expect({ stage: governed.stage, asked: asked(), audited: events.map((event) => event.outcome) }).toEqual({
      stage: "request",
      asked: 0,
      audited: ["proceeded"],
    });
  });
});

/**
 * The predicate itself, asked directly -- the single implementation of a rule
 * two shims and `governStep` all depend on, so its edges are pinned here
 * rather than inferred from the three call sites' behaviour.
 */
describe("governsTool — the rule both hosts and governStep share", () => {
  const scopedHookmap: Hookmap = {
    host: "test-host",
    hooks: { OnStep: { ...ON_STEP, tools: ["bash", "Write"] } },
  };

  it("answers true for every tool when the entry declares no tools list", () => {
    expect([
      governsTool(hookmap, "OnStep", "Bash"),
      governsTool(hookmap, "OnStep", "anything-at-all"),
      governsTool(hookmap, "OnStep", ""),
    ]).toEqual([true, true, true]);
  });

  it("answers true for a listed tool and false for an unlisted one, case-sensitively", () => {
    expect([
      governsTool(scopedHookmap, "OnStep", "bash"),
      governsTool(scopedHookmap, "OnStep", "Write"),
      governsTool(scopedHookmap, "OnStep", "read"),
      // Case matters, and this is the asymmetry that made opencode's own suite
      // pass against a tool name its host never sends: OpenCode reports
      // `bash`, Claude Code reports `Bash`.
      governsTool(scopedHookmap, "OnStep", "Bash"),
    ]).toEqual([true, true, false, false]);
  });

  /**
   * A hook this hookmap does not map has no `tools` list to be outside of, so
   * this answers "governs" and leaves the refusal to `governStep`'s own guard
   * -- which throws, because a hookmap missing the hook that fired can express
   * neither an arriving decision nor a posture's answer to an absent one. An
   * unmapped hook answered `false` here would turn that loud stop into a
   * silent skip.
   */
  it("answers true for a hook the hookmap does not map, leaving that refusal where it belongs", () => {
    expect(governsTool(scopedHookmap, "NoSuchHook", "bash")).toBe(true);
  });

  /**
   * `hasOwnProperty`, not a bare index: `hookEventName` reaches some hosts
   * from their own payloads, and `hooks["toString"]` resolves to an inherited
   * `Object.prototype` function. Today both forms answer `true` -- that
   * function carries no `tools` field either -- so this pins the answer as a
   * property of the hookmap's own entries rather than of what
   * `Object.prototype` happens to carry, and would fail if a future edit
   * started reading anything else off the resolved entry.
   */
  it("answers true for a prototype-named hook rather than reading Object.prototype", () => {
    expect(governsTool(scopedHookmap, "toString", "bash")).toBe(true);
  });
});
