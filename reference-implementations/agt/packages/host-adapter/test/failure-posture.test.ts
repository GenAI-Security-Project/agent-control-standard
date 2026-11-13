import { describe, expect, it } from "bun:test";
import type { AuditEvent, AuditSink } from "../src/audit-sink.ts";
import {
  applyFailurePosture,
  classifyDeliveryFailure,
  classifySessionFailure,
  DEFAULT_POSTURE,
} from "../src/failure-posture.ts";
import { GuardianTimeoutError } from "../src/guardian-client.ts";
import { SessionConfigStoreFailedError, type ResolvedSessionConfig } from "../src/handshake.ts";
import type { SessionConfig } from "../src/session-config.ts";

/** The arm of `AuditEvent` this module writes. `applyFailurePosture` answers
 * a failure with a posture, and every entry it files is that; the other arm
 * (`outcome: "ungoverned"`) belongs to a step no posture was consulted for
 * and reaches the sink from `auditUngovernedStep` instead. Narrowed here so
 * the assertions below can read `failure` and `posture` directly. */
type PostureAuditEvent = Extract<AuditEvent, { outcome: "proceeded" | "blocked" }>;

function recordingSink(): { sink: AuditSink; events: PostureAuditEvent[] } {
  const events: PostureAuditEvent[] = [];
  return {
    sink: {
      path: "test",
      write: (e) => {
        // Checked rather than cast: if this module ever starts writing the
        // other arm, that is a change to what it records and it should fail
        // here loudly rather than be narrowed away by an assertion.
        if (e.outcome === "ungoverned") {
          throw new Error(`applyFailurePosture wrote an ungoverned entry: ${JSON.stringify(e)}`);
        }
        events.push(e);
        return true;
      },
    },
    events,
  };
}

/** A sink that behaves exactly as the real one does when it cannot write:
 * it does not throw, it reports nothing back to the caller but false, and it
 * records nothing. The reproduction was ACS_AUDIT_LOG pointing at a path
 * under a regular file. */
function unwritableSink(): AuditSink {
  return { path: "test", write: () => false };
}

const NEGOTIATED = (posture: "proceed" | "deny"): SessionConfig => ({
  negotiated_version: "0.1.0",
  methods_evaluated: ["steps/toolCallRequest"],
  selected_transport: "http",
  timeout_config: { default_ms: 5000 },
  on_decision_failure: posture,
});

/** The session message applyFailurePosture is told (`ResolvedSessionConfig`):
 * the config that governs this step, and whatever went wrong establishing
 * it. `undefined` for the posture means nothing was negotiated, so the ACS
 * default governs. */
const SESSION = (posture: "proceed" | "deny" | undefined, failure?: unknown): ResolvedSessionConfig => ({
  config: posture === undefined ? undefined : NEGOTIATED(posture),
  failure,
});

const CALL = { sessionId: "sess-1", method: "steps/toolCallRequest", rpcId: "req-1" };

describe("applyFailurePosture — the negotiated posture", () => {
  it("proceeds under the negotiated proceed posture", () => {
    const { sink, events } = recordingSink();
    const decision = applyFailurePosture({
      failure: new GuardianTimeoutError(5000),
      session: SESSION("proceed"),
      audit: sink,
      ...CALL,
    });
    expect(decision.decision).toBe("allow");
    expect(decision.reason_codes).toEqual(["decision_failure"]);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      posture: "proceed",
      posture_source: "negotiated",
      outcome: "proceeded",
      failure: { kind: "timeout" },
    });
  });

  it("blocks under the negotiated deny posture", () => {
    const { sink, events } = recordingSink();
    const decision = applyFailurePosture({
      failure: new GuardianTimeoutError(5000),
      session: SESSION("deny"),
      audit: sink,
      ...CALL,
    });
    expect(decision.decision).toBe("deny");
    expect(events[0]).toMatchObject({ posture: "deny", posture_source: "negotiated", outcome: "blocked" });
  });

  // The case the file exists for: no handshake ever completed (Guardian was
  // already down at session start), so there is no negotiated posture. The
  // durable record has to say so -- distinct from "this deployment chose to
  // fail open" -- not just the ephemeral `reasoning` string.
  it("applies the ACS default when nothing was negotiated, and audits it", () => {
    const { sink, events } = recordingSink();
    const decision = applyFailurePosture({
      failure: new TypeError("Unable to connect"),
      session: SESSION(undefined),
      audit: sink,
      ...CALL,
    });
    expect(DEFAULT_POSTURE).toBe("proceed");
    expect(decision.decision).toBe("allow");
    expect(events[0]).toMatchObject({ posture: "proceed", posture_source: "default", outcome: "proceeded" });
  });

  it("names the failure in reasoning, so a human sees why the step was not governed", () => {
    const { sink } = recordingSink();
    const decision = applyFailurePosture({
      failure: new GuardianTimeoutError(5000),
      session: SESSION("proceed"),
      audit: sink,
      ...CALL,
    });
    expect(decision.reasoning).toMatch(/no decision/i);
    expect(decision.reasoning).toMatch(/5000/);
  });

  // A proceed with no audit entry is a silent bypass. Auditing must not be
  // skippable, so there is no option for it.
  it("audits every proceed — the sink is a required argument", () => {
    const { sink, events } = recordingSink();
    applyFailurePosture({ failure: new Error("x"), session: SESSION("proceed"), audit: sink, ...CALL });
    applyFailurePosture({ failure: new Error("y"), session: SESSION("proceed"), audit: sink, ...CALL });
    expect(events).toHaveLength(2);
  });

  // The sink is total, but prove the posture survives even a sink that
  // breaks its contract and throws.
  it("still returns a decision when the sink throws", () => {
    const throwing: AuditSink = { path: null, write: () => { throw new Error("sink is broken"); } };
    expect(
      applyFailurePosture({ failure: new Error("x"), session: SESSION("deny"), audit: throwing, ...CALL })
        .decision,
    ).toBe("deny");
  });
});

// Two properties genuinely disagree here, and the audit requirement
// governs: §6.4 makes the audit entry a MUST for a step that proceeds
// without a decision, so a proceed that could not be recorded is a silent
// bypass -- the one outcome this project exists to make impossible. Without
// this downgrade, with ACS_AUDIT_LOG under a regular file, the step would
// proceed, exit 0, and write no entry; the only trace would be a stderr
// line from a subprocess that succeeded.
describe("applyFailurePosture — an unauditable proceed is not a proceed (§6.4)", () => {
  it("downgrades a proceed it could not audit to deny, with its own reason code", () => {
    const decision = applyFailurePosture({
      failure: new GuardianTimeoutError(5000),
      session: SESSION("proceed"),
      audit: unwritableSink(),
      ...CALL,
    });
    expect(decision.decision).toBe("deny");
    expect(decision.reason_codes).toEqual(["decision_failure", "audit_unavailable"]);
    expect(decision.reasoning).toMatch(/could not be recorded/i);
  });

  it("downgrades when the sink throws outright, not only when it reports false", () => {
    const throwing: AuditSink = { path: null, write: () => { throw new Error("sink is broken"); } };
    expect(
      applyFailurePosture({
        failure: new GuardianTimeoutError(5000),
        session: SESSION("proceed"),
        audit: throwing,
        ...CALL,
      }).decision,
    ).toBe("deny");
  });

  // A deny needs no downgrade: the step is blocked either way, and the failed
  // write is already reported by the sink's own error path. It must not pick
  // up the downgrade's reason code, which would misdescribe why it blocked.
  it("leaves an unauditable deny alone", () => {
    const decision = applyFailurePosture({
      failure: new GuardianTimeoutError(5000),
      session: SESSION("deny"),
      audit: unwritableSink(),
      ...CALL,
    });
    expect(decision.decision).toBe("deny");
    expect(decision.reason_codes).toEqual(["decision_failure"]);
  });

  it("still proceeds when the entry WAS recorded -- the downgrade is about the record, not the posture", () => {
    const { sink } = recordingSink();
    expect(
      applyFailurePosture({
        failure: new GuardianTimeoutError(5000),
        session: SESSION("proceed"),
        audit: sink,
        ...CALL,
      }).decision,
    ).toBe("allow");
  });
});

describe("applyFailurePosture — a request that was never sent is not a delivery failure", () => {
  const NOT_SENT = { ...CALL, method: null, stage: "request" as const };

  it("classifies it as host_configuration, not unknown", () => {
    const { sink, events } = recordingSink();
    applyFailurePosture({
      // A buildEnvelope failure that can still reach this stage. "hookmap has
      // no entry for hook X" is out of the posture's reach entirely
      // (governStep throws on it and audits nothing, because the posture's own
      // answer could not be rendered either), so a fixture using that message
      // would be classifying a failure this stage never sees.
      failure: new Error('buildEnvelope: hookmap path "$.tool_name" for hook "PostToolUse" did not resolve to a string'),
      session: SESSION("proceed"),
      audit: sink,
      ...NOT_SENT,
    });
    expect(events[0]?.failure.kind).toBe("host_configuration");
    expect(events[0]?.method).toBeNull();
  });

  // The audit trail must not send an incident review to the wrong process.
  it("does not blame the guardian in the reasoning or the reason code", () => {
    const { sink } = recordingSink();
    const decision = applyFailurePosture({
      failure: new Error("no entry for this hook"),
      session: SESSION("proceed"),
      audit: sink,
      ...NOT_SENT,
    });
    expect(decision.reasoning).not.toMatch(/guardian/i);
    expect(decision.reasoning).toMatch(/could not build a request/i);
    expect(decision.reason_codes).toEqual(["host_configuration"]);
  });

  it("still names the guardian when a request really was sent", () => {
    const { sink } = recordingSink();
    const decision = applyFailurePosture({
      failure: new GuardianTimeoutError(5000),
      session: SESSION("proceed"),
      audit: sink,
      ...CALL,
    });
    expect(decision.reasoning).toMatch(/guardian/i);
  });
});

// A decision that arrived and was honoured, which this host then could not
// express, must not be audited as "no decision arrived from the guardian
// (unknown: ...)" -- both halves would be false: one arrived, and the cause
// is precisely known. It is the same misattribution the `request` stage
// above avoids, read the other way round -- and it would send an incident
// reviewer to a Guardian that answered correctly.
describe("applyFailurePosture — a decision that arrived and could not be rendered", () => {
  const UNRENDERABLE = {
    ...CALL,
    stage: "render" as const,
    failure: new Error(
      'renderDecision: hookmap\'s hook "PreToolUse" has no decisions entry for ACS decision "quarantine"',
    ),
  };

  it("classifies it as decision_unrenderable, not as a delivery failure", () => {
    const { sink, events } = recordingSink();
    applyFailurePosture({ session: SESSION("proceed"), audit: sink, ...UNRENDERABLE });
    expect(events[0]?.failure.kind).toBe("decision_unrenderable");
    expect(events[0]?.failure.message).toContain("quarantine");
  });

  it("says a decision arrived and this host could not express it", () => {
    const { sink } = recordingSink();
    const decision = applyFailurePosture({ session: SESSION("proceed"), audit: sink, ...UNRENDERABLE });
    expect(decision.reasoning).toMatch(/a decision arrived from the guardian .* and was honoured/i);
    expect(decision.reasoning).toMatch(/could not express it/i);
    // The exact claim that was false, asserted directly rather than inferred
    // from the sentence above: it must not say none arrived.
    expect(decision.reasoning).not.toMatch(/no decision arrived/i);
    expect(decision.reason_codes).toEqual(["decision_unrenderable"]);
  });

  // The posture logic is untouched by this reclassification: it still
  // decides, and it still decides the same way it would for any other
  // failure. Only what the record SAYS about the failure changed.
  it("still applies the posture, unchanged, in both directions", () => {
    const { sink } = recordingSink();
    expect(applyFailurePosture({ session: SESSION("proceed"), audit: sink, ...UNRENDERABLE }).decision)
      .toBe("allow");
    const second = recordingSink();
    expect(
      applyFailurePosture({ session: SESSION("deny"), audit: second.sink, ...UNRENDERABLE }).decision,
    ).toBe("deny");
  });
});

describe("applyFailurePosture — a session config that could not be established is recorded", () => {
  it("carries the session failure into the audited entry, beside the step's own failure", () => {
    const { sink, events } = recordingSink();
    applyFailurePosture({
      failure: new GuardianTimeoutError(5000),
      session: SESSION(undefined, new Error("EACCES: permission denied, mkdir '.acs/sessions'")),
      audit: sink,
      ...CALL,
    });
    expect(events[0]?.failure.kind).toBe("timeout");
    expect(events[0]?.session_failure?.message).toContain("EACCES");
  });

  // The two session-establishment failures are distinct kinds, not one
  // constant (`kind: "session_config"`) separated by free text. In a
  // Guardian-down session EVERY entry would otherwise carry the same note,
  // burying the one occurrence that actually costs something -- a
  // ServerHello that arrived and could not be kept.
  it("distinguishes a handshake that never came back from a ServerHello it could not keep", () => {
    const unreachable = recordingSink();
    applyFailurePosture({
      failure: new GuardianTimeoutError(5000),
      session: SESSION(undefined, new Error("Unable to connect. Is the computer able to access the url?")),
      audit: unreachable.sink,
      ...CALL,
    });
    expect(unreachable.events[0]?.session_failure?.kind).toBe("handshake_failed");

    const unstored = recordingSink();
    applyFailurePosture({
      failure: new GuardianTimeoutError(5000),
      session: SESSION(
        "deny",
        new SessionConfigStoreFailedError("handshake: the Guardian's ServerHello could not be stored", {
          config: NEGOTIATED("deny"),
        }),
      ),
      audit: unstored.sink,
      ...CALL,
    });
    expect(unstored.events[0]?.session_failure?.kind).toBe("session_config_unstored");
  });

  it("classifySessionFailure is total: an unrecognised throw still gets a kind", () => {
    expect(classifySessionFailure("not an error at all")).toEqual({
      kind: "handshake_failed",
      message: "not an error at all",
    });
  });

  it("omits the field entirely when the session config was fine", () => {
    const { sink, events } = recordingSink();
    applyFailurePosture({
      failure: new GuardianTimeoutError(5000),
      session: SESSION("proceed"),
      audit: sink,
      ...CALL,
    });
    expect(events[0]).not.toHaveProperty("session_failure");
  });

  it("says so in the reasoning a human reads, rather than discarding it", () => {
    const { sink } = recordingSink();
    const decision = applyFailurePosture({
      failure: new GuardianTimeoutError(5000),
      session: SESSION(undefined, new Error("EACCES: permission denied")),
      audit: sink,
      ...CALL,
    });
    expect(decision.reasoning).toMatch(/could not be established or stored/i);
    expect(decision.reasoning).toContain("EACCES");
  });
});

describe("classifyDeliveryFailure — what came back instead of a decision", () => {
  it("classifies a timeout", () => {
    expect(classifyDeliveryFailure(new GuardianTimeoutError(5000)).kind).toBe("timeout");
  });

  // MUST NOT be replaced with a synthetic error. A hand-built
  // `new TypeError(...)` would only prove classifyDeliveryFailure handles a
  // TypeError correctly, never that a real refused connection produces one.
  // It doesn't, on Bun (a plain Error with `.code: "ConnectionRefused"`, not
  // a TypeError) -- so a synthetic test would pass while the runtime's
  // actual dead-transport case classified as "unknown". Driving a real
  // rejection here is what catches that. Port 1 is a reliably refused
  // connection: no service binds it without root, and this sandbox has none
  // listening there either way.
  it("classifies a real refused connection (this runtime's actual route, not a spec-conformant guess)", async () => {
    let failure: unknown;
    try {
      await fetch("http://127.0.0.1:1/acs", { method: "POST", body: "{}" });
      throw new Error("expected fetch to reject");
    } catch (error) {
      failure = error;
    }
    expect(classifyDeliveryFailure(failure).kind).toBe("transport");
  });

  // The WHATWG fetch spec's own route (a TypeError for a network error) --
  // this runtime does not take it for a refused connection, but another
  // runtime, or a future Bun, might. Kept as a synthetic case specifically
  // because there is no way to provoke a real TypeError-shaped network
  // failure on THIS runtime to drive it with instead.
  it("classifies a spec-conformant TypeError network error, covering other runtimes", () => {
    expect(classifyDeliveryFailure(new TypeError("Unable to connect. Is the computer able to access the url?")).kind)
      .toBe("transport");
  });

  // An error code this host does not recognise as a refusal. It stays a
  // delivery failure and keeps the posture, which is the deliberate limit of
  // the enumerated refusal set: the shipped Guardian mints none of these
  // today, but an intermediary or a non-conformant peer can, and guessing
  // that every error object is the Guardian refusing would fail closed on an
  // error the Guardian never sent.
  it("classifies an error response whose code it does not recognise as a refusal", () => {
    const { kind, message } = classifyDeliveryFailure({ code: -32601, message: "Method not found" });
    expect(kind).toBe("error_without_decision");
    expect(message).toContain("-32601");
  });

  // The four codes this deployment's Guardian mints for a request it will not
  // decide (packages/guardian/src/server.ts). Asserted per code rather than
  // as a set, so a failure names which route regressed. client.test.ts drives
  // three of them against a real Guardian; this is the unit half.
  it.each([-32700, -32010, -32011, -32020])("classifies the guardian's %i as a refusal, not a delivery failure", (code) => {
    const { kind, message } = classifyDeliveryFailure({ code, message: "no" });
    expect(kind).toBe("refused");
    // The code an incident reviewer needs, in the field that reaches the
    // durable record -- there is no second structured copy of it.
    expect(message).toContain(String(code));
    expect(message).toMatch(/refused/i);
  });

  it("never throws on an unknown shape", () => {
    expect(classifyDeliveryFailure(Object.create(null)).kind).toBe("unknown");
    expect(classifyDeliveryFailure(undefined).kind).toBe("unknown");
  });
});

// The finding this describe exists for: the host could not tell "the Guardian
// is down" from "the Guardian is alive and refused your envelope", and under
// the shipped default posture (`proceed`) both became `allow`. Every test here
// runs under `proceed` deliberately -- under `deny` they would all pass
// against the unfixed code, since the posture would have denied anyway.
describe("applyFailurePosture — a guardian that was alive and refused the envelope", () => {
  const REFUSAL = { code: -32020, message: "evaluation failed" };

  it("denies while the negotiated posture is proceed", () => {
    const { sink } = recordingSink();
    const decision = applyFailurePosture({ failure: REFUSAL, session: SESSION("proceed"), audit: sink, ...CALL });
    expect(decision.decision).toBe("deny");
  });

  // The worse half of the same fault: a session that never handshook runs on
  // the ACS default, which IS `proceed`, so a Guardian refusing every envelope
  // would have allowed every step.
  it("denies under the ACS default posture too, where nothing was negotiated", () => {
    const { sink } = recordingSink();
    expect(DEFAULT_POSTURE).toBe("proceed");
    expect(
      applyFailurePosture({ failure: REFUSAL, session: SESSION(undefined), audit: sink, ...CALL }).decision,
    ).toBe("deny");
  });

  it.each([-32700, -32010, -32011, -32020])("denies on %i, which the guardian mints for an envelope it will not decide", (code) => {
    const { sink } = recordingSink();
    expect(
      applyFailurePosture({ failure: { code, message: "no" }, session: SESSION("proceed"), audit: sink, ...CALL })
        .decision,
    ).toBe("deny");
  });

  // Still audited -- fail-closed is not a licence to stop recording -- and the
  // entry has to be readable as a refusal rather than as a posture that
  // contradicts itself.
  it("audits it as blocked, under the refusal's own kind, with the guardian's code in the message", () => {
    const { sink, events } = recordingSink();
    applyFailurePosture({ failure: REFUSAL, session: SESSION("proceed"), audit: sink, ...CALL });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      posture: "proceed",
      posture_source: "negotiated",
      outcome: "blocked",
      failure: { kind: "refused" },
    });
    expect(events[0]?.failure.message).toContain("-32020");
    expect(events[0]?.failure.message).toContain("evaluation failed");
  });

  // `decision_failure` would tell a machine reader no decision arrived, when
  // the Guardian's refusal is exactly what did.
  it("carries its own reason code, not the delivery stage's", () => {
    const { sink } = recordingSink();
    const decision = applyFailurePosture({ failure: REFUSAL, session: SESSION("proceed"), audit: sink, ...CALL });
    expect(decision.reason_codes).toEqual(["guardian_refused"]);
  });

  it("says the guardian refused rather than that nothing arrived, and that the posture does not apply", () => {
    const { sink } = recordingSink();
    const decision = applyFailurePosture({ failure: REFUSAL, session: SESSION("proceed"), audit: sink, ...CALL });
    expect(decision.reasoning).toMatch(/refused the envelope/i);
    expect(decision.reasoning).toMatch(/does not apply/i);
    // The two claims that would be false. It must not report a delivery
    // failure, and it must not report the posture as having been honoured.
    expect(decision.reasoning).not.toMatch(/no decision arrived/i);
    expect(decision.reasoning).not.toMatch(/so this step was proceeded/i);
  });

  // The unauditable-proceed downgrade must not swallow this: it also denies,
  // so the decision alone cannot tell whether the refusal was honoured or the
  // step merely fell into that branch and was filed under the wrong reason.
  it("blocks an unauditable refusal as a refusal, not as an unrecorded proceed", () => {
    const decision = applyFailurePosture({
      failure: REFUSAL,
      session: SESSION("proceed"),
      audit: unwritableSink(),
      ...CALL,
    });
    expect(decision.decision).toBe("deny");
    expect(decision.reason_codes).toEqual(["guardian_refused"]);
    expect(decision.reasoning).not.toMatch(/could not be recorded/i);
  });

  it("still returns a decision when the sink throws, the same as every other failure", () => {
    const throwing: AuditSink = { path: null, write: () => { throw new Error("sink is broken"); } };
    expect(
      applyFailurePosture({ failure: REFUSAL, session: SESSION("proceed"), audit: throwing, ...CALL }).decision,
    ).toBe("deny");
  });

  // The other half of the split, asserted beside it: an error the host does
  // not recognise as a refusal is still the wire's business, so `proceed`
  // still proceeds. Without this, the refusal tests above would also pass if
  // the fix had simply made every JSON-RPC error fail closed.
  it("leaves an unrecognised error code on the posture path, where proceed still proceeds", () => {
    const { sink, events } = recordingSink();
    const decision = applyFailurePosture({
      failure: { code: -32601, message: "Method not found" },
      session: SESSION("proceed"),
      audit: sink,
      ...CALL,
    });
    expect(decision.decision).toBe("allow");
    expect(decision.reason_codes).toEqual(["decision_failure"]);
    expect(events[0]).toMatchObject({ outcome: "proceeded", failure: { kind: "error_without_decision" } });
  });

  // A refusal is a delivery-stage event; the other two stages are host-side
  // and their failure object is never a JSON-RPC error. Pinned so a future
  // edit cannot let a stage that KNOWS what happened be overruled by a
  // failure value that happens to carry a `code`.
  it("does not reclassify a host-side stage whose failure happens to carry a code", () => {
    const { sink, events } = recordingSink();
    const decision = applyFailurePosture({
      failure: { code: -32020, message: "evaluation failed" },
      session: SESSION("proceed"),
      audit: sink,
      ...CALL,
      stage: "request",
    });
    expect(events[0]?.failure.kind).toBe("host_configuration");
    expect(decision.decision).toBe("allow");
  });
});
