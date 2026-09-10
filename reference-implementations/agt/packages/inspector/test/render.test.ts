import { describe, expect, it } from "bun:test";
import {
  outcomeMessageOf,
  renderAuditEntry,
  renderDecisionBadge,
  renderEnvelopeLogEntry,
  renderOutcome,
  renderPostureBadge,
  renderRpcError,
  type OutcomeMessage,
  type RenderOptions,
} from "../src/render.ts";
import type { EnvelopeLogEntry } from "../src/tail-envelope-log.ts";

function entry(overrides: Partial<EnvelopeLogEntry>): EnvelopeLogEntry {
  return {
    seq: 3,
    recorded_at: "2026-08-09T12:04:31.221Z",
    direction: "response",
    method: "steps/toolCallRequest",
    rpc_id: 1,
    envelope: {},
    ...overrides,
  };
}

function response(result: Record<string, unknown>): EnvelopeLogEntry {
  return entry({ envelope: { jsonrpc: "2.0", id: 1, result } });
}

/** The message renderEnvelopeLogEntry would build for this envelope-log
 * line, for the badge tests that assert the rendered string end to end.
 * Throws rather than asserting non-null inline, so a line that stopped
 * carrying an outcome fails as itself instead of as a confusing `toBe`
 * diff. */
function messageOf(line: EnvelopeLogEntry): OutcomeMessage {
  const message = outcomeMessageOf(line);
  if (message === null) {
    throw new Error("expected this entry to carry a decision or an error");
  }
  return message;
}

function badgeFor(result: Record<string, unknown>, options?: RenderOptions): string {
  return renderOutcome(messageOf(response(result)), options);
}

describe("outcomeMessageOf -- what the renderers are told about", () => {
  it("has nothing to say about a request", () => {
    expect(outcomeMessageOf(entry({ direction: "request", envelope: { jsonrpc: "2.0", id: 1 } }))).toBeNull();
  });

  it("has nothing to say about a response with no decision -- a ServerHello", () => {
    expect(outcomeMessageOf(response({ negotiated_version: "0.1.0", on_decision_failure: "proceed" }))).toBeNull();
  });

  // The badge is handed ACS fields, not a log row to dig through, so
  // everything it renders is decided here.
  it("narrows the ACS fields the badge renders, and drops the rest of the envelope", () => {
    expect(
      outcomeMessageOf(
        response({
          decision: "deny",
          reason_codes: ["blocked", 7],
          policy_references: [{ policy_id: "agt_stock", rule_id: "blocked" }, "not an object"],
          reasoning: "ignored by the badge",
        }),
      ),
    ).toEqual({
      kind: "decision",
      decision: "deny",
      reason_codes: ["blocked"],
      policy_references: [{ policy_id: "agt_stock", rule_id: "blocked" }],
    });
  });

  it("reports a JSON-RPC error as an error message, with a null code when it is not a number", () => {
    expect(outcomeMessageOf(entry({ envelope: { jsonrpc: "2.0", id: 1, error: { code: "nope" } } }))).toEqual({
      kind: "error",
      code: null,
      message: "",
    });
  });

  // The discriminant is the point: a caller can tell an outcome that IS a
  // decision from one that stood in for the absence of one without
  // inspecting which fields happen to be present.
  it("discriminates a decision from an error, so nothing has to infer which arm it holds", () => {
    expect(outcomeMessageOf(response({ decision: "allow" }))?.kind).toBe("decision");
    expect(outcomeMessageOf(entry({ envelope: { jsonrpc: "2.0", id: 1, error: { code: -32010 } } }))?.kind).toBe(
      "error",
    );
  });
});

describe("renderDecisionBadge", () => {
  // The renderer needs no envelope log at all now: anything that can build
  // the message can use the badge.
  it("renders a message built by hand, with no log entry anywhere in sight", () => {
    expect(renderDecisionBadge({ decision: "deny", reason_codes: [], policy_references: [] })).toBe("● DENY");
  });

  it("badges a deny, with reason_codes and policy_references", () => {
    const badge = badgeFor({
      decision: "deny",
      reason_codes: ["destructive_shell_command_blocked"],
      policy_references: [{ policy_id: "agt_stock", rule_id: "destructive_shell_command_blocked" }],
    });

    expect(badge).toBe(
      "● DENY  reason_codes=[destructive_shell_command_blocked]  " +
        "policy_references=[agt_stock#destructive_shell_command_blocked]",
    );
  });

  it("badges a plain allow", () => {
    expect(badgeFor({ decision: "allow" })).toBe("○ ALLOW");
  });

  // The reason this badge exists: a policy that fired and let the action
  // proceed arrives as an ACS `allow` with a non-empty policy_references,
  // and the badge is what keeps it from being buried.
  //
  // This package carries no policy-runtime vocabulary, so the label says
  // only what ACS itself reports -- not the policy engine's own name for
  // the case -- and the last assertion holds that line.
  it("distinguishes an allow that carries policy_references, without naming a disposition ACS lacks", () => {
    const badge = badgeFor({
      decision: "allow",
      reason_codes: ["drift_detected"],
      policy_references: [{ policy_id: "agt_stock", rule_id: "drift_detected" }],
    });

    expect(badge).toBe(
      "◐ ALLOW (policy fired)  reason_codes=[drift_detected]  policy_references=[agt_stock#drift_detected]",
    );
    expect(badge).not.toBe(badgeFor({ decision: "allow" }));
    expect(badge).not.toContain("warn");
  });

  // Pins current behaviour: ACS's schemas do not require `rule_id` on a
  // policy_reference, so this is a real shape, not a hypothetical one.
  // Dropping to the bare policy_id here is a deliberate degradation, not a
  // bug -- this test exists so a future change to it is a decision, not an
  // accident.
  it("renders a policy_reference with no rule_id as the bare policy_id", () => {
    const badge = badgeFor({ decision: "deny", policy_references: [{ policy_id: "agt_stock" }] });

    expect(badge).toBe("● DENY  policy_references=[agt_stock]");
  });

  it("badges modify, ask, and defer", () => {
    expect(badgeFor({ decision: "modify" })).toBe("◆ MODIFY");
    expect(badgeFor({ decision: "ask" })).toBe("◆ ASK");
    expect(badgeFor({ decision: "defer" })).toBe("◆ DEFER");
  });

  // Renders through `renderOutcome`, which is what the stream renderer
  // calls: an error reaches `renderRpcError`, never the decision badge.
  // `renderDecisionBadge` cannot be handed one at all -- `DecisionMessage`
  // has no error arm to pass it.
  it("renders a JSON-RPC error as an error, not as a decision badge", () => {
    const line = renderOutcome(
      messageOf(entry({ envelope: { jsonrpc: "2.0", id: 1, error: { code: -32010, message: "ACS envelope failed" } } })),
    );

    expect(line).toBe("✖ ERROR -32010  ACS envelope failed");
  });

  // Pins the fallback the old renderer had inline: a code that is not a
  // number reaches the message as null and still renders as `?`.
  it("renders an error whose code is not a number", () => {
    expect(renderRpcError({ code: null, message: "unreadable" })).toBe("✖ ERROR ?  unreadable");
  });

  it("emits ANSI only when colour is asked for", () => {
    const plain = badgeFor({ decision: "deny" }, { color: false });
    const coloured = badgeFor({ decision: "deny" }, { color: true });

    expect(plain).toBe("● DENY");
    expect(coloured).toContain("\u001b[");
    expect(coloured).toContain("DENY");
  });

  // With color:true, painting only the glyph and decision label would make
  // a coloured badge read as one coloured half and one plain half. The
  // appended segments are painted dim so the whole badge reads as one unit;
  // color:false stays byte-identical to the exact-string tests above.
  it("paints the appended reason_codes/policy_references segments dim when coloured", () => {
    const coloured = badgeFor(
      {
        decision: "deny",
        reason_codes: ["destructive_shell_command_blocked"],
        policy_references: [{ policy_id: "agt_stock", rule_id: "destructive_shell_command_blocked" }],
      },
      { color: true },
    );

    expect(coloured).toContain("\u001b[2mreason_codes=[destructive_shell_command_blocked]\u001b[0m");
    expect(coloured).toContain("\u001b[2mpolicy_references=[agt_stock#destructive_shell_command_blocked]\u001b[0m");
  });
});

describe("renderEnvelopeLogEntry", () => {
  it("renders a request as a header line plus pretty JSON, with no badge", () => {
    const rendered = renderEnvelopeLogEntry(
      entry({
        direction: "request",
        seq: 1,
        envelope: { jsonrpc: "2.0", method: "steps/toolCallRequest", id: 1 },
      }),
    );

    expect(rendered.split("\n")[0]).toBe("── #1  12:04:31.221  → REQUEST   steps/toolCallRequest  id=1");
    expect(rendered).toContain('"jsonrpc": "2.0"');
    expect(rendered).not.toContain("●");
  });

  it("renders a response as a header line, a badge line, then pretty JSON", () => {
    const rendered = renderEnvelopeLogEntry(response({ decision: "deny", reason_codes: ["blocked"] }));
    const lines = rendered.split("\n");

    expect(lines[0]).toBe("── #3  12:04:31.221  ← RESPONSE  steps/toolCallRequest  id=1");
    expect(lines[1]).toBe("● DENY  reason_codes=[blocked]");
    expect(lines[2]).toBe("{");
  });

  it("labels an unpaired response -- the malformed-body case -- without an id or a method", () => {
    const rendered = renderEnvelopeLogEntry(
      entry({ method: null, rpc_id: null, envelope: { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } } }),
    );

    expect(rendered.split("\n")[0]).toBe("── #3  12:04:31.221  ← RESPONSE  (no method)  (unpaired)");
  });

  // What this checks is that the JSON *value* round trips: nothing stripped,
  // nothing reordered, only whitespace reshaped. Not that the bytes round trip
  // -- the envelope log stores the value the Guardian parsed, not the bytes
  // the host sent.
  it("changes nothing but whitespace -- the envelope value round trips through the renderer", () => {
    const envelope = { jsonrpc: "2.0", id: 1, result: { decision: "allow", nested: { deep: [1, 2] } } };
    const rendered = renderEnvelopeLogEntry(entry({ envelope }));
    const jsonStart = rendered.indexOf("{");

    expect(JSON.parse(rendered.slice(jsonStart))).toEqual(envelope);
  });

  // `isEnvelopeLogEntryShape` deliberately does not constrain `envelope`, so
  // a hand-written or truncated log line reaches the renderer with the key
  // missing entirely. `JSON.stringify(undefined)` returns `undefined`,
  // which `join` would coerce into a blank line indistinguishable from a
  // real empty body.
  it("marks an entry whose envelope key is absent, instead of emitting a blank body", () => {
    const withoutEnvelope = {
      seq: 3,
      recorded_at: "2026-08-09T12:04:31.221Z",
      direction: "response",
      method: "steps/toolCallRequest",
      rpc_id: 1,
    } as unknown as EnvelopeLogEntry;

    const lines = renderEnvelopeLogEntry(withoutEnvelope).split("\n");

    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe("── #3  12:04:31.221  ← RESPONSE  steps/toolCallRequest  id=1");
    expect(lines[1]).toBe("(no envelope recorded)");
  });
});

describe("renderPostureBadge", () => {
  it("shows the last observed posture and a zero count before anything fails", () => {
    expect(renderPostureBadge({ posture: "proceed", proceeds: 0 }, { color: false }))
      .toBe("last_observed_posture=proceed  fail-open proceeds=0");
  });

  // The number that matters. A fail-open bypass is invisible unless something
  // counts it, and §6.4 exists because it must not be invisible.
  it("counts audited fail-open proceeds", () => {
    expect(renderPostureBadge({ posture: "proceed", proceeds: 3 }, { color: false }))
      .toBe("last_observed_posture=proceed  fail-open proceeds=3");
  });

  // A label of "posture=(not negotiated)" would be false in the healthiest
  // case there is -- a session that negotiated `deny` and had zero delivery
  // failures writes no audit entry at all, so the badge would say "not
  // negotiated" forever while the negotiated value sat in the session
  // store. The badge reports what it can actually see: the last posture
  // observed in the audit log, and its absence.
  it("says nothing has been observed yet, rather than claiming nothing was negotiated", () => {
    const badge = renderPostureBadge({ posture: null, proceeds: 0 }, { color: false });
    expect(badge).toBe("last_observed_posture=(none observed)  fail-open proceeds=0");
    expect(badge).not.toContain("negotiated");
  });

  it("paints a non-zero proceed count as a warning and zero as clean", () => {
    expect(renderPostureBadge({ posture: "proceed", proceeds: 1 }, { color: true })).toContain(String.fromCharCode(27) + "[33m");
    expect(renderPostureBadge({ posture: "proceed", proceeds: 0 }, { color: true })).not.toContain(String.fromCharCode(27) + "[33m");
  });

  it("paints the deny posture distinctly from proceed", () => {
    const deny = renderPostureBadge({ posture: "deny", proceeds: 0 }, { color: true });
    const proceed = renderPostureBadge({ posture: "proceed", proceeds: 0 }, { color: true });
    expect(deny).not.toBe(proceed);
  });

  it("is byte-identical with color off, whatever the state", () => {
    for (const posture of ["proceed", "deny", null] as const) {
      for (const proceeds of [0, 1, 42]) {
        const out = renderPostureBadge({ posture, proceeds }, { color: false });
        expect(out).not.toContain(String.fromCharCode(27));
      }
    }
  });
});

describe("renderAuditEntry", () => {
  it("renders a proceeded entry with the failure that caused it", () => {
    const line = renderAuditEntry(
      {
        seq: 1,
        recorded_at: "2026-08-10T12:00:00.000Z",
        session_id: "sess-1",
        method: "steps/toolCallRequest",
        rpc_id: "req-1",
        posture: "proceed",
        posture_source: "negotiated",
        outcome: "proceeded",
        failure: { kind: "timeout", message: "no response within 5000ms" },
      },
      { color: false },
    );
    expect(line).toContain("PROCEEDED");
    expect(line).toContain("steps/toolCallRequest");
    expect(line).toContain("timeout");
  });

  it("renders a blocked entry distinctly", () => {
    const line = renderAuditEntry(
      { seq: 2, recorded_at: "2026-08-10T12:00:01.000Z", session_id: "s", method: "m", rpc_id: null,
        posture: "deny", posture_source: "negotiated", outcome: "blocked",
        failure: { kind: "transport", message: "gone" } },
      { color: false },
    );
    expect(line).toContain("BLOCKED");
  });

  // Rendering `method` verbatim from the entry would print a host's event
  // name at runtime: the writer puts its own hook event name there when no
  // request was ever built, and this package's whole claim is that it
  // names no host, even though the grep gate over its own source would
  // stay green. It reads null instead, and this is the fallback.
  it("labels an entry with no ACS method rather than printing whatever was in the field", () => {
    const line = renderAuditEntry(
      { seq: 1, recorded_at: "2026-08-10T12:00:00.000Z", session_id: "s", method: null, rpc_id: null,
        posture: "proceed", posture_source: "default", outcome: "proceeded",
        failure: { kind: "host_configuration", message: "no entry for this hook" } },
      { color: false },
    );
    expect(line).toContain("(no method)");
    expect(line).not.toContain("null");
  });

  it("renders a session_failure on its own labelled line, and nothing when absent", () => {
    const base = {
      seq: 1,
      recorded_at: "2026-08-10T12:00:00.000Z",
      session_id: "s",
      method: "steps/toolCallRequest",
      rpc_id: null,
      posture: "proceed",
      posture_source: "default",
      outcome: "proceeded",
      failure: { kind: "timeout", message: "no response within 5000ms" },
    } as const;

    const withSessionFailure = renderAuditEntry(
      { ...base, session_failure: { kind: "session_config_unstored", message: "EACCES: permission denied" } },
      { color: false },
    );
    expect(withSessionFailure.split("\n")).toHaveLength(3);
    expect(withSessionFailure).toContain("session_failure=session_config_unstored: EACCES: permission denied");
    // The step's own failure is still reported as the step's own.
    expect(withSessionFailure).toContain("failure=timeout: no response within 5000ms");

    expect(renderAuditEntry(base, { color: false }).split("\n")).toHaveLength(2);
  });

  // The third outcome, and the two things that must NOT appear on its line:
  // a posture (none was consulted -- printing this session's declared one
  // would read as "the deployment chose to proceed") and a failure (nothing
  // failed; the hookmap asked for the skip).
  it("renders an ungoverned entry with the tool and the list that declined it, and no posture", () => {
    const line = renderAuditEntry(
      {
        seq: 3,
        recorded_at: "2026-08-10T12:00:02.000Z",
        session_id: "sess-1",
        method: "steps/toolCallResult",
        rpc_id: null,
        outcome: "ungoverned",
        ungoverned: { tool: "read", tools: ["bash"] },
      },
      { color: false },
    );
    expect(line).toContain("UNGOVERNED");
    expect(line).toContain("steps/toolCallResult");
    expect(line).toContain("ungoverned=read: not in this gate's tools [bash]");
    expect(line).not.toContain("posture=");
    expect(line).not.toContain("failure=");
    // Header plus the one explanatory line, the same two-line shape a
    // posture-resolved entry with no session failure renders as.
    expect(line.split("\n")).toHaveLength(2);
  });

  // A gate whose entry declares no `tools` list never skips, so an empty list
  // reaches this renderer only from a hand-built or corrupted line. `[]`
  // would render as `[]` and read as a list that names nothing, which is
  // true but says nothing; `(none)` says it out loud.
  it("names an empty tools list rather than rendering an empty bracket", () => {
    const line = renderAuditEntry(
      {
        seq: 1,
        recorded_at: "2026-08-10T12:00:00.000Z",
        session_id: "s",
        method: null,
        rpc_id: null,
        outcome: "ungoverned",
        ungoverned: { tool: "read", tools: [] },
      },
      { color: false },
    );
    expect(line).toContain("[(none)]");
    expect(line).toContain("(no method)");
  });
});
