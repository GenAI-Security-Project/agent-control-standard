# ACS in Action

A worked example of an Observed Agent calling the `email.send` tool, with a Guardian Agent enforcing IBAC + FIDES policies, emitting a Trace event, and updating the AgBOM. Read [Core Concepts](./core_concepts.md) first if you haven't.

## Sequence

```
Observed Agent          Guardian Agent          Trace sink (OTLP/SIEM)
══════════════          ══════════════          ══════════════════════
  │                          │                          │
  │ 1. handshake/hello       │                          │
  ├─────────────────────────>│                          │
  │ 2. ServerHello           │                          │
  │<─────────────────────────┤                          │
  │ 3. agbom/snapshot        │                          │
  ├─────────────────────────>│                          │
  │                          │ 4. Trace: acs.agbom      │
  │                          ├─────────────────────────>│
  │ 5. allow                 │                          │
  │<─────────────────────────┤                          │
  │ 6. steps/sessionStart    │                          │
  ├─────────────────────────>│ 7. Open chain root       │
  │ 8. allow                 │                          │
  │<─────────────────────────┤                          │
  │ 9. steps/userMessage     │                          │
  ├─────────────────────────>│                          │
  │ 10. allow                │                          │
  │<─────────────────────────┤                          │
  │ 11. steps/toolCallRequest│                          │
  ├─────────────────────────>│ 12. Evaluate IBAC + FIDES│
  │                          │ 13. Trace: acs.decision  │
  │                          ├─────────────────────────>│
  │ 14. allow                │                          │
  │<─────────────────────────┤                          │
  │ 15. Execute tool         │                          │
  │ 16. steps/toolCallResult │                          │
  ├─────────────────────────>│                          │
  │ 17. allow                │                          │
  │<─────────────────────────┤                          │
```

## The decision point: `steps/toolCallRequest`

The Observed Agent has been asked by a user to "summarize Project X status and email it to my manager." The agent has retrieved the status (untrusted, from a knowledge base), composed a body via the LLM (agent_generated, derived from the retrieval), and is about to call `email.send`. The Guardian must decide.

This example shows a deployment that elects to populate the OPTIONAL `trust` field on the wire. An equally-conformant v0.1 deployment would omit `trust` from the Provenance objects and have the Guardian derive the same classification from `origin` + `source_id` against local policy.

### Request

```json
{
  "jsonrpc": "2.0",
  "method": "steps/toolCallRequest",
  "id": "req-001",
  "params": {
    "acs_version": "0.1.0",
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2026-04-30T10:30:00Z",
    "tenant_id": "acme-corp",
    "metadata": {
      "agent_id": "cursor-agent-01",
      "session_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
      "turn_id": "t-7",
      "platform": "cursor"
    },
    "payload": {
      "tool": { "name": "email.send" },
      "capability": "network.egress",
      "arguments": {
        "recipient": {
          "value": "manager@example.com",
          "provenance": {
            "provenance_id": "p1",
            "origin": "user_input",
            "source_id": "user-12345",
            "derived_from": []
          }
        },
        "body": {
          "value": "Project X summary: ...",
          "provenance": {
            "provenance_id": "p3",
            "origin": "agent_generated",
            "source_id": "llm-gpt-4",
            "derived_from": ["p2"]
          }
        }
      }
    }
  }
}
```

### Decision

The Guardian's deterministic layer evaluates against IBAC (does `email.send` to `manager@example.com` fall inside `Intent.parsed`?) and FIDES (does the trusted-recipient + possibly-tainted-body combination satisfy the P-F flow check?). Both pass.

```json
{
  "jsonrpc": "2.0",
  "id": "req-001",
  "result": {
    "type": "final",
    "acs_version": "0.1.0",
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "decision": "allow",
    "reasoning": "Recipient is trusted (user_input); body lineage is untrusted but the trusted recipient + possibly-tainted body combination is permitted by FIDES P-F under acme-baseline version v1.",
    "reason_codes": ["fides_p_f_check_passed", "ibac_capability_match"],
    "policy_references": [
      { "policy_id": "acme-baseline", "policy_version": "v1", "rule_id": "allow-trusted-recipients" },
      { "policy_id": "acme-ibac", "policy_version": "v1", "rule_id": "email-send-in-intent" }
    ],
    "policy_data": {
      "fides": { "recipient_trust": "trusted", "body_trust": "untrusted", "p_f_passed": true },
      "ibac": { "matched_capability": { "tool": "email.send", "resource": "manager@example.com" } }
    },
    "cited_provenance_ids": ["p1", "p3"],
    "metadata": {
      "evaluator": "deterministic",
      "evaluator_version": "opa-0.65",
      "evaluation_duration_ms": 12
    }
  }
}
```

## What the Guardian also does

The decision above is one of three concurrent obligations:

1. **Permit/deny/modify** — return the decision envelope to the Observed Agent (above).
2. **Trace** — emit an OTel span event `acs.decision` on the parent `gen_ai.tool.call` span, plus an OCSF Detection Finding (2004) when the decision is non-`allow`. See [Trace Events](../spec/trace/events.md).
3. **AgBOM** — `agbom/snapshot` was emitted earlier in the session; if the agent has registered new components since, `agbom/changed` is emitted before any content-bearing hook continues. See [Inspect](../spec/inspect/README.md).

## What different paradigms cite

The same wire format supports four published agent-security architectures and their compositions. Each cites different primitives in `policy_data` and `cited_provenance_ids`, but the envelope shape is identical. Below: one denial-shaped example per paradigm.

### IBAC — Intent-based authorization

User's committed Intent: `["summarize Project X"]`. The agent attempts `email.send` to a recipient outside that capability list. IBAC denies because the action is not in `Intent.parsed`. The user can extend `Intent.parsed` via the [ASK flow](../spec/instrument/specification.md#91-intent-extension-via-ask-normative) if deployment policy permits.

```json
{
  "decision": "deny",
  "reasoning": "Tool call email.send falls outside Intent.parsed for session abc-123.",
  "reason_codes": ["ibac_capability_mismatch"],
  "policy_references": [
    { "policy_id": "acme-ibac", "policy_version": "v1", "rule_id": "tool-call-must-be-in-intent" }
  ],
  "policy_data": {
    "ibac": {
      "requested_capability": { "tool": "email.send", "resource": "manager@example.com" },
      "intent_parsed": ["summarize.read"],
      "closest_match_in_intent": null
    }
  },
  "cited_provenance_ids": ["p1"]
}
```

### FIDES — Information flow control

A second tool call later in the same session: `email.send` with a `recipient` derived from a tool lookup (`origin: tool_output`, lineage includes untrusted retrieved content) and a body derived from the same retrieval. FIDES's P-T (planner-taint) check fails: a consequential outbound action depends on a fully-untrusted lineage with no trusted re-grounding.

```json
{
  "decision": "deny",
  "reasoning": "Outbound email.send recipient and body both derive from untrusted retrieval (provenance_id=p2); FIDES P-T denies under acme-baseline version v1.",
  "reason_codes": ["fides_p_t_failed", "untrusted_recipient_derivation"],
  "policy_references": [
    { "policy_id": "acme-baseline", "policy_version": "v1", "rule_id": "no-untrusted-recipient-derivation" }
  ],
  "policy_data": {
    "fides": {
      "p_t_passed": false,
      "violating_argument_path": ["recipient"],
      "lineage_origins": ["retrieved", "agent_generated"],
      "earliest_untrusted_provenance_id": "p2"
    }
  },
  "cited_provenance_ids": ["p2", "p4", "p5"]
}
```

### CaMeL — Program synthesis

A calendar agent: privileged LLM emits a program `schedule_meeting(attendees=USER_TEAM, time=NEXT_TUESDAY)`. The unprivileged LLM fills `attendees` from a forwarded calendar invite (which carried a hidden injection) instead of from the user's stated team list. CaMeL denies because the per-argument `derived_from` graph shows a consequential argument flowing from untrusted `retrieved` data along a path the program's capability declarations do not authorize.

```json
{
  "decision": "deny",
  "reasoning": "Argument 'attendees' derives from retrieved content (provenance_id=p7) along a path the synthesized program's capability set forbids.",
  "reason_codes": ["camel_argument_dependency_violation"],
  "policy_references": [
    { "policy_id": "acme-camel", "policy_version": "v1", "rule_id": "consequential-args-must-trace-to-trusted-input" }
  ],
  "policy_data": {
    "camel": {
      "argument_path": ["attendees"],
      "argument_lineage": ["p7", "p6"],
      "expected_lineage_root": { "origin": "user_input", "provenance_id": "p1" },
      "actual_lineage_root": { "origin": "retrieved", "source_id": "calendar-invite-2026-04-29" }
    }
  },
  "cited_provenance_ids": ["p1", "p6", "p7"]
}
```

### AARM — Cumulative-context tracking

Much later in a session that has touched untrusted email content, the agent attempts `payment.transfer`. The action's own arguments may look clean, but AARM's lookback against the session's accumulated `provenance_summary` shows untrusted retrieval has entered without an intervening trusted re-grounding. The deployment policy denies consequential financial actions in any tainted session window.

```json
{
  "decision": "deny",
  "reasoning": "Session abc-123 has processed retrieved content from step s-14 onward without trusted re-grounding; payment.transfer is consequential per acme-aarm version v1.",
  "reason_codes": ["aarm_cumulative_taint", "consequential_action_in_tainted_window"],
  "policy_references": [
    { "policy_id": "acme-aarm", "policy_version": "v1", "rule_id": "no-consequential-finance-after-untrusted-retrieval" }
  ],
  "policy_data": {
    "aarm": {
      "lookback_window": "session",
      "earliest_untrusted_step_id": "s-14",
      "untrusted_origins_seen": ["retrieved", "tool_output"],
      "entry_count_by_origin": { "user_input": 4, "retrieved": 2, "tool_output": 11, "agent_generated": 9 },
      "trusted_regrounding_since": null
    }
  },
  "cited_provenance_ids": ["p_s14", "p_s17", "p_s23"]
}
```

### Composition: IBAC outer + FIDES inner

In multi-paradigm deployments a single decision MAY cite all firing paradigms — `policy_references` carries one entry per paradigm, `reason_codes` aggregates, `policy_data` is keyed by paradigm. A request that fails IBAC's capability check *and* FIDES's flow check denies once with both contributions:

```json
{
  "decision": "deny",
  "reasoning": "Action outside Intent.parsed (IBAC) and arguments derived from untrusted retrieval (FIDES P-T); either alone would deny.",
  "reason_codes": ["ibac_capability_mismatch", "fides_p_t_failed"],
  "policy_references": [
    { "policy_id": "acme-ibac", "policy_version": "v1", "rule_id": "tool-call-must-be-in-intent" },
    { "policy_id": "acme-fides", "policy_version": "v1", "rule_id": "p-t-blocks-untrusted-derivation" }
  ],
  "policy_data": {
    "ibac": { "requested_capability": { "tool": "email.send" }, "intent_parsed": ["summarize.read"] },
    "fides": { "p_t_passed": false, "violating_argument_path": ["body"] }
  },
  "cited_provenance_ids": ["p1", "p2", "p3"]
}
```

Audit replay walks `policy_references` to reconstruct each paradigm's contribution independently.

## Read Next

- [Instrument](../spec/instrument/README.md)
- [Trace](../spec/trace/README.md)
- [Inspect](../spec/inspect/README.md)
- [Conformance Profiles](../spec/conformance.md)
