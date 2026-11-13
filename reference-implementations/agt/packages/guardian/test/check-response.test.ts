import { describe, expect, it } from "bun:test";
import { checkResponse } from "../src/check-response.ts";
import { buildServerHello } from "../src/handshake.ts";

// A real UUID, not a readable placeholder: response-envelope.json's
// AcsResult.request_id is `format: "uuid"`, and this field is what the
// Guardian actually sends -- finalResult (acs-result.ts) copies it straight
// from `params.request_id`, which validateEnvelope already confirmed
// matches this same format before any response exists to build. The same
// placeholder UUID validate-envelope.test.ts already uses for the inbound
// side, reused here rather than a second one invented for the outbound side.
const PLACEHOLDER_REQUEST_ID = "8f14e45f-ceea-467e-bd5f-1d4d9a4e0c8f";

describe("checkResponse -- validateEnvelope's outbound counterpart", () => {
  it("accepts a decision response the Guardian actually builds", () => {
    expect(
      checkResponse({
        jsonrpc: "2.0",
        id: "rpc-1",
        result: {
          type: "final",
          acs_version: "0.1.0",
          request_id: PLACEHOLDER_REQUEST_ID,
          decision: "allow",
        },
      }),
    ).toEqual({ status: "checked_valid" });
  });

  it("rejects a decision response carrying a disposition ACS does not define", () => {
    const outcome = checkResponse({
      jsonrpc: "2.0",
      id: "rpc-1",
      // request_id is the placeholder UUID here too, not a non-UUID literal:
      // with a non-UUID request_id, this test would pass for the wrong
      // reason -- errors[0] would be the request_id format failure, not the
      // decision enum failure, so the assertion below would hold
      // identically if "warn" became a legal ACS decision tomorrow. A valid
      // request_id isolates the one field this test is actually about.
      result: { type: "final", acs_version: "0.1.0", request_id: PLACEHOLDER_REQUEST_ID, decision: "warn" },
    });

    expect(outcome).toEqual({
      status: "checked_invalid",
      pointer: "/result/decision",
      message: "/result/decision must be equal to one of the allowed values",
    });
  });

  it("reports a decision response that merely lost its decision as invalid, not as a ServerHello", () => {
    // No `decision`, same as a ServerHello, but none of the ServerHello's
    // required fields either -- a malformed AcsResult. It matches neither
    // branch of the envelope's `oneOf`, so it must be reported invalid, not
    // excused as the other shape.
    const outcome = checkResponse({
      jsonrpc: "2.0",
      id: "rpc-1",
      result: { type: "final", acs_version: "0.1.0", request_id: PLACEHOLDER_REQUEST_ID },
    });

    expect(outcome).toEqual({
      status: "checked_invalid",
      pointer: "/result",
      message: "/result must have required property 'decision'",
    });
  });

  it("accepts the Guardian's own ServerHello, which the envelope has expressed since spec v0.1.2", () => {
    const outcome = checkResponse({
      jsonrpc: "2.0",
      id: "rpc-1",
      result: buildServerHello({ ACS_ON_DECISION_FAILURE: "proceed" }),
    });

    expect(outcome).toEqual({ status: "checked_valid" });
  });

  it("reports a ServerHello missing one of its own required fields as invalid, not excused", () => {
    const { timeout_config: _dropped, ...partial } = buildServerHello({ ACS_ON_DECISION_FAILURE: "proceed" });
    const outcome = checkResponse({ jsonrpc: "2.0", id: "rpc-1", result: partial });

    expect(outcome.status).toBe("checked_invalid");
  });

  it("accepts a JSON-RPC error response, which the envelope schema does express", () => {
    expect(
      checkResponse({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32700, message: "Parse error" },
      }),
    ).toEqual({ status: "checked_valid" });
  });
});
