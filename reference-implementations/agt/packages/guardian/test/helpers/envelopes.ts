/**
 * Request envelopes for the guardian package's tests. Shared because both
 * the exporter tests and main.test.ts post a real `steps/toolCallRequest`.
 */

export function makeEnvelope(
  method: string,
  payload: Record<string, unknown>,
  overrides: { id?: number | null; requestId?: string; sessionId?: string } = {},
): Record<string, unknown> {
  const { id = 1, requestId = crypto.randomUUID(), sessionId = crypto.randomUUID() } = overrides;
  return {
    jsonrpc: "2.0",
    method,
    ...(id === null ? {} : { id }),
    params: {
      acs_version: "0.1.0",
      request_id: requestId,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "agent-1", session_id: sessionId },
      payload,
    },
  };
}

/** Carries `capability`, which hooks/tool-call-request.json declares
 * optional and the mapping requires on the span, so a span built from this
 * envelope has every required attribute the mapping names. */
export function toolCallEnvelope(command: string, overrides: { id?: number | null; requestId?: string; sessionId?: string } = {}) {
  return makeEnvelope(
    "steps/toolCallRequest",
    { tool: { name: "run_shell" }, capability: "process.exec", arguments: { command: { value: command } } },
    overrides,
  );
}
