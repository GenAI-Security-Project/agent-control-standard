// Run against live Rust and TypeScript Guardians using the same AGT manifest.
// Both URLs may be overridden for a local checkout.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

const urls = [
  process.env.RUST_GUARDIAN_URL ?? "http://127.0.0.1:8787/acs",
  process.env.TS_GUARDIAN_URL ?? "http://127.0.0.1:8788/acs",
];
const sessionId = randomUUID();

function request(method, payload) {
  const id = randomUUID();
  return {
    jsonrpc: "2.0",
    method,
    id,
    params: {
      acs_version: "0.1.0",
      request_id: id,
      timestamp: "2026-09-07T16:00:37.962Z",
      metadata: { agent_id: "claude-code", session_id: sessionId },
      payload,
    },
  };
}

const cases = [
  ["handshake", request("handshake/hello", {})],
  ["deny", request("steps/toolCallRequest", {
    tool: { name: "Bash" },
    arguments: { command: { value: "echo rm -rf /" } },
    raw_command: "echo rm -rf /",
  })],
  ["allow", request("steps/toolCallRequest", {
    tool: { name: "Bash" },
    arguments: { command: { value: "ls -la" } },
    raw_command: "ls -la",
  })],
  ["result redaction", request("steps/toolCallResult", {
    tool: { name: "Bash" },
    exit_status: "success",
    outputs: [{ value: "TOKEN=ghp_ABCDEF123456" }],
  })],
  ["egress deny", request("steps/toolCallRequest", {
    tool: { name: "Bash" },
    arguments: { command: { value: "git clone https://github.com/openai/whisper" } },
    raw_command: "git clone https://github.com/openai/whisper",
  })],
  ["WebFetch allow", request("steps/toolCallRequest", {
    tool: { name: "WebFetch" },
    arguments: { url: { value: "https://docs.anthropic.com/en/docs" } },
  })],
  ["request redaction", request("steps/toolCallRequest", {
    tool: { name: "Bash" },
    arguments: { command: { value: "echo ghp_ABCDEF123456" } },
    raw_command: "echo ghp_ABCDEF123456",
  })],
  ["invalid payload", request("steps/toolCallRequest", { tool: { name: "Bash" } })],
  ["undispatched method", request("steps/sessionStart", {})],
];

for (const [name, input] of cases) {
  const responses = await Promise.all(urls.map(async (url) => {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
    });
    assert.equal(response.status, 200, `${name} at ${url} returned HTTP ${response.status}`);
    return response.json();
  }));
  assert.deepStrictEqual(responses[0], responses[1], `${name} differs`);
  console.log(`${name}: equal`);
}
