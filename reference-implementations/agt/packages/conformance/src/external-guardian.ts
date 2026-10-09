import { createHmac, hkdfSync, randomUUID, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";

export const EXTERNAL_GUARDIAN_URL_ENV = "ACS_CONFORMANCE_GUARDIAN_URL";
export const EXTERNAL_GUARDIAN_SECRET_ENV = "ACS_CONFORMANCE_HMAC_SECRET_FILE";
export const EXTERNAL_GUARDIAN_KEY_ID_ENV = "ACS_CONFORMANCE_HMAC_KEY_ID";

type JsonObject = Record<string, unknown>;
type JsonRpcResponse = {
  jsonrpc?: unknown;
  id?: unknown;
  result?: JsonObject;
  error?: JsonObject;
};
type Post = (url: string, body: unknown) => Promise<JsonRpcResponse>;

export type ExternalGuardianCheck =
  | { ran: false; reason: string }
  | { ran: true; probes: number };

export function canonicalJSON(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("JCS input contains a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJSON).join(",")}]`;
  }
  if (typeof value !== "object") throw new Error(`JCS input contains ${typeof value}`);
  const object = value as JsonObject;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJSON(object[key])}`).join(",")}}`;
}

export function deriveSessionKey(secret: Uint8Array, sessionID: string): Buffer {
  return Buffer.from(hkdfSync("sha256", secret, Buffer.alloc(0), Buffer.from(sessionID, "utf8"), 32));
}

export function signCanonical(secret: Uint8Array, sessionID: string, canonical: string): Buffer {
  return createHmac("sha256", deriveSessionKey(secret, sessionID)).update(canonical).digest();
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function signRequest(envelope: JsonObject, secret: Uint8Array, sessionID: string, keyID: string): JsonObject {
  const signed = clone(envelope);
  const params = signed.params as JsonObject;
  const canonical = canonicalJSON(signed);
  params.signature = {
    algorithm: "HMAC-SHA256",
    value: signCanonical(secret, sessionID, canonical).toString("base64"),
    key_id: keyID,
  };
  return signed;
}

function verifyResponse(response: JsonRpcResponse, secret: Uint8Array, sessionID: string, expectedID: unknown, keyID: string): void {
  if (response.jsonrpc !== "2.0" || response.id !== expectedID) {
    throw new Error(`external Guardian returned an uncorrelated JSON-RPC response: ${JSON.stringify(response)}`);
  }
  const holderName = response.error === undefined ? "result" : "error";
  const holder = response[holderName] as JsonObject | undefined;
  const signature = holder?.signature as JsonObject | undefined;
  if (signature?.algorithm !== "HMAC-SHA256" || signature.key_id !== keyID || typeof signature.value !== "string") {
    throw new Error(`external Guardian returned no usable signature: ${JSON.stringify(response)}`);
  }
  const unsigned = clone(response) as JsonRpcResponse;
  delete (unsigned[holderName] as JsonObject).signature;
  const expected = signCanonical(secret, sessionID, canonicalJSON(unsigned));
  const received = Buffer.from(signature.value, "base64");
  if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
    throw new Error("external Guardian response signature does not verify");
  }
}

async function post(url: string, body: unknown): Promise<JsonRpcResponse> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`external Guardian returned HTTP ${response.status}`);
  return await response.json() as JsonRpcResponse;
}

function envelope(method: string, sessionID: string, agentID: string, payload: JsonObject, requestID = randomUUID()): JsonObject {
  return {
    jsonrpc: "2.0",
    method,
    id: requestID,
    params: {
      acs_version: "0.1.0",
      request_id: requestID,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: agentID, session_id: sessionID },
      payload,
    },
  };
}

async function signedPost(send: Post, url: string, request: JsonObject, secret: Uint8Array, sessionID: string, keyID: string): Promise<JsonRpcResponse> {
  const signed = signRequest(request, secret, sessionID, keyID);
  const response = await send(url, signed);
  verifyResponse(response, secret, sessionID, request.id, keyID);
  return response;
}

function expectError(response: JsonRpcResponse, code: number): void {
  if (response.error?.code !== code || response.result !== undefined) {
    throw new Error(`external Guardian returned ${JSON.stringify(response)}, expected error ${code}`);
  }
}

function expectDecision(response: JsonRpcResponse, disposition: string, requestID: unknown): void {
  if (response.error !== undefined || response.result?.decision !== disposition || response.result.request_id !== requestID) {
    throw new Error(`external Guardian returned ${JSON.stringify(response)}, expected correlated ${disposition}`);
  }
}

async function handshake(send: Post, url: string, secret: Uint8Array, keyID: string, sessionID: string, agentID: string, methods: string[]): Promise<JsonRpcResponse> {
  return signedPost(send, url, envelope("handshake/hello", sessionID, agentID, {
    acs_versions_supported: ["0.1.0"],
    methods_implemented: methods,
    transports_supported: ["http"],
    provenance_producer: "none",
    profiles_supported: ["acs-core"],
  }), secret, sessionID, keyID);
}

export async function checkExternalGuardian(environment: NodeJS.ProcessEnv = process.env, send: Post = post): Promise<ExternalGuardianCheck> {
  const url = environment[EXTERNAL_GUARDIAN_URL_ENV];
  const secretFile = environment[EXTERNAL_GUARDIAN_SECRET_ENV];
  if (url === undefined && secretFile === undefined) {
    return { ran: false, reason: `set ${EXTERNAL_GUARDIAN_URL_ENV} and ${EXTERNAL_GUARDIAN_SECRET_ENV}` };
  }
  if (url === undefined || secretFile === undefined) {
    throw new Error(`${EXTERNAL_GUARDIAN_URL_ENV} and ${EXTERNAL_GUARDIAN_SECRET_ENV} must be set together`);
  }
  const secret = readFileSync(secretFile);
  if (secret.length < 32) throw new Error("external Guardian HMAC secret is shorter than 32 bytes");
  const keyID = environment[EXTERNAL_GUARDIAN_KEY_ID_ENV] ?? "conformance";
  const agentID = "conformance-observed-agent";
  let probes = 0;

  const invalidJSONRPC = await send(url, { jsonrpc: "1.0", method: "steps/toolCallRequest", id: "bad", params: {} });
  if (invalidJSONRPC.error?.code !== -32600 || invalidJSONRPC.result !== undefined) {
    throw new Error(`invalid JSON-RPC was not refused at the JSON-RPC boundary: ${JSON.stringify(invalidJSONRPC)}`);
  }
  probes++;

  const beforeSession = randomUUID();
  const beforeRequest = envelope("steps/toolCallRequest", beforeSession, agentID, {
    tool: { name: "Bash" }, arguments: { command: { value: "ls -la" } }, raw_command: "ls -la",
  });
  expectError(await signedPost(send, url, beforeRequest, secret, beforeSession, keyID), -32003);
  probes++;

  const transportSession = randomUUID();
  const refusedTransport = envelope("handshake/hello", transportSession, agentID, {
    acs_versions_supported: ["0.1.0"], methods_implemented: ["steps/toolCallRequest"],
    transports_supported: ["stdio"], provenance_producer: "none", profiles_supported: ["acs-core"],
  });
  expectError(await signedPost(send, url, refusedTransport, secret, transportSession, keyID), -32000);
  probes++;

  const sessionID = randomUUID();
  const methods = ["steps/toolCallRequest", "steps/toolCallResult"];
  const hello = await handshake(send, url, secret, keyID, sessionID, agentID, methods);
  if (hello.result?.negotiated_version !== "0.1.0" || !Array.isArray(hello.result.methods_evaluated)) {
    throw new Error(`external Guardian returned an invalid ServerHello: ${JSON.stringify(hello)}`);
  }
  probes++;

  const allowed = envelope("steps/toolCallRequest", sessionID, agentID, {
    tool: { name: "Bash" }, arguments: { command: { value: "ls -la" } }, raw_command: "ls -la",
  });
  expectDecision(await signedPost(send, url, allowed, secret, sessionID, keyID), "allow", allowed.id);
  probes++;
  expectError(await signedPost(send, url, allowed, secret, sessionID, keyID), -32005);
  probes++;

  const invalidPayload = envelope("steps/toolCallRequest", sessionID, agentID, { tool: { name: "Bash" } });
  expectError(await signedPost(send, url, invalidPayload, secret, sessionID, keyID), -32602);
  probes++;
  expectError(await signedPost(send, url, invalidPayload, secret, sessionID, keyID), -32005);
  probes++;

  const unnegotiated = envelope("steps/userMessage", sessionID, agentID, {
    content: [{ type: "text", value: "hello" }],
  });
  expectError(await signedPost(send, url, unnegotiated, secret, sessionID, keyID), -32003);
  probes++;
  expectError(await signedPost(send, url, unnegotiated, secret, sessionID, keyID), -32005);
  probes++;

  return { ran: true, probes };
}
