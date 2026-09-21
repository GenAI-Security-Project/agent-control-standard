import { describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalJSON, checkExternalGuardian, deriveSessionKey, signCanonical } from "../src/external-guardian.ts";

type Vector = { signed: Record<string, unknown>; signing_input: string };
type Vectors = {
  ikm_hex: string;
  session_id: string;
  session_key_hex: string;
  request: Vector;
  response: Vector;
};

describe("the external Guardian signer", () => {
  const vectors = JSON.parse(readFileSync("../agt-go/internal/envelope/testdata/vectors.json", "utf8")) as Vectors;
  const secret = Buffer.from(vectors.ikm_hex, "hex");

  it("matches the Go Guardian's independent JCS and HKDF vectors", () => {
    expect(deriveSessionKey(secret, vectors.session_id).toString("hex")).toBe(vectors.session_key_hex);
    for (const [holderName, vector] of [["params", vectors.request], ["result", vectors.response]] as const) {
      const unsigned = structuredClone(vector.signed);
      const holder = unsigned[holderName] as Record<string, unknown>;
      const signature = holder.signature as { value: string };
      delete holder.signature;
      const canonical = canonicalJSON(unsigned);
      expect(canonical).toBe(vector.signing_input);
      expect(signCanonical(secret, vectors.session_id, canonical).toString("base64")).toBe(signature.value);
    }
  });
});

describe("the external Guardian wire checks", () => {
  it("does not require handshake restart", async () => {
    const directory = mkdtempSync(join(tmpdir(), "acs-conformance-"));
    const secretFile = join(directory, "hmac-secret");
    const secret = Buffer.alloc(32, 7);
    writeFileSync(secretFile, secret);
    const keyID = "test-key";
    const seen = new Set<unknown>();
    let acceptedHandshakes = 0;

    const signed = (request: Record<string, unknown>, holderName: "result" | "error", holder: Record<string, unknown>) => {
      const params = request.params as Record<string, unknown>;
      const metadata = params.metadata as { session_id: string };
      const response = { jsonrpc: "2.0", id: request.id, [holderName]: holder };
      const signature = signCanonical(secret, metadata.session_id, canonicalJSON(response)).toString("base64");
      holder.signature = { algorithm: "HMAC-SHA256", key_id: keyID, value: signature };
      return response;
    };
    const error = (request: Record<string, unknown>, code: number) => signed(request, "error", { code, message: "refused" });

    try {
      const result = await checkExternalGuardian({
        ACS_CONFORMANCE_GUARDIAN_URL: "http://guardian.test",
        ACS_CONFORMANCE_HMAC_SECRET_FILE: secretFile,
        ACS_CONFORMANCE_HMAC_KEY_ID: keyID,
      }, async (_url, body) => {
        const request = body as Record<string, unknown>;
        if (request.jsonrpc !== "2.0") return { jsonrpc: "2.0", id: request.id, error: { code: -32600 } };
        if (seen.has(request.id)) return error(request, -32005);
        seen.add(request.id);

        const params = request.params as Record<string, unknown>;
        const payload = params.payload as Record<string, unknown>;
        if (request.method === "handshake/hello") {
          if ((payload.transports_supported as string[]).includes("stdio")) return error(request, -32000);
          acceptedHandshakes++;
          if (acceptedHandshakes > 1) return error(request, -32000);
          return signed(request, "result", {
            negotiated_version: "0.1.0",
            methods_evaluated: payload.methods_implemented,
          });
        }
        if (request.method === "steps/userMessage") return error(request, -32003);
        if (payload.arguments === undefined) return error(request, -32602);
        if (acceptedHandshakes === 0) return error(request, -32003);
        return signed(request, "result", { request_id: request.id, decision: "allow" });
      });

      expect(result).toEqual({ ran: true, probes: 10 });
      expect(acceptedHandshakes).toBe(1);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
