import { describe, expect, it } from "bun:test";
import { mkdtempSync, rmdirSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startGuardian } from "../packages/guardian/src/index.ts";
import { tailEnvelopeLog, type EnvelopeLogEntry } from "../packages/inspector/src/tail-envelope-log.ts";
import { outcomeMessageOf, renderOutcome, type OutcomeMessage } from "../packages/inspector/src/render.ts";

/**
 * The contract test for the envelope log. The Guardian writes it; the
 * Inspector declares its own EnvelopeLogEntry and reads it back.
 * If either side renames a field, adds a required one, or changes a type,
 * this is what fails -- nothing else would, because the two never share a
 * type.
 */
function toolCallEnvelope(command: string, id: number): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    method: "steps/toolCallRequest",
    id,
    params: {
      acs_version: "0.1.0",
      request_id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "agent-1", session_id: crypto.randomUUID() },
      payload: { tool: { name: "run_shell" }, arguments: { command: { value: command } } },
    },
  };
}

async function take(
  tail: AsyncGenerator<EnvelopeLogEntry, void, void>,
  count: number,
  controller: AbortController,
): Promise<EnvelopeLogEntry[]> {
  const out: EnvelopeLogEntry[] = [];
  const deadline = setTimeout(() => controller.abort(), 5000);
  try {
    for await (const entry of tail) {
      out.push(entry);
      if (out.length >= count) {
        break;
      }
    }
  } finally {
    clearTimeout(deadline);
    controller.abort();
  }
  return out;
}

describe("envelope log round trip: Guardian sink -> Inspector tail -> decision badge", () => {
  it("a denied tool call arrives as a paired request/response the Inspector can render", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-roundtrip-"));
    const logPath = join(dir, "envelopes.jsonl");
    const guardian = await startGuardian({
      port: 0,
      manifestPath: "policy/manifest.yaml",
      envelopeLogPath: logPath,
    });
    const controller = new AbortController();

    try {
      await fetch(guardian.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(toolCallEnvelope("rm -rf /", 77)),
      });

      const tail = tailEnvelopeLog({ path: logPath, fromStart: true, pollMs: 10, signal: controller.signal });
      const [request, response] = await take(tail, 2, controller);

      // Every field the Inspector's EnvelopeLogEntry declares must actually
      // be present and correctly typed on what the Guardian wrote.
      expect(request?.seq).toBe(1);
      expect(response?.seq).toBe(2);
      expect(typeof request?.recorded_at).toBe("string");
      expect(typeof response?.recorded_at).toBe("string");
      expect(request?.direction).toBe("request");
      expect(response?.direction).toBe("response");
      expect(request?.method).toBe("steps/toolCallRequest");
      expect(response?.method).toBe("steps/toolCallRequest");
      expect(request?.rpc_id).toBe(77);
      expect(response?.rpc_id).toBe(77);

      // ...and the badge reads a real AGT-backed decision off it. Two steps,
      // not one: outcomeMessageOf turns the log line into what the step
      // reported, and the renderer renders that message. Both halves are
      // exercised here deliberately -- the round trip's claim is
      // that a real Guardian's real output survives all the way to a rendered
      // badge, including that it arrives as a decision rather than an error.
      const message = outcomeMessageOf(response as EnvelopeLogEntry);
      expect(message?.kind).toBe("decision");
      expect(renderOutcome(message as OutcomeMessage)).toContain("DENY");
    } finally {
      controller.abort();
      await guardian.close();
      unlinkSync(logPath);
      rmdirSync(dir);
    }
  });
});
