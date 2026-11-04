/**
 * Writes the committed sample trace (issue #266): what the reference
 * Guardian's OTLP export actually looks like, from a fixed set of synthetic
 * requests through the two live hook methods, plus one host-side failure run
 * through the audit converter.
 *
 *   bun run sample:trace
 *
 * Decisions come from the real AGT policy in policy/manifest.yaml. The one
 * change is a delay on the request carrying SLOW_MARKER, so that decision
 * finishes after the short timeout this script negotiates and the sample
 * shows a `timeout` failure. Every id is fixed and every value synthetic:
 * the sample is committed, and `acs.reasoning` and `acs.provenance.source_id`
 * go out as written.
 */
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { convertAuditLog } from "../packages/guardian/src/audit-to-otlp.ts";
import { createDeploymentBridge } from "../packages/guardian/src/deployment-bridge.ts";
import { buildServerHello } from "../packages/guardian/src/handshake.ts";
import { startGuardian } from "../packages/guardian/src/index.ts";
import { createOtelTraceExporter } from "../packages/guardian/src/otel-trace-exporter.ts";

export const SAMPLE_PATH = fileURLToPath(new URL("../samples/trace/acs-trace-sample.jsonl", import.meta.url));
const MANIFEST_PATH = fileURLToPath(new URL("../policy/manifest.yaml", import.meta.url));

/** How long the host waits for a decision in this sample, and how long the
 * marked request makes the Guardian take. Far enough apart that the stock
 * policy's own evaluation time never crosses the timeout. */
const TIMEOUT_MS = 1500;
const SLOW_MS = 2000;
const SLOW_MARKER = "sample-slow-marker";

const SESSION_ID = "5a3c1e7e-0b1d-4c6a-9e2f-7d4b8c0a1f01";

export type Scenario = {
  name: string;
  requestId: string;
  /** The `capability` the request carried, if any. */
  capability?: string;
  /** The `request_id_ref` a result carried, if any. */
  requestIdRef?: string;
  /** The decision the Guardian answered with, or none when it was never
   * reached. */
  decision?: "allow" | "deny";
};

/**
 * A forged request that reuses the allowed call's session and request id and
 * fails the schema (it carries no JSON-RPC id). The Guardian rejects it
 * before trusting it, so it is recorded as a `guardian.rejected_request`
 * span with the ids it claimed under rejected names, and the allowed call
 * keeps the only span under its pair (Trace Events, issue #283). It is not a
 * step, so it is not in SCENARIOS, which are keyed by the pair on a span.
 */
export const REJECTED = { name: "forged", claimedRequestId: "1b6f0c2a-3d4e-4f5a-8b6c-7d8e9f0a1b01", reason: "envelope_invalid" } as const;

/** Every step the sample holds, keyed by the request id its span carries. */
export const SCENARIOS: readonly Scenario[] = [
  { name: "allowed", requestId: "1b6f0c2a-3d4e-4f5a-8b6c-7d8e9f0a1b01", capability: "process.exec", decision: "allow" },
  { name: "result", requestId: "1b6f0c2a-3d4e-4f5a-8b6c-7d8e9f0a1b02", requestIdRef: "1b6f0c2a-3d4e-4f5a-8b6c-7d8e9f0a1b01", decision: "allow" },
  { name: "denied", requestId: "1b6f0c2a-3d4e-4f5a-8b6c-7d8e9f0a1b03", decision: "deny" },
  { name: "late", requestId: "1b6f0c2a-3d4e-4f5a-8b6c-7d8e9f0a1b05", decision: "allow" },
  { name: "unreachable", requestId: "1b6f0c2a-3d4e-4f5a-8b6c-7d8e9f0a1b06" },
];

function requestIdOf(name: string): string {
  return SCENARIOS.find((scenario) => scenario.name === name)!.requestId;
}

function envelope(method: string, requestId: string, payload: Record<string, unknown>, id: number | null): Record<string, unknown> {
  return {
    jsonrpc: "2.0",
    method,
    ...(id === null ? {} : { id }),
    params: {
      acs_version: "0.1.0",
      request_id: requestId,
      timestamp: new Date().toISOString(),
      metadata: { agent_id: "sample-agent", session_id: SESSION_ID },
      payload,
    },
  };
}

function bash(command: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { tool: { name: "Bash" }, arguments: { command: { value: command } }, ...extra };
}

/** The envelopes the Guardian receives, in order. */
function requests(): Record<string, unknown>[] {
  return [
    envelope("steps/toolCallRequest", requestIdOf("allowed"), bash("ls -la", { capability: "process.exec" }), 1),
    envelope(
      "steps/toolCallResult",
      requestIdOf("result"),
      {
        tool: { name: "Bash" },
        exit_status: "success",
        outputs: [{ value: "README.md\nsrc" }],
        request_id_ref: requestIdOf("allowed"),
      },
      2,
    ),
    // Two Provenance objects, one with a source_id and one without, so the
    // source_id column shows its "" padding.
    envelope(
      "steps/toolCallRequest",
      requestIdOf("denied"),
      {
        tool: { name: "Bash" },
        arguments: {
          command: {
            // Matches the stock policy's destructive-command rule without
            // naming a real path.
            value: "rm -rf .",
            provenance: { provenance_id: "prov-sample-1", origin: "user_input", source_id: "sample-user-1" },
          },
          note: { value: "cleanup", provenance: { provenance_id: "prov-sample-2", origin: "agent_generated" } },
        },
      },
      3,
    ),
    // No JSON-RPC id, so it fails the schema, and the allowed call's pair.
    envelope("steps/toolCallRequest", REJECTED.claimedRequestId, bash("pwd"), null),
    envelope("steps/toolCallRequest", requestIdOf("late"), bash(`echo ${SLOW_MARKER}`), 5),
  ];
}

/** The host's record of a step that never reached the Guardian, in the
 * audit-log format packages/host-adapter/src/audit-sink.ts writes. */
function unreachableAuditLine(): string {
  return `${JSON.stringify({
    seq: 1,
    recorded_at: new Date().toISOString(),
    session_id: SESSION_ID,
    method: "steps/toolCallRequest",
    rpc_id: requestIdOf("unreachable"),
    outcome: "proceeded",
    posture: "proceed",
    posture_source: "negotiated",
    failure: { kind: "transport", message: "connect ECONNREFUSED 127.0.0.1:8787" },
  })}\n`;
}

export async function generateSampleTrace(outPath: string = SAMPLE_PATH): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "acs-make-sample-trace-"));
  try {
    const guardianTrace = join(dir, "guardian.jsonl");
    const auditPath = join(dir, "audit.jsonl");
    const converterTrace = join(dir, "converter.jsonl");

    // The bridge the Guardian itself builds, built-in annotator included: the
    // stock manifest declares an egress annotator, and a bridge without it
    // fails every step closed, which is not what a sample should show.
    const real = createDeploymentBridge(MANIFEST_PATH);
    const bridge = {
      async evaluate(point: string, snapshot: Record<string, unknown>) {
        if (JSON.stringify(snapshot).includes(SLOW_MARKER)) {
          await Bun.sleep(SLOW_MS);
        }
        return real.evaluate(point, snapshot);
      },
    };
    const traceExporter = createOtelTraceExporter({
      filePath: guardianTrace,
      methodsEvaluated: buildServerHello().methods_evaluated,
      timeoutConfig: { default_ms: TIMEOUT_MS },
      posture: "fail_open",
    });
    const guardian = await startGuardian({ port: 0, manifestPath: MANIFEST_PATH, bridge, traceExporter });
    try {
      for (const request of requests()) {
        await fetch(guardian.url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(request) });
      }
    } finally {
      // Closing the Guardian shuts the exporter down, which flushes the file.
      await guardian.close();
    }

    writeFileSync(auditPath, unreachableAuditLine());
    const summary = await convertAuditLog(auditPath, converterTrace);
    if (summary.written !== 1) {
      throw new Error(`the audit converter wrote ${summary.written} span(s), expected 1`);
    }

    writeFileSync(outPath, readFileSync(guardianTrace, "utf8"));
    appendFileSync(outPath, readFileSync(converterTrace, "utf8"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (import.meta.main) {
  await generateSampleTrace();
  console.log(`wrote ${SAMPLE_PATH}`);
}
