/**
 * Reads `plugins.entries.acs-guardian-client.config` and loads the HMAC key.
 * `openclaw.plugin.json` declares the config shape. This module validates it
 * again because the plugin must not rely on host validation.
 */
import { readFileSync } from "node:fs";
import { DEFAULT_TIMEOUT_MS, type HmacKey } from "./host-adapter.ts";

/** Time reserved from each hook deadline to record the Guardian's answer in OpenClaw state. */
export const STATE_RESERVE_MS = 250;

export type FailurePosture = "closed" | "negotiated";

export type PluginConfig = {
  guardianUrl: string;
  hmacKey: HmacKey;
  failurePosture: FailurePosture;
  /** Maximum time for a hook's Guardian requests, including handshakes. */
  deadlineMs: number;
  /** Timeout requested from OpenClaw for each hook; longer than `deadlineMs`. */
  hookTimeoutMs: number;
  /** Interval between gateway `system/ping` probes (§13). */
  pingIntervalMs: number;
  /** Maximum messages kept per session for a run that is not yet admitted. */
  maxUndecidedMessages: number;
  /** Maximum attachment bytes sent for one inbound message. */
  maxAttachmentBytes: number;
  auditLog: string;
};

/** §10: an HMAC-SHA256 secret holds at least 32 bytes. */
export const MIN_SECRET_BYTES = 32;

const DEFAULTS = {
  // ACS's own default: the posture the Guardian negotiates applies.
  failurePosture: "negotiated",
  // OpenClaw's own default for its modifying hooks (src/plugins/hooks.ts).
  hookTimeoutMs: 15_000,
  pingIntervalMs: 30_000,
  maxUndecidedMessages: 20,
  // Base64 of 512 KiB and its envelope fit the TypeScript Guardian's 1 MiB request limit.
  maxAttachmentBytes: 524_288,
  auditLog: ".acs/audit.jsonl",
} as const;

const KNOWN_KEYS = new Set([
  "guardianUrl",
  "hmacKeyId",
  "hmacSecretFile",
  "hmacSecretEnv",
  "failurePosture",
  "deadlineMs",
  "hookTimeoutMs",
  "pingIntervalMs",
  "maxUndecidedMessages",
  "maxAttachmentBytes",
  "auditLog",
]);

export class PluginConfigError extends Error {
  constructor(readonly problems: string[]) {
    super(`ACS plugin config is invalid: ${problems.join("; ")}`);
    this.name = "PluginConfigError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

// The Guardian and adapter share the base64 format in reference-implementations/README.md.
function readSecret(raw: Record<string, unknown>, env: NodeJS.ProcessEnv, problems: string[]): Buffer | undefined {
  const encoded = readSecretText(raw, env, problems);
  if (encoded === undefined) {
    return undefined;
  }
  const text = encoded.trim();
  const secret = Buffer.from(text, "base64");
  if (secret.toString("base64") !== text) {
    problems.push("the HMAC secret is not standard base64");
    return undefined;
  }
  if (secret.length < MIN_SECRET_BYTES) {
    problems.push(`the HMAC secret decodes to ${secret.length} bytes; it must hold at least ${MIN_SECRET_BYTES}`);
    return undefined;
  }
  return secret;
}

function readSecretText(raw: Record<string, unknown>, env: NodeJS.ProcessEnv, problems: string[]): string | undefined {
  const hasFile = raw.hmacSecretFile !== undefined;
  const hasEnv = raw.hmacSecretEnv !== undefined;
  if (hasFile === hasEnv) {
    problems.push('name the HMAC secret with exactly one of "hmacSecretFile" or "hmacSecretEnv"');
    return undefined;
  }
  if (hasFile) {
    if (!nonEmptyString(raw.hmacSecretFile)) {
      problems.push('"hmacSecretFile" must be a non-empty path');
      return undefined;
    }
    try {
      return readFileSync(raw.hmacSecretFile, "utf8");
    } catch (error) {
      problems.push(`"hmacSecretFile" ${JSON.stringify(raw.hmacSecretFile)} cannot be read: ${(error as Error).message}`);
      return undefined;
    }
  }
  if (!nonEmptyString(raw.hmacSecretEnv)) {
    problems.push('"hmacSecretEnv" must name an environment variable');
    return undefined;
  }
  const value = env[raw.hmacSecretEnv];
  if (!nonEmptyString(value)) {
    problems.push(`environment variable ${raw.hmacSecretEnv} named by "hmacSecretEnv" is unset or empty`);
    return undefined;
  }
  return value;
}

export function parseConfig(raw: unknown, env: NodeJS.ProcessEnv = process.env): PluginConfig {
  const problems: string[] = [];
  if (!isRecord(raw)) {
    throw new PluginConfigError(["the config is not an object"]);
  }
  const unknown = Object.keys(raw).filter((key) => !KNOWN_KEYS.has(key));
  if (unknown.length > 0) {
    problems.push(`unknown keys ${unknown.join(", ")}`);
  }

  if (!nonEmptyString(raw.guardianUrl) || !URL.canParse(raw.guardianUrl)) {
    problems.push('"guardianUrl" must be the Guardian\'s ACS endpoint URL');
  }
  if (!nonEmptyString(raw.hmacKeyId)) {
    problems.push('"hmacKeyId" is required: the key_id the Guardian knows the HMAC secret by');
  }
  const secret = readSecret(raw, env, problems);

  const failurePosture = raw.failurePosture ?? DEFAULTS.failurePosture;
  if (failurePosture !== "closed" && failurePosture !== "negotiated") {
    problems.push('"failurePosture" must be "closed" or "negotiated"');
  }
  const deadlineMs = raw.deadlineMs ?? DEFAULT_TIMEOUT_MS;
  if (typeof deadlineMs !== "number" || !Number.isInteger(deadlineMs) || deadlineMs <= STATE_RESERVE_MS) {
    problems.push(`"deadlineMs" must be an integer above ${STATE_RESERVE_MS}, the part of it kept to record the Guardian's answer`);
  }
  const hookTimeoutMs = raw.hookTimeoutMs ?? DEFAULTS.hookTimeoutMs;
  if (typeof hookTimeoutMs !== "number" || !Number.isInteger(hookTimeoutMs) || hookTimeoutMs < 1) {
    problems.push('"hookTimeoutMs" must be a positive integer');
  } else if (typeof deadlineMs === "number" && deadlineMs >= hookTimeoutMs) {
    problems.push(`"deadlineMs" (${deadlineMs}) must be shorter than "hookTimeoutMs" (${hookTimeoutMs}), or OpenClaw ends a hook before the plugin answers`);
  }
  const pingIntervalMs = raw.pingIntervalMs ?? DEFAULTS.pingIntervalMs;
  if (typeof pingIntervalMs !== "number" || !Number.isInteger(pingIntervalMs) || pingIntervalMs < 1) {
    problems.push('"pingIntervalMs" must be a positive integer');
  }
  const maxUndecidedMessages = raw.maxUndecidedMessages ?? DEFAULTS.maxUndecidedMessages;
  if (typeof maxUndecidedMessages !== "number" || !Number.isInteger(maxUndecidedMessages) || maxUndecidedMessages < 1) {
    problems.push('"maxUndecidedMessages" must be a positive integer');
  }
  const maxAttachmentBytes = raw.maxAttachmentBytes ?? DEFAULTS.maxAttachmentBytes;
  if (typeof maxAttachmentBytes !== "number" || !Number.isInteger(maxAttachmentBytes) || maxAttachmentBytes < 0) {
    problems.push('"maxAttachmentBytes" must be a non-negative integer');
  }
  const auditLog = raw.auditLog ?? DEFAULTS.auditLog;
  if (!nonEmptyString(auditLog)) {
    problems.push('"auditLog" must be a non-empty path');
  }

  if (problems.length > 0 || secret === undefined) {
    throw new PluginConfigError(problems);
  }
  return {
    guardianUrl: raw.guardianUrl as string,
    hmacKey: { keyId: raw.hmacKeyId as string, secret },
    failurePosture: failurePosture as FailurePosture,
    deadlineMs: deadlineMs as number,
    hookTimeoutMs: hookTimeoutMs as number,
    pingIntervalMs: pingIntervalMs as number,
    maxUndecidedMessages: maxUndecidedMessages as number,
    maxAttachmentBytes: maxAttachmentBytes as number,
    auditLog: auditLog as string,
  };
}
