/**
 * The Guardian's standalone CLI entrypoint -- `bun run guardian`.
 *
 * The tests use the Guardian in-process, calling `startGuardian` directly. The
 * demo needs it as a long-running process a hook subprocess can reach over
 * HTTP, so this file makes the runbook's "start the Guardian" step a real
 * command. Not re-exported from `./index.ts`: this is a process entrypoint,
 * not a library call.
 *
 * `ACS_GUARDIAN_PORT` defaults to 8787 -- the same default port
 * `hosts/claude-code/acs-hook.ts` assumes for `ACS_GUARDIAN_URL` when that
 * env var is unset, so the runbook and the shim agree without either
 * hardcoding the other's value.
 *
 * `ACS_GUARDIAN_HOST` is left unset by default, which leaves startGuardian's
 * loopback bind in place -- see server.ts's header for why an unauthenticated
 * endpoint defaults to the narrowest bind. This is where a deployment that
 * needs a routable one says so, since env is this process's configuration
 * surface and server.ts reads none itself.
 */
import { buildServerHello } from "./handshake.ts";
import { startGuardian } from "./server.ts";

const DEFAULT_PORT = 8787;
const DEFAULT_MANIFEST_PATH = "policy/manifest.yaml";
const DEFAULT_ENVELOPE_LOG = ".acs/envelopes.jsonl";
const DEFAULT_SESSION_CONTEXT_LOG = ".acs/session-context.jsonl";

const port = Number(process.env.ACS_GUARDIAN_PORT ?? DEFAULT_PORT);
const hostname = process.env.ACS_GUARDIAN_HOST;
const manifestPath = process.env.ACS_MANIFEST_PATH ?? DEFAULT_MANIFEST_PATH;
const envelopeLogPath = process.env.ACS_ENVELOPE_LOG ?? DEFAULT_ENVELOPE_LOG;
const sessionContextLog = process.env.ACS_SESSION_CONTEXT_LOG ?? DEFAULT_SESSION_CONTEXT_LOG;

// Read and validate the posture BEFORE starting the server. Not the audit
// sink's path: that file is the host's, written by the hook, not by
// this process, so this Guardian has no way to know it. What this process
// does know -- and is about to declare to every session that handshakes --
// is the posture. Calling buildServerHello() with no argument here reads
// the same `process.env.ACS_ON_DECISION_FAILURE` a real handshake would, so
// this line and the first handshake always agree. Reading it first, not
// last, means an invalid override value throws before "Guardian listening"
// ever prints -- an operator watching the terminal sees a crash, never a
// healthy start immediately followed by one.
const posture = buildServerHello().on_decision_failure;

const guardian = await startGuardian({ port, hostname, manifestPath, envelopeLogPath, sessionContextLog });
console.log(`Guardian listening at ${guardian.url}`);
console.log(`Envelope log: ${envelopeLogPath}`);
console.log(`Session context log: ${sessionContextLog}`);
console.log(`Failure posture: ${posture}   (override with ACS_ON_DECISION_FAILURE=deny)`);
