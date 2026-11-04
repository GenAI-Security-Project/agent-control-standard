/** Tests run the TypeScript Guardian and, when built, the Go Guardian. Both use the policy named by `demo/guardian.ts`. */
import { spawn, type ChildProcess } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { AGT, startGuardian } from "../demo/guardian.ts";
import type { HmacKey } from "../host-adapter.ts";

const AGT_GO = join(AGT, "../agt-go");

/** `askApprover`: the human every ASK names; the TypeScript Guardian reads it from the manifest instead. */
export type StartOptions = { manifestPath: string; onDecisionFailure: "proceed" | "deny"; key: HmacKey; askApprover?: string };
export type Launcher = {
  name: string;
  unavailable(): string | undefined;
  start(options: StartOptions): Promise<RunningGuardian>;
  /** Whether a manifest of the test's own can make it answer ASK. */
  asks: boolean;
  /** Whether it evaluates the run's own steps, not only the tool steps (its ServerHello's `methods_evaluated`). */
  evaluatesRunSteps: boolean;
  requiredInCi: boolean;
};
export type RunningGuardian = { url: string; stop(): void };

function listen(child: ChildProcess, scratch: string): Promise<RunningGuardian> {
  let output = "";
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`the Guardian did not start: ${output}`)), 30_000);
    const read = (chunk: Buffer) => {
      output += chunk.toString();
      const match = /Guardian listening at (http:\/\/\S+\/acs)/.exec(output);
      if (match) {
        clearTimeout(timer);
        resolve({
          url: match[1]!,
          stop: () => {
            child.kill();
            rmSync(scratch, { recursive: true, force: true });
          },
        });
      }
    };
    child.stdout?.on("data", read);
    child.stderr?.on("data", read);
    child.on("exit", (code) => reject(new Error(`the Guardian exited with ${code}: ${output}`)));
  });
}

export const typescript: Launcher = {
  name: "TypeScript",
  asks: true,
  evaluatesRunSteps: false,
  requiredInCi: true,
  unavailable: () => (existsSync(join(AGT, "node_modules")) ? undefined : "run `bun install` in reference-implementations/agt"),
  start({ manifestPath, onDecisionFailure, key }) {
    const scratch = mkdtempSync(join(tmpdir(), "acs-openclaw-ts-guardian-"));
    const child = startGuardian(manifestPath, {
      ACS_GUARDIAN_PORT: "0",
      ACS_GUARDIAN_HOST: "127.0.0.1",
      ACS_HMAC_SECRET: key.secret.toString("base64"),
      ACS_HMAC_KEY_ID: key.keyId,
      ACS_ON_DECISION_FAILURE: onDecisionFailure,
      ACS_ENVELOPE_LOG: join(scratch, "envelopes.jsonl"),
      ACS_SESSION_CONTEXT_LOG: join(scratch, "session-context.jsonl"),
    });
    return listen(child, scratch);
  },
};

/** Finds `ACS_GUARDIAN_BIN` or the first binary built under `<agt-go>/.acs/bin`. */
function goGuardian(): { binary: string; dir: string; opaPath: string } | undefined {
  const fromTree = (): string | undefined => {
    const builds = join(AGT_GO, ".acs/bin");
    return existsSync(builds) ? readdirSync(builds).map((target) => join(builds, target, "agt/acs-guardian")).find((path) => existsSync(path)) : undefined;
  };
  const binary = process.env.ACS_GUARDIAN_BIN ?? fromTree();
  if (binary === undefined) {
    return undefined;
  }
  const dir = resolve(binary, "../../../../..");
  const target = basename(resolve(binary, "../.."));
  return { binary, dir, opaPath: join(dir, ".acs/agt", target, "bin") };
}

export const go: Launcher = {
  name: "Go",
  asks: true,
  evaluatesRunSteps: true,
  requiredInCi: false,
  unavailable: () =>
    goGuardian() !== undefined
      ? undefined
      : existsSync(AGT_GO)
        ? "run `make build` in reference-implementations/agt-go"
        : "reference-implementations/agt-go/ is not in this tree, and ACS_GUARDIAN_BIN names no built Go Guardian",
  start({ manifestPath, onDecisionFailure, key, askApprover }) {
    const scratch = mkdtempSync(join(tmpdir(), "acs-openclaw-go-guardian-"));
    const secretFile = join(scratch, "hmac-secret");
    writeFileSync(secretFile, key.secret.toString("base64"), { mode: 0o600 });
    const { binary, dir, opaPath } = goGuardian()!;
    copyFileSync(join(AGT, "mapping.yaml"), join(dirname(manifestPath), "mapping.yaml"));
    const child = spawn(binary, ["--config", "guardian.yaml"], {
      cwd: dir,
      env: {
        ...process.env,
        ACS__SERVER__PORT: "0",
        ACS__SECURITY__HMAC_KEY_ID: key.keyId,
        ACS__SECURITY__HMAC_SECRET_FILE: secretFile,
        // The Go Guardian reads both files from its deployment directory.
        // `writeManifest` wrote the manifest there; copy the reference mapping beside it.
        ACS__POLICY__DEPLOYMENT_DIR: dirname(manifestPath),
        ACS__POLICY__MANIFEST: basename(manifestPath),
        ACS__POLICY__MAPPING: "mapping.yaml",
        ACS__POLICY__OPA_PATH: opaPath,
        ACS__PROTOCOL__ON_DECISION_FAILURE: onDecisionFailure,
        ACS__AUDIT__ENVELOPE_LOG: join(scratch, "envelopes.jsonl"),
        ACS__AUDIT__EVENT_LOG: join(scratch, "events.jsonl"),
        // OpenClaw routes an ASK to a person, so this Guardian sends the ASK instead of its substitute.
        ...(askApprover === undefined ? {} : { ACS__POLICY__ASK_SUBSTITUTION: "none", ACS__POLICY__ASK_APPROVER__TYPE: "human", ACS__POLICY__ASK_APPROVER__ID: askApprover }),
      },
    });
    return listen(child, scratch);
  },
};
