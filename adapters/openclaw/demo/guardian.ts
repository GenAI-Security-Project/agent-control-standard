/**
 * Runs the TypeScript Guardian with its stock AGT policy for OpenClaw's
 * `exec` and `webfetch` tools. The policy reads `exec.command` and
 * `webfetch.url` (`reference-implementations/agt/mapping.yaml`).
 *
 * The demo writes the manifest at run time. AGT requires a plain policy-bundle
 * path. A path through `..` or a bundle of symlinks loads no data document,
 * which makes every rule allow.
 *
 * `bun demo/guardian.ts` listens on ACS_GUARDIAN_PORT (8787) and reads
 * ACS_HMAC_SECRET and ACS_HMAC_KEY_ID. `bun demo/guardian.ts --ask` requires
 * approval for every tool call. The Guardian names the approver.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** Approver named by the TypeScript Guardian for every ASK (`packages/guardian/src/map-verdict.ts`). */
export const GUARDIAN_APPROVER = "deployment-default";

export const AGT = new URL("../../../reference-implementations/agt/", import.meta.url).pathname;
const STOCK_BUNDLE = join(AGT, "policy/lib");

/** The stock bundle never asks. `approvers` copies it and requires approval for every tool call. */
export function writeManifest(dir: string, approvers?: string[]): string {
  mkdirSync(dir, { recursive: true });
  let bundle = STOCK_BUNDLE;
  if (approvers !== undefined) {
    bundle = join(dir, "lib");
    mkdirSync(bundle, { recursive: true });
    for (const file of readdirSync(STOCK_BUNDLE).filter((name) => name.endsWith(".rego") && !name.endsWith("_test.rego"))) {
      copyFileSync(join(STOCK_BUNDLE, file), join(bundle, file));
    }
    const data = JSON.parse(readFileSync(join(STOCK_BUNDLE, "data.json"), "utf8"));
    data.agt.defaults.config.approval = { required: true, approvers };
    writeFileSync(join(bundle, "data.json"), JSON.stringify(data));
  }
  const manifest = `agent_control_specification_version: "0.3.1-beta"
metadata:
  name: "acs-openclaw-adapter-demo"
policies:
  agt_stock:
    type: rego
    bundle: ${JSON.stringify(bundle)}
    query: data.agt.defaults.verdict
annotators:
  egress:
    type: classifier
intervention_points:
  pre_tool_call:
    policy_target: "$.tool_call.args.acs_policy_target"
    policy_target_kind: tool_args
    tool_name_from: "$.tool_call.name"
    annotations:
      egress:
        from: "$.tool_call.raw_command"
    policy:
      id: agt_stock
  post_tool_call:
    policy_target: "$.tool_result.outputs[0].value"
    policy_target_kind: tool_result
    tool_name_from: "$.tool_call.name"
    policy:
      id: agt_stock
tools:
  exec:
    type: Tool
    id: exec
    security_labels: [shell]
  webfetch:
    type: Tool
    id: webfetch
`;
  const path = join(dir, "manifest.yaml");
  writeFileSync(path, manifest);
  return path;
}

export function startGuardian(manifestPath: string, env: Record<string, string>): ChildProcess {
  return spawn(process.execPath, ["run", "packages/guardian/src/main.ts"], {
    cwd: AGT,
    env: { ...process.env, ACS_MANIFEST_PATH: manifestPath, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
}

if (import.meta.main) {
  const approvers = process.argv.includes("--ask") ? [GUARDIAN_APPROVER] : undefined;
  const child = startGuardian(writeManifest(join(process.cwd(), ".acs/demo"), approvers), {});
  child.stdout?.pipe(process.stdout);
  child.stderr?.pipe(process.stderr);
  child.on("exit", (code) => process.exit(code ?? 1));
}
