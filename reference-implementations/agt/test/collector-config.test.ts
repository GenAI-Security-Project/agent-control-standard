import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * otel-collector.yaml as committed (issue #276). Structure only: the proof
 * that otelcol-contrib 0.162.0 accepts it and behaves is the end-to-end run
 * in the PR. What this pins is what a later edit could quietly undo.
 */
const CONFIG_PATH = fileURLToPath(new URL("../otel-collector.yaml", import.meta.url));
const IMAGE = "otel/opentelemetry-collector-contrib:0.162.0@sha256:39923a8e431bd1f57be82411999d389fcfe40857492e4365456d97a4c1f74be6";
const text = readFileSync(CONFIG_PATH, "utf8");
const config = Bun.YAML.parse(text) as {
  receivers: { otlp: { protocols: { http: { endpoint: string } } } };
  exporters: { file: { path: string; append?: unknown; create_directory?: unknown; directory_permissions?: unknown } };
  service: { telemetry?: { metrics?: { level?: string } } };
};

describe("otel-collector.yaml", () => {
  it("listens on loopback only, as a literal: an empty env var would bind every interface", () => {
    expect(config.receivers.otlp.protocols.http.endpoint).toBe("127.0.0.1:4318");
    expect(text).not.toMatch(/\$\{/);
  });

  it("publishes the container's port on host loopback only", () => {
    expect(text).toContain("-p 127.0.0.1:4318:4318");
    expect(text).not.toMatch(/-p 4318:4318/);
  });

  it("appends across restarts and creates its directory owner-only", () => {
    expect(config.exporters.file.append).toBe(true);
    expect(config.exporters.file.create_directory).toBe(true);
    expect(config.exporters.file.directory_permissions).toBe("0700");
  });

  it("turns off its own metrics endpoint, so port 8888 cannot clash", () => {
    expect(config.service.telemetry?.metrics?.level).toBe("none");
  });

  it("names the digest-pinned image", () => {
    expect(text).toContain(IMAGE);
  });
});

const README_PATH = fileURLToPath(new URL("../README.md", import.meta.url));
const readme = readFileSync(README_PATH, "utf8");

describe("the walkthrough's collector step", () => {
  it("names the same digest-pinned image and loopback-only port as the config", () => {
    expect(readme).toContain(IMAGE);
    expect(readme).toContain("-p 127.0.0.1:4318:4318");
  });

  it("states what was verified, with no unfilled placeholder", () => {
    expect(readme).not.toContain("[run on");
    expect(readme).not.toContain("| not run yet]");
    expect(readme).toContain("with the Docker command above on Docker Desktop for Mac");
  });
});

// Bar's two pre-handoff findings on issue #274.
describe("the walkthrough's proxy and rerun instructions", () => {
  const STOP_FIRST =
    "Stop the Guardian and the collector first, with Ctrl-C or `docker stop acs-otelcol`. A process that is still running keeps writing into the deleted file, and its spans are lost without an error.";

  it("tells the reader to stop the Guardian and the collector before deleting .acs", () => {
    const paragraph = readme.slice(readme.indexOf("**Run it again.**"));
    expect(paragraph.indexOf(STOP_FIRST)).toBeGreaterThan(-1);
    expect(paragraph.indexOf(STOP_FIRST)).toBeLessThan(paragraph.indexOf("rm -rf .acs"));
  });

  it("names the container, so docker stop has something to stop, in both the README and the config", () => {
    expect(readme).toContain("docker run --rm --name acs-otelcol");
    expect(text).toContain("docker run --rm --name acs-otelcol");
  });

  it("keeps the reader's own exemptions in both proxy variables in step 1", () => {
    expect(readme).toContain('export NO_PROXY="${NO_PROXY:+$NO_PROXY,}${no_proxy:+$no_proxy,}127.0.0.1,localhost"\nexport no_proxy="$NO_PROXY"');
    expect(readme).not.toContain("export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost");
  });
});
