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
