import { describe, expect, it } from "bun:test";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const lock = JSON.parse(readFileSync("agt.lock", "utf8"));

describe("AGT pin", () => {
  it("records a full 40-character commit ref", () => {
    expect(lock.agt_ref).toMatch(/^[0-9a-f]{40}$/);
  });

  it("records a valid semver OPA version", () => {
    expect(lock.opa_version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(lock.opa_version).toBe("0.70.0");
  });

  it("pins the SDK version the bridge installs", () => {
    for (const manifestPath of [
      "package.json",
      "packages/agt-bridge/package.json",
      "packages/conformance/package.json",
    ]) {
      const pkg = JSON.parse(readFileSync(manifestPath, "utf8"));
      const dep =
        pkg.dependencies?.[lock.sdk_package] ??
        pkg.devDependencies?.[lock.sdk_package];
      expect(dep).toBeDefined();
      expect(dep.replace(/^[^0-9]*/, "")).toBe(lock.sdk_version);
    }
  });

  it("keeps every implementation lock file aligned with agt.lock", () => {
    const nativeLock = JSON.parse(readFileSync("../agt-go/agt-native.lock", "utf8"));
    expect(nativeLock.agt_repo).toBe(lock.agt_repo);
    expect(nativeLock.agt_ref).toBe(lock.agt_ref);
    expect(nativeLock.opa_version).toBe(lock.opa_version);
    expect(nativeLock.crate_version).toBe(lock.sdk_version);
  });

  it("vendors the stock bundle with every stock module present", () => {
    const files = readdirSync("policy/lib").filter((f) => f.endsWith(".rego"));
    for (const mod of [
      "agt_default.rego", "agt_ifc.rego", "approval.rego", "budgets.rego",
      "confidence.rego", "content_hash.rego", "drift.rego", "egress.rego",
      "ifc.rego", "patterns.rego", "redact.rego",
    ]) {
      expect(files).toContain(mod);
    }
  });

  it("adds nothing to the bundle except data.json", () => {
    const extra = readdirSync("policy/lib").filter(
      (f) => !f.endsWith(".rego") && f !== "run_tests.sh" && f !== "data.json",
    );
    expect(extra).toEqual([]);
  });

  // UPSTREAM_BUNDLE is set by `bun run verify:pin`, which clones the pinned
  // ref and needs network access to GitHub -- unavailable in the fast unit
  // run. A bare early `return` here used to make this
  // report green while asserting nothing, silently un-guarding the
  // project's central "AGT runs unforked" claim. `it.skipIf` instead makes
  // bun report this test as SKIPPED, not passed -- unmistakable in output --
  // without failing when the env var is legitimately absent (offline dev),
  // and without deleting the assertion `bun run verify:pin` still enforces.
  it.skipIf(!process.env.UPSTREAM_BUNDLE)(
    "authors no Rego of our own — every .rego is byte-identical to upstream",
    () => {
      const upstream = process.env.UPSTREAM_BUNDLE;
      if (!upstream) {
        throw new Error("UPSTREAM_BUNDLE must be set to run this assertion — see `bun run verify:pin`");
      }
      for (const f of readdirSync("policy/lib").filter((f) => f.endsWith(".rego"))) {
        expect(readFileSync(join("policy/lib", f), "utf8")).toBe(
          readFileSync(join(upstream, f), "utf8"),
        );
      }
    },
  );
});
