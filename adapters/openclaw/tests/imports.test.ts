import { expect, it } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";

const dependencies = Object.keys(JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).dependencies ?? {});

it("reaches the TypeScript reference only through host-adapter.ts, and only its host adapter", () => {
  const dir = new URL("..", import.meta.url);
  const sources = readdirSync(dir).filter((file) => file.endsWith(".ts"));
  expect(sources).toContain("openclaw-hooks.ts");
  for (const file of sources) {
    const specifiers = [...readFileSync(new URL(file, dir), "utf8").matchAll(/from "([^"]+)"/g)].map((match) => match[1]!);
    // Imports must come from the host SDK, declared dependencies, or the specification.
    const outside = specifiers.filter((specifier) =>
      !specifier.startsWith("./") && !specifier.startsWith("node:") && !specifier.startsWith("openclaw/plugin-sdk/") &&
      !specifier.startsWith("../../specification/") &&
      !dependencies.some((name) => specifier === name || specifier.startsWith(`${name}/`)));
    const expected = file === "host-adapter.ts" ? ["../../reference-implementations/agt/packages/host-adapter/src/index.ts"] : [];
    expect({ file, outside }).toEqual({ file, outside: expected });
  }
});
