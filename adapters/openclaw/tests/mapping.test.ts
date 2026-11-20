import { expect, it } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";

const mapping = readFileSync(new URL("../mapping.md", import.meta.url), "utf8");
const named = new Set(
  mapping
    .split("\n")
    .filter((line) => line.startsWith("| `") || line.startsWith("| tool-result"))
    .flatMap((line) => [...line.split("|")[1]!.matchAll(/`([^`]+)`/g)].map((match) => match[1]!)),
);

it("names every hook of the installed OpenClaw, as used or not used", () => {
  const dist = new URL("../node_modules/openclaw/dist/", import.meta.url);
  const contracts = readdirSync(dist).filter((file) => file.startsWith("config-contracts-") && file.endsWith(".d.ts"));
  const declared = contracts.map((file) => /PLUGIN_HOOK_NAMES: readonly \[([^\]]+)\]/.exec(readFileSync(new URL(file, dist), "utf8"))?.[1]).find(Boolean);
  const hooks = [...declared!.matchAll(/"([a-z_]+)"/g)].map((match) => match[1]!);
  expect(hooks.length).toBeGreaterThan(30);
  expect(hooks.filter((hook) => !named.has(hook))).toEqual([]);
});

it("names every ACS step of specification/v0.1.0/, as sent or not sent", () => {
  const hooks = new URL("../../../specification/v0.1.0/hooks/", import.meta.url);
  // Step schemas use kebab-case. AgBOM methods and `system/ping` are not steps.
  const steps = readdirSync(hooks)
    .filter((file) => /^[a-z-]+\.json$/.test(file) && !file.startsWith("agbom-") && file !== "system-ping.json")
    .map((file) => `steps/${file.replace(".json", "").replace(/-([a-z])/g, (_, letter: string) => letter.toUpperCase())}`);
  expect(steps).toHaveLength(19);
  const mentioned = new Set([...mapping.matchAll(/`(steps\/[A-Za-z]+)`/g)].map((match) => match[1]!));
  expect(steps.filter((step) => !mentioned.has(step))).toEqual([]);
});

it("opens with one row per ACS step, each naming its hook and its gap", () => {
  const section = mapping.split("## Every ACS step")[1]!.split("\n## ")[0]!;
  const rows = section.split("\n").filter((line) => line.startsWith("| `steps/"));
  const steps = rows.map((line) => /^\| `(steps\/[A-Za-z]+)`/.exec(line)![1]);
  expect(new Set(steps).size).toBe(19);
  expect(steps).toHaveLength(19);
  expect(rows.every((line) => line.split("|").length === 6 && line.split("|").slice(1, 5).every((cell) => cell.trim() !== ""))).toBe(true);
});
