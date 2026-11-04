import { expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join, normalize } from "node:path";
import { RESPONSE_SCHEMAS } from "../response-schema.ts";

it("imports response-envelope.json and exactly the schemas its $refs reach", () => {
  const root = new URL("../../../specification/v0.1.0/", import.meta.url).pathname;
  const reached = new Set<string>();
  const visit = (file: string) => {
    if (reached.has(file)) {
      return;
    }
    reached.add(file);
    for (const [, ref] of readFileSync(join(root, file), "utf8").matchAll(/"\$ref":\s*"([^"#]+)/g)) {
      visit(normalize(join(dirname(file), ref!)));
    }
  };
  visit("response-envelope.json");
  const ids = [...reached].map((file) => (JSON.parse(readFileSync(join(root, file), "utf8")) as { $id: string }).$id);
  expect(RESPONSE_SCHEMAS.map((schema) => schema.$id).sort()).toEqual(ids.sort());
});
