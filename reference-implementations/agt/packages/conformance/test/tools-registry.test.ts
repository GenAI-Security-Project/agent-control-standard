// packages/conformance/test/tools-registry.test.ts
import { describe, expect, it } from "bun:test";
import { checkToolsAgainstRegistry, renderToolsRegistryReport } from "../src/tools-registry.ts";

const hookmap = (path: string, tools: unknown) => ({ path, hooks: { "tool.execute.before": { tools } } });

describe("checkToolsAgainstRegistry -- a tools entry the manifest registers nothing for", () => {
  it("reports a tool name no registry entry matches", () => {
    const found = checkToolsAgainstRegistry([hookmap("opencode.hookmap.yaml", ["bashh"])], ["bash", "Bash"]);

    expect(found).toEqual([{ hookmap: "opencode.hookmap.yaml", hook: "tool.execute.before", tool: "bashh" }]);
  });

  it("says nothing about a hook that declares no tools at all", () => {
    expect(checkToolsAgainstRegistry([hookmap("claude-code.hookmap.yaml", undefined)], ["Bash"])).toEqual([]);
  });

  it("compares case-sensitively, exactly as governsTool does", () => {
    expect(checkToolsAgainstRegistry([hookmap("h.yaml", ["BASH"])], ["bash"])).toHaveLength(1);
  });

  it("does NOT report a name the manifest registers for a different host -- the case this check cannot close", () => {
    // policy/manifest.yaml registers run_shell, Bash and bash: one per host,
    // deliberately. So OpenCode's `tools: [bash]` recased to `[Bash]` is a
    // gate that governs nothing, and this check passes it clean.
    expect(checkToolsAgainstRegistry([hookmap("opencode.hookmap.yaml", ["Bash"])], ["run_shell", "Bash", "bash"])).toEqual([]);
  });

  it("renders nothing found as a clean line, and findings as rows", () => {
    expect(renderToolsRegistryReport([])).toContain("every declared tool is registered");
    expect(renderToolsRegistryReport([{ hookmap: "h.yaml", hook: "g", tool: "bashh" }])).toContain("bashh");
  });
});
