/** A hookmap gate naming a tool the policy manifest registers nothing for. */
export type UnregisteredTool = {
  readonly hookmap: string;
  readonly hook: string;
  readonly tool: string;
};

type HookmapLike = { readonly path: string; readonly hooks: Record<string, { tools?: unknown }> };

/**
 * Reports every `tools` entry in a hookmap that the policy manifest
 * registers no tool for. A gate scoped to a name nothing dispatches governs
 * nothing, and today nothing anywhere says so.
 *
 * Case-sensitive, because that is how the scoping comparison itself works:
 * a check that matched case-insensitively would report clean for exactly the
 * mismatch that makes a gate silent.
 *
 * WHAT THIS DOES NOT CATCH, measured rather than assumed. The manifest
 * registers every host's spelling -- `run_shell`, `Bash` and `bash` -- because
 * one manifest serves both hosts. So a gate recased from its own host's name
 * to the other host's name is still a registered name, and this check passes
 * it. Catching that needs a per-host declaration of the names that host
 * actually dispatches, which no document in this repository carries.
 */
export function checkToolsAgainstRegistry(
  hookmaps: readonly HookmapLike[],
  registry: readonly string[],
): UnregisteredTool[] {
  const registered = new Set(registry);
  const found: UnregisteredTool[] = [];
  for (const hookmap of hookmaps) {
    for (const [hook, entry] of Object.entries(hookmap.hooks ?? {})) {
      const tools = entry?.tools;
      if (!Array.isArray(tools)) {
        continue;
      }
      for (const tool of tools) {
        if (typeof tool === "string" && !registered.has(tool)) {
          found.push({ hookmap: hookmap.path, hook, tool });
        }
      }
    }
  }
  return found;
}

export function renderToolsRegistryReport(findings: readonly UnregisteredTool[]): string {
  if (findings.length === 0) {
    return "Hookmap tools against the policy manifest: every declared tool is registered.";
  }
  const lines = [
    `Hookmap tools against the policy manifest: ${findings.length} declared tool(s) the manifest registers nothing for.`,
    "",
    "| hookmap | hook | tool |",
    "|---|---|---|",
  ];
  for (const f of findings) {
    lines.push(`| ${f.hookmap} | ${f.hook} | \`${f.tool}\` |`);
  }
  return lines.join("\n");
}
