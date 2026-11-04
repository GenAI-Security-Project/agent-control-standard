/**
 * Keeps a loopback trace endpoint off an HTTP proxy. Both functions take the
 * environment as a parameter: main.ts, the composition root, passes
 * process.env, and the exporter itself never reads or writes it.
 */

/** The NO_PROXY entries that exempt a loopback endpoint's host, or none
 * when the endpoint is not loopback. IPv6 gets both forms: Bun matches only
 * `[::1]`, and other clients expect the bare `::1`. */
function loopbackProxyEntries(endpoint: string): string[] {
  const host = new URL(endpoint).hostname.replace(/^\[|\]$/g, "");
  if (host === "127.0.0.1" || host === "localhost") {
    return [host];
  }
  return host === "::1" ? ["::1", "[::1]"] : [];
}

const splitProxyList = (value: string): string[] =>
  value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");

/**
 * Adds a loopback endpoint's host to NO_PROXY and no_proxy, so an
 * HTTP_PROXY in the Guardian's environment cannot route spans meant for this
 * machine through a proxy: request content (reasoning text, provenance ids)
 * would reach the proxy, and the collector would never see it. Bun's HTTP
 * client honors these variables per request, and an explicit agent does not
 * opt out, so the environment is the only lever. A non-loopback endpoint is
 * left to the operator's proxy settings.
 *
 * Only the variables the user set are touched. Bun 1.3.14 reads a non-empty
 * no_proxy in preference to NO_PROXY, so creating the one the user did not
 * set would switch off every exemption in the one they did. "Set" follows
 * Bun's own rule: any value but the empty string counts, and an empty one
 * makes Bun fall back to the other. A set variable that holds no entries
 * (a stray comma, say) is what Bun reads, so it is filled with the host.
 * When neither is set, both get the host, and nothing is lost.
 *
 * Bun 1.3.11 reads these variables only when the process starts, so on that
 * version this edit has no effect, and loopbackProxyWarning below is what
 * tells the operator.
 *
 * The edit is made to the `env` it is given and never undone. main.ts
 * passes process.env, so there the change is process-wide and permanent:
 * anything else in that process (a host adapter embedded with the Guardian)
 * and any child process it spawns inherits it. That is acceptable because
 * only loopback hosts are ever added, and traffic to this machine should not
 * use a proxy for any of them. The exporter never calls this itself, so an
 * embedder that builds the exporter decides whether its environment changes.
 */
export function keepLoopbackOffProxy(endpoint: string, env: Record<string, string | undefined>): void {
  const additions = loopbackProxyEntries(endpoint);
  if (additions.length === 0) {
    return;
  }
  const keys = ["NO_PROXY", "no_proxy"] as const;
  const setKeys = keys.filter((key) => (env[key] ?? "") !== "");
  for (const key of setKeys.length === 0 ? keys : setKeys) {
    const entries = splitProxyList(env[key] ?? "");
    const missing = additions.filter((entry) => !entries.includes(entry));
    if (missing.length > 0) {
      env[key] = [...entries, ...missing].join(",");
    }
  }
}

/**
 * A warning when a loopback endpoint would reach an HTTP proxy, judged by
 * the variables as they stand: a proxy is set, and the list Bun reads (a
 * non-empty no_proxy, otherwise NO_PROXY) does not exempt the host. main.ts
 * calls it before keepLoopbackOffProxy, so on Bun 1.3.11, which ignores the
 * runtime edit, the operator still learns that spans may go through the
 * proxy and what to set before starting the Guardian.
 */
export function loopbackProxyWarning(endpoint: string, env: Record<string, string | undefined>): string | undefined {
  const additions = loopbackProxyEntries(endpoint);
  const proxy = env.http_proxy || env.HTTP_PROXY;
  if (additions.length === 0 || !proxy) {
    return undefined;
  }
  const list = splitProxyList(env.no_proxy ? env.no_proxy : (env.NO_PROXY ?? ""));
  // The bracketed form is the one Bun matches for IPv6.
  const needed = additions[additions.length - 1]!;
  if (list.includes("*") || list.includes(needed)) {
    return undefined;
  }
  return (
    `otel trace export to ${endpoint}: an HTTP proxy is set and NO_PROXY/no_proxy did not exempt ${needed}, ` +
    `so on some Bun versions these spans go through the proxy. Start the Guardian with ${needed} in both NO_PROXY and no_proxy.`
  );
}
