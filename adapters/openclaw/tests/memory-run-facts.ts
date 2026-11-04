import type { RunFactsStore } from "../hook-state.ts";

/** In-memory test store for OpenClaw's retained run facts. */
export function memoryRunFacts(): RunFactsStore {
  const values = new Map<string, Record<string, unknown>>();
  const key = (runId: string, namespace: string) => `${runId}\n${namespace}`;
  return {
    async set(runId, namespace, value) {
      values.set(key(runId, namespace), structuredClone(value));
    },
    async setIfAbsent(runId, namespace, value) {
      const entry = key(runId, namespace);
      if (values.has(entry)) return false;
      values.set(entry, structuredClone(value));
      return true;
    },
    async get(runId, namespace) {
      const value = values.get(key(runId, namespace));
      return value === undefined ? undefined : structuredClone(value);
    },
    async consume(runId, namespace) {
      const entry = key(runId, namespace);
      const value = values.get(entry);
      values.delete(entry);
      return value === undefined ? undefined : structuredClone(value);
    },
    async clear(runId, namespace) {
      if (namespace !== undefined) {
        values.delete(key(runId, namespace));
      } else {
        for (const entry of values.keys()) {
          if (entry.startsWith(`${runId}\n`)) values.delete(entry);
        }
      }
    },
    async pruneOtherProcesses() {},
  };
}
