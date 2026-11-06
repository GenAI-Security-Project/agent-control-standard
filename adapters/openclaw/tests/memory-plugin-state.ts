export function memoryPluginState() {
  const namespaces = new Map<string, Map<string, unknown>>();
  return {
    openKeyedStore({ namespace }: { namespace: string }) {
      let rows = namespaces.get(namespace);
      if (rows === undefined) {
        rows = new Map();
        namespaces.set(namespace, rows);
      }
      return {
        async register(key: string, value: unknown) {
          rows!.set(key, structuredClone(value));
        },
        async registerIfAbsent(key: string, value: unknown) {
          if (rows!.has(key)) return false;
          rows!.set(key, structuredClone(value));
          return true;
        },
        async lookup(key: string) {
          const value = rows!.get(key);
          return value === undefined ? undefined : structuredClone(value);
        },
        async consume(key: string) {
          const value = rows!.get(key);
          rows!.delete(key);
          return value === undefined ? undefined : structuredClone(value);
        },
        async delete(key: string) {
          rows!.delete(key);
        },
        async entries() {
          return [...rows!].map(([key, value]) => ({ key, value: structuredClone(value) }));
        },
      };
    },
  };
}
