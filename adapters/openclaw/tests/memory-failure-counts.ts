/** Test store. Reusing it across registrations shares state, as OpenClaw does. */
import type { DecisionFailures, FailureCountStore } from "../acs-exchange.ts";

export function memoryFailureCounts(): FailureCountStore {
  const rows = new Map<string, DecisionFailures>();
  return {
    async start(sessionUuid) {
      if (!rows.has(sessionUuid)) {
        rows.set(sessionUuid, {});
      }
    },
    async add(sessionUuid, failureClass) {
      const counts = rows.get(sessionUuid);
      if (counts !== undefined) {
        rows.set(sessionUuid, { ...counts, [failureClass]: (counts[failureClass] ?? 0) + 1 });
      }
    },
    async get(sessionUuid) {
      const counts = rows.get(sessionUuid);
      return counts === undefined ? undefined : { ...counts };
    },
    async delete(sessionUuid) {
      rows.delete(sessionUuid);
    },
  };
}
