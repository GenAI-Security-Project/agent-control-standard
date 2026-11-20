/** Test store. Reusing it across registrations shares state, as OpenClaw does. */
import type { SessionRefusal } from "../acs-exchange.ts";
import type { RefusalStore } from "../hook-state.ts";

export function memoryRefusals(): RefusalStore {
  const rows = new Map<string, SessionRefusal>();
  return {
    async get(sessionId) {
      return rows.get(sessionId);
    },
    async put(sessionId, refusal) {
      rows.set(sessionId, refusal);
    },
    async delete(sessionId) {
      rows.delete(sessionId);
    },
  };
}
