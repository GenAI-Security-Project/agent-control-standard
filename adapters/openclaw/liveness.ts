/**
 * Probes `system/ping` on a timer so OpenClaw logs Guardian outages when no
 * step is sent (§13). Probes carry no decision; steps keep their own failure
 * posture (§6.4).
 */
import type { AcsExchange } from "./acs-exchange.ts";

export type LivenessProbe = { start(): void; stop(): void };

export function createLivenessProbe(
  exchange: Pick<AcsExchange, "ping">,
  intervalMs: number,
  logger: { warn(message: string): void; info(message: string): void },
): LivenessProbe {
  let timer: ReturnType<typeof setInterval> | undefined;
  let down = false;
  let probing = false;

  async function probe(): Promise<void> {
    if (probing) {
      return;
    }
    probing = true;
    try {
      await exchange.ping();
      if (down) {
        down = false;
        logger.info("ACS plugin: the Guardian answers system/ping again");
      }
    } catch (error) {
      // Report each outage once, not once per probe.
      if (!down) {
        down = true;
        logger.warn(`ACS plugin: the Guardian did not answer system/ping: ${(error as Error).message}`);
      }
    } finally {
      probing = false;
    }
  }

  return {
    start() {
      if (timer !== undefined) {
        return;
      }
      void probe();
      timer = setInterval(() => void probe(), intervalMs);
      timer.unref?.();
    },
    stop() {
      clearInterval(timer);
      timer = undefined;
    },
  };
}
