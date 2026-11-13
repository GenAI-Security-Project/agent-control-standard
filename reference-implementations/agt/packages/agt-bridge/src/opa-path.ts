/**
 * Makes the `opa` binary AGT's native core spawns reachable from THIS
 * process before any policy is evaluated -- and refuses to build a bridge
 * when it cannot.
 *
 * Why this file exists, measured rather than assumed. The SDK ships OPA as a
 * per-platform optional dependency (`agent-control-specification-opa-*`),
 * and `AgentControl.fromPath` wires it in by resolving that package and
 * prepending its directory to `process.env.PATH`. The Rust core then spawns
 * `opa` by name, reading PATH from the real process environment. Under Node
 * those are one environment: a `process.env` assignment calls `setenv`.
 * Under Bun they are not. `process.env` is a JavaScript-side copy, and
 * writing to it changes nothing libc's `getenv` can see -- measured on Bun
 * 1.3.11 by reading the variable back through `bun:ffi` immediately after
 * the write and getting the old value. So in every Bun process the SDK's own
 * wiring is a silent no-op, the core spawns whatever `opa` the shell that
 * launched Bun already had -- none, on a fresh GitHub runner -- and EVERY
 * evaluation answers deny on `runtime_error:policy_invocation_failed`.
 * Fail-closed, which is the right direction, and also sixty-eight red tests
 * for a reason with nothing to do with the commit under test.
 *
 * What this does about it. Resolve OPA through the SDK's own resolver, in
 * the SDK's own documented order (an explicit `$ACS_OPA_PATH`, then the
 * bundled optional dependency, then `opa` on PATH), then publish the
 * resolved executable into the REAL environment as `ACS_OPA_PATH` through
 * libc's `setenv`. `ACS_OPA_PATH` rather than PATH, for two reasons: the
 * core treats it as authoritative -- "explicit OPA paths do not fall back to
 * PATH" is its own error text -- so a wrong value fails loudly instead of
 * quietly picking up some other `opa`; and rewriting PATH would reorder
 * lookups for every other subprocess the Guardian ever spawns.
 *
 * Then read it back. A `setenv` that returned 0 but did not land -- a libc
 * this file did not know how to open, or a Bun that one day grows a real
 * `process.env` bridge with different semantics -- would put this process
 * straight back into the silent case above. The readback is the check, and
 * a mismatch throws. `createBridge` calls this before constructing the SDK's
 * runtime, so a process that cannot reach OPA never gets a bridge at all:
 * the Guardian refuses to start, rather than starting and denying everything.
 *
 * The one path that skips FFI entirely: a libc this file cannot open, on a
 * process whose real environment already names the resolved binary. Bun
 * seeds `process.env` from the real environment at startup, so
 * `ACS_OPA_PATH=<binary> bun test` is the escape hatch for such a platform,
 * and is honoured without touching the environment.
 */
import { dlopen, FFIType } from "bun:ffi";
import { ensureOpaResolvable, OPA_PATH_ENV } from "agent-control-specification/integrations/opa-binary";

/**
 * Where the C library lives, by platform. Tried in order; the first that
 * opens wins. glibc first because that is what the GitHub runner and every
 * mainstream Linux carry, then macOS's, then the two musl spellings.
 */
const LIBC_CANDIDATES = [
  "libc.so.6",
  "libSystem.B.dylib",
  "libc.musl-x86_64.so.1",
  "libc.musl-aarch64.so.1",
  "libc.so",
];

type Libc = {
  setenv(name: string, value: string): number;
  getenv(name: string): string;
};

/**
 * Resolves the `opa` AGT will run and publishes it to the real environment.
 * Answers with the resolved executable's path. Throws, with the SDK's own
 * actionable message, when no OPA can be found at all -- and with this
 * file's when one was found but could not be made visible to the core.
 */
export function publishOpaPath(): string {
  // The SDK's resolver, so the order is the one its README documents rather
  // than a second one kept here. It throws when nothing resolves, which is
  // the loud failure this file wants: an explicit hint that names nothing
  // stops here, before any setenv, and never falls back to another opa.
  const resolved = ensureOpaResolvable();

  const libc = openLibc();
  if (libc === undefined) {
    if (process.env[OPA_PATH_ENV] === resolved) return resolved;
    throw new Error(
      `agt-bridge: found opa at ${resolved} but could not open the C library (tried ${LIBC_CANDIDATES.join(", ")}) ` +
        `to publish it to the process environment -- under Bun, process.env writes never reach the native core that ` +
        `spawns opa. Launch this process with ${OPA_PATH_ENV}=${resolved} set in its real environment.`,
    );
  }

  if (libc.getenv(OPA_PATH_ENV) !== resolved) {
    const rc = libc.setenv(OPA_PATH_ENV, resolved);
    const readback = libc.getenv(OPA_PATH_ENV);
    if (rc !== 0 || readback !== resolved) {
      throw new Error(
        `agt-bridge: setenv(${OPA_PATH_ENV}) answered ${rc} and the environment reads back ` +
          `${JSON.stringify(readback)}, not ${JSON.stringify(resolved)} -- the native core would spawn opa without ` +
          `it and deny every step on runtime_error:policy_invocation_failed. Launch this process with ` +
          `${OPA_PATH_ENV}=${resolved} set in its real environment.`,
      );
    }
  }

  // The JavaScript-side copy too, so the SDK's own `configureOpaPath` -- which
  // reads the hint from process.env when the runtime is constructed -- sees
  // the same binary the core will, rather than resolving a second time.
  process.env[OPA_PATH_ENV] = resolved;
  return resolved;
}

function openLibc(): Libc | undefined {
  for (const candidate of LIBC_CANDIDATES) {
    let lib: ReturnType<typeof dlopen>;
    try {
      lib = dlopen(candidate, {
        setenv: { args: [FFIType.cstring, FFIType.cstring, FFIType.i32], returns: FFIType.i32 },
        getenv: { args: [FFIType.cstring], returns: FFIType.cstring },
      });
    } catch {
      continue;
    }
    const { setenv, getenv } = lib.symbols as unknown as {
      setenv(name: Buffer, value: Buffer, overwrite: number): number;
      getenv(name: Buffer): { toString(): string } | null;
    };
    return {
      setenv: (name, value) => setenv(cstring(name), cstring(value), 1),
      // A NULL from getenv -- the variable is unset -- arrives as a pointer
      // that stringifies empty, which never equals a path, so "unset" and
      // "set to something else" both land on the same branch above.
      getenv: (name) => getenv(cstring(name))?.toString() ?? "",
    };
  }
  return undefined;
}

function cstring(value: string): Buffer {
  return Buffer.from(`${value}\0`, "utf8");
}
