# AGT bridge

The one place this tree touches Microsoft's Agent Governance Toolkit. It constructs the AGT SDK runtime from a manifest, makes the bundled OPA binary reachable from the current process, and exposes AGT as two small roles the rest of the tree depends on. Nothing here knows what a host is. That boundary is enforced by [`test/invariants.test.ts`](../../test/invariants.test.ts) at the root of the tree.

## Get started

```ts
import { createBridge } from "agt-bridge";

const bridge = createBridge("policy/manifest.yaml");
const verdict = await bridge.evaluate("pre_tool_call", snapshot);
// verdict.decision is "allow", "deny", "warn", "escalate" or "transform"
```

Construct once at startup. Call `evaluate` once per decision. The bridge keeps nothing between calls.

The snapshot is AGT's policy input document for that intervention point. The [Guardian](../guardian/README.md) assembles it, and this package only constrains it to be a JSON object. The manifest path is resolved by AGT relative to the manifest's own directory, which is why `policy/manifest.yaml` names its bundle as `lib`.

`createBridge` answers with two roles:

| Role | Method | Who depends on it |
|---|---|---|
| `PolicyBridge` | `evaluate(point, snapshot)` returns the verdict | The Guardian |
| `EvidenceBridge` | `evaluateWithEvidence(point, snapshot)` returns the verdict plus AGT's own policy input and its identity strings | The conformance harness |

The narrow answer is derived from the wide one, so there is exactly one path into the SDK.

An `annotator` option supplies the function AGT calls for every `annotators.<name>` entry a manifest declares. Its return value lands at `input.annotations.<name>` in the policy input. The deployment's annotator, which extracts an egress destination from a shell command, lives in the Guardian's `src/deployment-bridge.ts`, not here. A manifest that declares an annotator and is evaluated by a bridge with no annotator denies every call, so the Guardian always supplies one.

## OPA

AGT's native core spawns `opa`. The SDK ships it as a per-platform optional dependency and tries to put it on `PATH` by assigning `process.env`, which under Bun changes nothing a spawned process can see. This package resolves the binary the SDK's own way, publishes it into the real process environment as `ACS_OPA_PATH` through libc, and reads it back. If the readback disagrees, construction throws. A process that cannot reach OPA never gets a bridge, so a Guardian refuses to start rather than starting and denying everything.

| Variable | What it does |
|---|---|
| `ACS_OPA_PATH` | An explicit OPA executable. It is authoritative: a value that names nothing stops construction. Unset, the bundled binary is used, then `opa` on `PATH` |

## The manifest path

`createBridge` refuses a manifest path that contains `/./`. AGT joins the path verbatim, and OPA's bundle loader then drops the bundle's data document, which disables every rule while still answering `allow`. The refusal is a backstop for that fail-open. A `./`-prefixed path is the usual way to hit it.

## The pin

`agt.lock` at the root of the tree records the AGT commit, the bundle path inside that commit, and the SDK version this bridge is built against. `policy/lib/` is that commit's stock bundle, byte for byte, plus one `data.json` this project wrote. `bun run verify:pin` re-clones the commit and diffs the two.

## Files

| File | What it holds |
|---|---|
| `src/index.ts` | `createBridge`, the two roles, and the verdict, evidence and annotator types |
| `src/opa-path.ts` | The OPA resolution, the libc publish, and the readback |

## Tests

```bash
bun test packages/agt-bridge
```

Two files. One drives the real SDK against the pinned bundle and confirms the shape of what it returns. The other builds a bridge in a process with no `opa` on its `PATH` and still evaluates policy, and confirms that an explicit `ACS_OPA_PATH` naming nothing stops construction.
