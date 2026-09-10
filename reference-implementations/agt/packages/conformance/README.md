# Conformance harness

Measures what ACS v0.1.0 can express of AGT, cell by cell, at the AGT commit `agt.lock` pins. It prints three tables and says which checks measured them. It is an instrument, not a conformance claim. A gap in the specification exits 0. A false declaration in this tree exits non-zero.

## Get started

```bash
bun run conformance
```

This runs `scripts/run-conformance.sh`. The script clones AGT at the pinned commit into a temporary directory, hands the path to the runner as `PINNED_AGT_CLONE`, and removes the clone with `trash` when the run ends. It needs network access to GitHub, `jq`, and `trash` on your `PATH`, and it refuses to start without them.

The runner starts its own Guardian on an OS-assigned port for the one check that needs a live HTTP round trip, and closes it before exiting. Nothing in the run is a host hook, and nothing asks a model anything.

## The three tables

**The mapping table** is read from `mapping.yaml`: each AGT intervention point and its ACS method, and each AGT verdict and its ACS decision. The Guardian reads the same file at decision time, so the table is what the runtime does, not a claim beside it.

**The coverage matrix** is eight AGT intervention points by five AGT verdicts. The axes come from the AGT SDK's own constants, not from a list kept here. Every cell has a status:

| Status | Meaning |
|---|---|
| `expressed` | ACS v0.1.0 carries this point and verdict, and a check drove it through the pinned bundle |
| `guardian_only` | Only process-local Guardian knowledge can express it. It does not cross the wire |
| `unexpressed` | ACS v0.1.0 has no target here. The cell carries the reason. This is a fact about the specification, and it exits 0 |
| `contract_violated` | A declaration in this tree was checked and does not hold. This exits non-zero |

**The trace-pillar rows** list, for each of the six methods in scope, which OpenTelemetry attributes a consumer could emit from the envelopes alone. This tree does not claim the Trace profile, and the rows measure that non-claim.

## The checks

| Check | What it measures |
|---|---|
| `checkInterventionPoints` | Each AGT point's declared ACS method resolves back to that point through the Guardian's own resolver |
| `checkVerdicts` | Each AGT verdict goes through the Guardian's own `mapVerdict` to an ACS decision and back, at every intervention point, through an inverse derived from `mapping.yaml`. The verdict that comes back must be the one that went in |
| `measureIdentity` | AGT's enforced identity is recomputed from the policy input and the transform, at both gates that can transform, and compared with AGT's own |
| `checkDenyFailsClosed` | A schema-invalid envelope reaches a live Guardian over HTTP and comes back as an honoured `deny` |
| `checkTracePillar` | The trace-pillar rows above |
| `checkPolicyInputSchema` | The policy input the Guardian sends validates against AGT's own `policy-input.schema.json` at the pinned commit. It self-skips without `PINNED_AGT_CLONE`, and the output says whether it ran |

The first four are merged into the matrix by coordinate. Two cells at one coordinate is a throw, not a first-match win. A cell no check claims to have measured fails the run, because an unattributed claim is not a measurement.

## Watch upstream

```bash
bun run watch:upstream
```

This runs `scripts/run-upstream-watch.sh`, which clones AGT twice, once at the pinned commit and once at `main`, and hands the two paths to the runner as `PINNED_AGT_CLONE` and `UPSTREAM_AGT_CLONE`. The runner diffs AGT's eight declared contract surfaces field by field, validates the Guardian's policy input against both schema versions, and reports which tools the two hookmaps declare against the manifest's registry.

The watch reports. It never fails a build. Nothing reaches this tree until a human moves the pin in `agt.lock`.

## Use it in-process

`bun test` runs the same checks in-process. The legs that need a clone self-skip, and Bun reports them as skipped rather than passed. The public surface in `src/index.ts` exports each check, the cell and matrix types, the renderers and the exit rule, so a test can call one check on its own.

## Files

| File | What it holds |
|---|---|
| `src/main.ts` | The runner: drives every check, merges, renders, and resolves the exit code |
| `src/cells.ts`, `src/merge-cells.ts`, `src/render.ts` | The matrix, the merge by coordinate, and the three renderers |
| `src/intervention-points.ts`, `src/verdicts.ts`, `src/identity.ts`, `src/failure-domains.ts`, `src/trace-pillar.ts` | One check each |
| `src/policy-input-schema.ts` | The schema leg, against AGT's own schema at a given clone |
| `src/exit-code.ts` | The exit rule |
| `src/upstream-watch.ts`, `src/surfaces.ts`, `src/diff-surfaces.ts`, `src/fetch-upstream.ts`, `src/render-upstream-diff.ts`, `src/tools-registry.ts` | The upstream watch |

## Tests

```bash
bun test packages/conformance
```

Eighteen files. Five of them clean up fixture directories with `trash` and fail without it.
