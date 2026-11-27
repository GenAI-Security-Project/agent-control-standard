# Running the suite against the reference AGT Guardian

The suite is the instrument; the reference Guardian (Microsoft AGT behind the ACS wire contract, TypeScript on Bun) is a target. Nothing here needs Bun on your host: stand the Guardian up in a disposable container and point the suite (plain Python) at it.

> Note on scope: the AGT reference Guardian is a governance toolkit, not a cumulative-grant budget enforcer. Pointing Layer B's scenarios at it tests whether it enforces that invariant at all, which is a result either way, and the honest thing to report. Layer A (protocol) applies to it directly.

## Isolated run (Docker)

These are the exact steps used for the recorded runs in `evidence/agt-2026-11-06/` (AGT at `integration` @ db457a8, bun 1.4.4).

```bash
# 1. clone into a throwaway dir (never your project tree)
mkdir -p /tmp/acs-ref && git clone --branch integration \
  https://github.com/GenAI-Security-Project/agent-control-standard /tmp/acs-ref/src

# 2. create the container from a digest-pinned Bun image. The Guardian binds 127.0.0.1 inside
#    the container by default, so ACS_GUARDIAN_HOST=0.0.0.0 is needed for the port mapping to
#    reach it; the host side stays on loopback.
docker create --name acs-agt -p 127.0.0.1:8787:8787 -e ACS_GUARDIAN_HOST=0.0.0.0 \
  -w /app/reference-implementations/agt \
  oven/bun@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d \
  sh -c "bun install --frozen-lockfile && bun run guardian"

# 3. copy the source in rather than bind-mounting it. A bind mount of a /tmp path came up
#    empty under Docker Desktop on macOS; docker cp avoids depending on file-sharing settings.
docker cp /tmp/acs-ref/src/. acs-agt:/app
docker start acs-agt
docker logs -f acs-agt          # wait for "Guardian listening at http://localhost:8787/acs"

# 4. from the host, point the suite at it (from a clean clone if you want the repo's frozen
#    results/ left untouched: run_conformance.py rewrites results/)
python3 run_conformance.py --guardian-url http://127.0.0.1:8787/acs
python3 verify.py

# 5. keep the Guardian's own envelope log as evidence, then tear down
docker exec acs-agt cat .acs/envelopes.jsonl > agt_envelopes.jsonl
docker rm -f acs-agt && rm -rf /tmp/acs-ref
```

`bun install` pulls an npm dependency tree and may run postinstall scripts, which is why this runs in a container and not on your main machine.

## If the Guardian's endpoint or command differs

The repo's `reference-implementations/agt/` README is authoritative for the exact `bun run` target and port. Check `bun run` scripts there; the ACS wire path is `/acs` and the default port in the docs is 8787. If it listens elsewhere, pass that URL to `--guardian-url`.

## What the recorded runs found

See `evidence/agt-2026-11-06/FINDINGS.md`. Layer A: handshake, toolCallRequest and undeclared-method refusal pass; system/ping is -32011 (open question); §10 is not exercised because the ServerHello advertises no signature algorithm. Layer B: N/A, since AGT has no cumulative-grant policy for `budget.consume`. The first run also caught a defect in this suite (schema-invalid `toolCallResult` payloads), fixed in 39606f1.

## What to capture for the record

- Layer A: which protocol checks the reference Guardian passes.
- Layer B: its invariant scorecard. If it returns `allow` on the third concurrent `consume(40)`, the suite records the overshoot from the world ledger: the cumulative-grant gap, measured against the reference implementation itself. If it has no cumulative-grant policy at all, the suite reports `N/A` (nothing executed), never a misleading `HOLD`.
