#!/usr/bin/env bash
# Records the parity corpus from the TypeScript reference Guardian in
# ../agt, at the commit checked out, into agtbridge/testdata/ts-cases.json.
# Needs bun (the version ../agt's workflow pins) on PATH; run it from this
# module's directory.
set -euo pipefail

module="$(cd "$(dirname "$0")/.." && pwd)"
tree="$module/../agt"
port="${ACS_RECORD_PORT:-8797}"
logs="$(mktemp -d)"

(cd "$tree" && bun install --frozen-lockfile >/dev/null)
# exec, so the PID the trap kills is the Guardian's own, not a wrapper's.
(cd "$tree" && ACS_GUARDIAN_PORT="$port" ACS_ENVELOPE_LOG="$logs/envelopes.jsonl" \
  ACS_SESSION_CONTEXT_LOG="$logs/session-context.jsonl" exec bun packages/guardian/src/main.ts >"$logs/guardian.log" 2>&1) &
guardian=$!
trap 'kill "$guardian" 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  grep -q "Guardian listening" "$logs/guardian.log" 2>/dev/null && break
  sleep 0.2
done

cd "$module"
go run ./internal/tscases/record \
  -url "http://127.0.0.1:$port/acs" \
  -out agtbridge/testdata/ts-cases.json \
  -ts-commit "$(git -C "$tree" log -1 --format=%H -- packages/guardian/src packages/agt-bridge/src mapping.yaml policy)" \
  -spec-version "$(cat "$module/../../version.txt")"
