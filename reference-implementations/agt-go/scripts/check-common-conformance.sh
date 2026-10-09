#!/usr/bin/env bash
set -euo pipefail

module="$(cd "$(dirname "$0")/.." && pwd)"
typescript="$module/../agt"
port="${ACS_CONFORMANCE_PORT:-0}"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/acs-go-conformance.XXXXXX")"
secret="$scratch/hmac-secret"
guardian_pid=""

cleanup() {
  if [ -n "$guardian_pid" ]; then
    kill "$guardian_pid" 2>/dev/null || true
    wait "$guardian_pid" 2>/dev/null || true
  fi
  rm -f "$scratch/envelopes.jsonl" "$scratch/events.jsonl" "$scratch/guardian.log" "$secret"
  rmdir "$scratch"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

openssl rand 32 >"$secret"
chmod 600 "$secret"

cd "$module"
ACS__SERVER__PORT="$port" \
ACS__SECURITY__HMAC_KEY_ID=conformance \
ACS__SECURITY__HMAC_SECRET_FILE="$secret" \
ACS__AUDIT__ENVELOPE_LOG="$scratch/envelopes.jsonl" \
ACS__AUDIT__EVENT_LOG="$scratch/events.jsonl" \
  "${ACS_GUARDIAN_BIN:?set ACS_GUARDIAN_BIN through make conformance}" --config guardian.yaml >"$scratch/guardian.log" 2>&1 &
guardian_pid=$!

for attempt in $(seq 1 30); do
  if ! kill -0 "$guardian_pid" 2>/dev/null; then
    cat "$scratch/guardian.log"
    exit 1
  fi
  guardian_url="$(sed -n 's#^Guardian listening at \(http://[^ ]*/acs\)$#\1#p' "$scratch/guardian.log" | tail -n 1)"
  if [ -n "$guardian_url" ] && curl --fail --silent --show-error "${guardian_url%/acs}/readyz" >/dev/null; then
    break
  fi
  if [ "$attempt" -eq 30 ]; then
    cat "$scratch/guardian.log"
    exit 1
  fi
  sleep 1
done

cd "$typescript"
bun test packages/conformance/test/external-guardian.test.ts
ACS_CONFORMANCE_GUARDIAN_URL="$guardian_url" \
ACS_CONFORMANCE_HMAC_SECRET_FILE="$secret" \
ACS_CONFORMANCE_HMAC_KEY_ID=conformance \
  "$module/scripts/check-conformance-report.sh"
