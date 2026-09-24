#!/usr/bin/env bash
set -euo pipefail

if (( $# == 0 )); then
  echo "usage: scripts/run-host-example.sh command [argument ...]" >&2
  exit 2
fi

port="${ACS_HOST_EXAMPLE_PORT:-0}"
if [ "$port" != 0 ] && curl --fail --silent --show-error "http://127.0.0.1:$port/readyz" >/dev/null; then
  echo "127.0.0.1:$port is already serving a Guardian" >&2
  exit 1
fi

scratch="$(mktemp -d "${TMPDIR:-/tmp}/acs-host-example.XXXXXX")"
guardian_log="$scratch/guardian.log"
ACS__SERVER__PORT="$port" \
ACS__AUDIT__ENVELOPE_LOG="$scratch/envelopes.jsonl" \
ACS__AUDIT__EVENT_LOG="$scratch/events.jsonl" \
  .acs/bin/acs-guardian --config guardian.yaml >"$guardian_log" 2>&1 &
guardian_pid=$!

cleanup() {
  kill "$guardian_pid" 2>/dev/null || true
  wait "$guardian_pid" 2>/dev/null || true
  rm -f "$guardian_log" "$scratch/envelopes.jsonl" "$scratch/events.jsonl"
  rmdir "$scratch"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for attempt in $(seq 1 30); do
  if ! kill -0 "$guardian_pid" 2>/dev/null; then
    cat "$guardian_log"
    exit 1
  fi
  guardian_url="$(sed -n 's#^Guardian listening at \(http://[^ ]*/acs\)$#\1#p' "$guardian_log" | tail -n 1)"
  if [ -n "$guardian_url" ] && curl --fail --silent --show-error "${guardian_url%/acs}/readyz" >/dev/null; then
    ACS_GUARDIAN_URL="$guardian_url" "$@"
    exit $?
  fi
  if (( attempt == 30 )); then
    cat "$guardian_log"
    exit 1
  fi
  sleep 1
done
