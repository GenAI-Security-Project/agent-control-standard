#!/usr/bin/env bash
set -euo pipefail

module="$(cd "$(dirname "$0")/.." && pwd)"
cd "$module/../agt"
report="$(PINNED_AGT_CLONE="$module/.acs/agt/src" bun run conformance:guardian)"
printf '%s\n' "$report"
if ! printf '%s\n' "$report" | grep -q '^policy-input schema .*: RAN'; then
  printf '%s\n' 'the AGT policy-input schema checks did not run' >&2
  exit 1
fi
if ! printf '%s\n' "$report" | grep -q '^external Guardian wire checks: RAN'; then
  printf '%s\n' 'the external Guardian leg did not run; the Guardian was never probed' >&2
  exit 1
fi
