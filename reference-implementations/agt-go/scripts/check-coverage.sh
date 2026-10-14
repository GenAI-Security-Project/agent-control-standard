#!/usr/bin/env bash
# Fails when the statement coverage of the module's packages, counted across
# every test in the module, falls below the floor. Every package counts except
# the ones excluded below: commands, examples and test helpers. A new package
# is therefore counted without anyone listing it. Arguments after the floor go
# to go list and go test, so `-tags agteval` counts the agt evaluator.
#
# Usage: scripts/check-coverage.sh [floor-percent] [go flags...]
set -euo pipefail

floor="${1:-80}"
shift || true
cd "$(dirname "$0")/.."
module="$(go list -m)"
excluded="^$module/(cmd|examples|internal/docscheck|internal/tscases|guardian/guardiantest)(/|$)"
packages="$(go list "$@" ./... | grep -Ev "$excluded" | paste -sd, -)"
profile="$(mktemp)"
output="$(mktemp)"
trap 'rm -f "$profile" "$output"' EXIT
if ! go test "$@" ./... -coverpkg="$packages" -coverprofile="$profile" >"$output" 2>&1; then
  grep -Ev '^(ok |\? |coverage: )' "$output" >&2
  exit 1
fi
total="$(go tool cover -func="$profile" | awk '/^total:/ {sub("%", "", $3); print $3}')"
echo "package coverage: ${total}% (floor ${floor}%)"
awk -v t="$total" -v f="$floor" 'BEGIN { exit !(t + 0 >= f + 0) }'
