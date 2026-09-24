#!/usr/bin/env bash
# Fails when the statement coverage of the protocol packages, counted across
# every test in the module, falls below the floor. The protocol packages are
# the ones that implement the standard; commands, examples and test helpers
# are not counted.
#
# Usage: scripts/check-coverage.sh [floor-percent]
set -euo pipefail

floor="${1:-80}"
cd "$(dirname "$0")/.."
module="$(go list -m)"
packages="$module/acs,$module/guardian,$module/agtbridge,$module/internal/mcp"
for p in jcs schema chain envelope method handshake disposition; do
  packages="$packages,$module/internal/$p"
done
profile="$(mktemp)"
trap 'rm -f "$profile"' EXIT
go test ./... -coverpkg="$packages" -coverprofile="$profile" >/dev/null
total="$(go tool cover -func="$profile" | awk '/^total:/ {sub("%", "", $3); print $3}')"
echo "protocol package coverage: ${total}% (floor ${floor}%)"
awk -v t="$total" -v f="$floor" 'BEGIN { exit !(t + 0 >= f + 0) }'
