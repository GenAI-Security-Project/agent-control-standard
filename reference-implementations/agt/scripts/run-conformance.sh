#!/usr/bin/env bash
# Runs the conformance runner (packages/conformance/src/main.ts) for real:
# publishes the mapping table, the coverage matrix and the trace-pillar rows,
# with the policy-input schema check included rather than self-skipped.
#
# That check validates the policy input the Guardian would send at
# pre_tool_call / post_tool_call against AGT's OWN policy-input.schema.json
# at agt.lock's pinned ref -- never a copy of that schema kept in this repo.
# Reaching it needs the network, so this script mirrors
# scripts/verify-pin.sh's own pattern exactly: shallow-clone AGT at the
# pinned ref into a scratch temp dir, hand the clone's path to the runner by
# environment variable, clean up with `trash`. `bun test` alone never sets
# that variable, so the schema leg self-skips there and every other check
# stays covered whether or not a network is available (see main.ts's and
# policy-input-schema.ts's own headers).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

lock_file="agt.lock"
if [ ! -f "$lock_file" ]; then
  echo "run-conformance: missing $lock_file" >&2
  exit 1
fi

agt_repo="$(jq -r '.agt_repo' "$lock_file")"
agt_ref="$(jq -r '.agt_ref' "$lock_file")"

if [ -z "$agt_repo" ] || [ -z "$agt_ref" ]; then
  echo "run-conformance: agt.lock is missing agt_repo/agt_ref" >&2
  exit 1
fi

if ! command -v trash >/dev/null 2>&1; then
  echo "run-conformance: 'trash' is required for scratch-dir cleanup (rm -rf is not permitted in this repo) — install it and re-run" >&2
  exit 1
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/run-conformance.XXXXXX")"
cleanup() {
  trash "$tmp_dir"
}
trap cleanup EXIT

# No identifying information on outbound git traffic: no credential helper,
# no terminal credential prompt, and git's default HTTP User-Agent carries
# no contact field.
export GIT_TERMINAL_PROMPT=0

git -c credential.helper= -c credential.useHttpPath=false \
  init --quiet "$tmp_dir"
git -C "$tmp_dir" -c credential.helper= remote add origin "$agt_repo"
git -C "$tmp_dir" -c credential.helper= fetch --quiet --depth 1 origin "$agt_ref"
git -C "$tmp_dir" -c credential.helper= checkout --quiet FETCH_HEAD

schema_path="$tmp_dir/policy-engine/spec/schema/wire/policy-input.schema.json"
if [ ! -f "$schema_path" ]; then
  echo "run-conformance: expected upstream schema at $schema_path" >&2
  exit 1
fi

PINNED_AGT_CLONE="$tmp_dir" bun run packages/conformance/src/main.ts
