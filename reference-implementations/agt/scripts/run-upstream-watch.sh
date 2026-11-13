#!/usr/bin/env bash
# Runs the upstream contract watch for real: shallow-clones AGT twice --
# once at agt.lock's pinned ref, once at main -- and hands both paths to the
# runner by environment variable.
#
# Two clones, two variables, and they are never the same name: the pinned
# side is PINNED_AGT_CLONE (the variable the conformance run already uses)
# and the upstream side is UPSTREAM_AGT_CLONE. A run that read one side
# twice would report a clean diff against a contract that moved.
#
# `bun test` sets neither, so the watch self-skips there and the rest of the
# suite stays covered whether or not a network is available.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

lock_file="agt.lock"
if [ ! -f "$lock_file" ]; then
  echo "run-upstream-watch: missing $lock_file" >&2
  exit 1
fi

agt_repo="$(jq -r '.agt_repo' "$lock_file")"
agt_ref="$(jq -r '.agt_ref' "$lock_file")"

if [ -z "$agt_repo" ] || [ -z "$agt_ref" ]; then
  echo "run-upstream-watch: agt.lock is missing agt_repo/agt_ref" >&2
  exit 1
fi

if ! command -v trash >/dev/null 2>&1; then
  echo "run-upstream-watch: 'trash' is required for scratch-dir cleanup (rm -rf is not permitted in this repo) — install it and re-run" >&2
  exit 1
fi

pinned_dir="$(mktemp -d "${TMPDIR:-/tmp}/upstream-watch-pinned.XXXXXX")"
upstream_dir="$(mktemp -d "${TMPDIR:-/tmp}/upstream-watch-main.XXXXXX")"
cleanup() {
  trash "$pinned_dir"
  trash "$upstream_dir"
}
trap cleanup EXIT

# No identifying information on outbound git traffic: no credential helper,
# no terminal credential prompt, and git's default HTTP User-Agent carries
# no contact field.
export GIT_TERMINAL_PROMPT=0

fetch_into() {
  local dir="$1" ref="$2"
  git -c credential.helper= -c credential.useHttpPath=false init --quiet "$dir"
  git -C "$dir" -c credential.helper= remote add origin "$agt_repo"
  git -C "$dir" -c credential.helper= fetch --quiet --depth 1 origin "$ref"
  git -C "$dir" -c credential.helper= checkout --quiet FETCH_HEAD
}

fetch_into "$pinned_dir" "$agt_ref"
fetch_into "$upstream_dir" "main"

# Resolved here, and handed to the runner the same way the clone paths are --
# by environment variable -- so the report can name the two commits it
# actually compared without anything in TypeScript resolving a ref itself.
pinned_sha="$(git -C "$pinned_dir" rev-parse HEAD)"
upstream_sha="$(git -C "$upstream_dir" rev-parse HEAD)"

PINNED_AGT_CLONE="$pinned_dir" UPSTREAM_AGT_CLONE="$upstream_dir" \
  PINNED_AGT_SHA="$pinned_sha" UPSTREAM_AGT_SHA="$upstream_sha" \
  bun run packages/conformance/src/upstream-watch.ts
