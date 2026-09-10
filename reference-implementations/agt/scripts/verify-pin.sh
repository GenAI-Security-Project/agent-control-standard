#!/usr/bin/env bash
# Verifies the vendored policy/lib bundle is byte-identical to AGT at the
# pinned ref recorded in agt.lock. Clones the pinned commit into a scratch
# temp dir, points UPSTREAM_BUNDLE at its policy-engine/policy/lib, and
# re-runs the pin test so the byte-identity assertion (self-skipped without
# that env var) actually executes.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

lock_file="agt.lock"
if [ ! -f "$lock_file" ]; then
  echo "verify-pin: missing $lock_file" >&2
  exit 1
fi

agt_repo="$(jq -r '.agt_repo' "$lock_file")"
agt_ref="$(jq -r '.agt_ref' "$lock_file")"
bundle_path="$(jq -r '.bundle_path' "$lock_file")"

if [ -z "$agt_repo" ] || [ -z "$agt_ref" ] || [ -z "$bundle_path" ]; then
  echo "verify-pin: agt.lock is missing agt_repo/agt_ref/bundle_path" >&2
  exit 1
fi

if ! command -v trash >/dev/null 2>&1; then
  echo "verify-pin: 'trash' is required for scratch-dir cleanup (rm -rf is not permitted in this repo) — install it and re-run" >&2
  exit 1
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/verify-pin.XXXXXX")"
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

upstream_bundle="$tmp_dir/$bundle_path"
if [ ! -d "$upstream_bundle" ]; then
  echo "verify-pin: expected upstream bundle at $upstream_bundle" >&2
  exit 1
fi

UPSTREAM_BUNDLE="$upstream_bundle" bun test test/pin.test.ts
