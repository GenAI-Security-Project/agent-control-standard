#!/usr/bin/env bash
# The zero-diff claim, mechanically: adding the second host must cost zero
# changed lines in the Guardian, the AGT bridge, or AGT itself -- this diff IS
# the demonstration. Same shape as verify-pin.sh: a check that needs git
# history, so it is a script rather than a bun test.
set -euo pipefail

# cd to the repo root, as verify-pin.sh does (verify-pin.sh:9-10). Under a
# user's `diff.relative=true`, invoked from a subdirectory,
# `git diff --name-only` emits paths relative to the CURRENT
# DIRECTORY (`guardian/src/server.ts`, not `packages/guardian/src/server.ts`),
# and every `^`-anchored alternative below would silently miss.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

base="${1:-slice/v4}"

# Verify the base ref resolves BEFORE diffing against it. An earlier form,
# `git diff --name-only "$base"...HEAD | grep ... || true`, put `|| true`
# around the WHOLE pipeline, not just grep's "no match" exit code -- so an
# unresolvable `$base` (git prints `fatal: ambiguous argument` to stderr and
# the pipeline fails) was swallowed the same way as a clean pass, and the
# script printed success. That is the gate-that-cannot-fail case, on the
# exact path this check exists for: a fresh clone that has `origin/slice/v4`
# but no local `slice/v4`, and the repo after the branch stack merges and
# `slice/v4` is deleted -- this script's whole reason to exist instead of a
# `bun test` (see the header above). Falls back to `origin/$base` before
# giving up, since that is what a fresh clone actually has.
#
# Resolving the ref stops the bad-ref trigger, but not the MECHANISM --
# `|| true` around the whole pipeline still swallows any OTHER git failure
# past this point. A shallow clone (`git clone --depth 1` plus
# `git fetch --depth 1 origin slice/v4`, the standard CI checkout shape)
# resolves `origin/slice/v4` fine -- the guard above passes -- and THEN
# `git diff "$base"...HEAD` itself fails with "no merge base", because the
# shallow history has no common ancestor to diff from. That fails the same
# way an unresolvable ref did: silently, as a clean pass. So it is fixed at
# the root (both diff sites below), not by guarding one more trigger --
# `git diff --name-only` runs on its own line first, so ITS failure hits
# `set -e` and stops the script with git's own message, and only grep's
# "no match" (a real, expected, non-error outcome) gets `|| true`.
resolve_ref() {
  local candidate="$1"
  if git rev-parse --verify --quiet "${candidate}^{commit}" >/dev/null; then
    printf '%s\n' "$candidate"
    return 0
  fi
  return 1
}

if resolved="$(resolve_ref "$base")"; then
  base="$resolved"
elif resolved="$(resolve_ref "origin/$base")"; then
  base="$resolved"
else
  echo "verify-zero-diff: base ref '$base' not found (checked '$base' and 'origin/$base') -- pass a valid base explicitly, e.g. 'bun run verify:zero-diff origin/slice/v4'" >&2
  exit 1
fi

# `policy/lib/` -- the pinned bundle and its config -- NOT `policy/` wholesale.
# What this freeze and `verify:pin` protect is the unforked bundle: zero Rego
# authored, every `.rego` byte-identical, `data.agt.defaults.config`
# unchanged. `policy/manifest.yaml` (and its drift mirror) is the
# deployment's tool REGISTRY, not its policy, and a deployment governing two
# hosts registers both hosts' tool names -- OpenCode calls its shell tool
# `bash` where Claude Code calls it `Bash`, and an unregistered name fails
# AGT's evaluation closed before any rule runs. Freezing `policy/` wholesale
# would fail this script on a change a two-host deployment legitimately
# requires, and the fix would be to loosen the check until it passed --
# exactly the mistake this script exists not to make.
#
# `hosts/claude-code/[^/]+\.(ts|yaml)$` -- NOT `hosts/claude-code/`
# wholesale, and NOT `hosts/claude-code/src` (that directory does not exist --
# the shim is `hosts/claude-code/acs-hook.ts` at the package root, so a
# `src/` alternative would be a branch that can never match: a dead check
# reading as protection, the same failure mode this whole script exists to
# avoid). This narrower form covers `acs-hook.ts` and
# `claude-code.hookmap.yaml` -- host #1's actual wire contract -- and
# deliberately excludes `hosts/claude-code/test/`, because adding the second
# host also added two purely additive regression tests there
# (post-tool-use.test.ts, posture.test.ts; +79/-0), covering the code both
# hosts now share, and a wholesale freeze would reject those for the wrong
# reason -- the same "loosen the gate until it passes" failure the
# `policy/lib/` note above exists to prevent. Host #1's SOURCE is +0/-0
# throughout; this makes that claim -- "host #1 needed no change either" --
# part of what the script proves, not just prose.
frozen='^(packages/guardian/src/|packages/agt-bridge/src/|policy/lib/|agt\.lock$|mapping\.yaml$|hosts/claude-code/[^/]+\.(ts|yaml)$)'

diff_output="$(git diff --name-only "$base"...HEAD)" || {
  echo "verify-zero-diff: git diff against '$base' failed -- is this a shallow clone? try 'git fetch --unshallow'" >&2
  exit 1
}
changed="$(printf '%s\n' "$diff_output" | grep -E "$frozen" || true)"
if [ -n "$changed" ]; then
  echo "verify-zero-diff: the second host must cost zero changed lines in the Guardian, the AGT bridge, or AGT itself -- but these frozen paths changed:" >&2
  echo "$changed" >&2
  exit 1
fi

# A SECOND, separately labelled question -- not merged into the check above,
# because the two answer different things. `base...HEAD` (above) is the
# committed diff, the claim as it ships, and the right PRIMARY check: failing
# on someone's uncommitted scratch edit would be exactly the "annoyingly
# false" failure mode this suite works to avoid, and `verify-pin.sh`'s own
# precedent (its byte-diff runs against whatever is checked out, uncommitted
# or not) does not override that -- zero diff is a claim about what ships,
# not about a work-in-progress edit. But leaving it at that has two real
# gaps: the check is otherwise unusable pre-commit (this script's own
# mutation test needed a temporary commit for exactly this reason), and an
# uncommitted edit under a frozen path could leave `bun test` green BECAUSE
# of that edit while the check above still reports zero, since it never
# touched HEAD. This closes both: staged and unstaged changes against the
# same frozen set, diffed against HEAD directly.
working_tree_diff="$(git diff --name-only HEAD)" || {
  echo "verify-zero-diff: git diff against HEAD failed" >&2
  exit 1
}
working_tree_changed="$(printf '%s\n' "$working_tree_diff" | grep -E "$frozen" || true)"
if [ -n "$working_tree_changed" ]; then
  echo "verify-zero-diff: the second host must cost zero changed lines in the Guardian, the AGT bridge, or AGT itself -- but these frozen paths changed, uncommitted in the working tree:" >&2
  echo "$working_tree_changed" >&2
  exit 1
fi

echo "verify-zero-diff: zero changed lines under the Guardian, the bridge, or AGT (vs $base, committed and working tree)"
