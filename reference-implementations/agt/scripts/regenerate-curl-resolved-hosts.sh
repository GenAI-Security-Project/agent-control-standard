#!/usr/bin/env bash
# Re-measures, for every command line in the differential corpus, the host
# `curl` itself resolves that command's URL to — and rewrites the corpus file
# with the measurements.
#
# WHY THIS EXISTS. The Guardian's egress annotator reads a PRE-SHELL command
# line and has to answer which host it reaches. `curl` answers that from a
# POST-SHELL argument, using its own parser, which agrees with neither the
# WHATWG parser nor the two splits AGT's gate performs. Four attempts to
# compute the answer from the command line each shipped a different bypass. So
# the answer is measured from `curl` instead of derived, and the corpus test in
# packages/guardian/test/annotate-egress.test.ts asserts against it.
#
# WHY IT DOES NOT RUN ON EVERY TEST RUN. Spawning eighteen curls per `bun test`
# is slow and makes the suite depend on a binary's version. The measurements are
# pinned here instead; re-run this script when the corpus grows, and commit the
# result.
#
# HOW THE MEASUREMENT AVOIDS SENDING ANYTHING. `--proxy http://127.0.0.1:1`
# points curl at a port nothing listens on, so every request fails to connect
# (exit 7) with no packet leaving the machine. `-w '%{url.host}'` is filled in
# from curl's own parse of the URL before any connection is attempted, which is
# precisely the value wanted. No `User-Agent` beyond curl's default is set and
# no identifying header is added.
#
# HOW THE SHELL HALF IS KEPT HONEST. Each command is run through `eval` in a
# real bash, so bash performs the word splitting and quote removal it would
# perform for real — the backslash rows in the corpus exist because that step is
# where the annotator and curl part company. Globbing is switched off with
# `set -f`: the corpus carries URLs containing `?`, which bash would otherwise
# treat as a single-character pattern. With globbing on, bash leaves a pattern
# that matches no file unchanged, so this changes no measurement unless a file
# in the working directory happens to match a URL.
#
# TO EXTEND THE CORPUS: add the command line as a new key in the corpus file
# with any placeholder value, then run
#
#   bash scripts/regenerate-curl-resolved-hosts.sh
#
# and commit the rewritten file.
set -euo pipefail
set -f

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

corpus="packages/guardian/test/fixtures/curl-resolved-hosts.json"
dead_proxy="http://127.0.0.1:1"

if [ ! -f "$corpus" ]; then
  echo "regenerate-curl-resolved-hosts: missing $corpus" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "regenerate-curl-resolved-hosts: 'jq' is required" >&2
  exit 1
fi

measured="{}"
while IFS= read -r command; do
  case "$command" in
    "curl "*) ;;
    *)
      echo "regenerate-curl-resolved-hosts: every corpus entry must be a curl command line; got: $command" >&2
      exit 1
      ;;
  esac

  argument="${command#curl }"
  host="$(eval "curl -s -o /dev/null --proxy $dead_proxy -w '%{url.host}' $argument" || true)"

  if [ -z "$host" ]; then
    echo "regenerate-curl-resolved-hosts: curl resolved no host for: $command" >&2
    exit 1
  fi

  measured="$(jq --arg k "$command" --arg v "$host" '. + {($k): $v}' <<<"$measured")"
done < <(jq -r 'keys_unsorted[]' "$corpus")

jq --indent 2 . <<<"$measured" > "$corpus"
echo "regenerate-curl-resolved-hosts: rewrote $corpus"
