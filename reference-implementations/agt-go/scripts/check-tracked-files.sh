#!/usr/bin/env bash
# Refuses tracked files that look like local build output: a binary file, a
# file over 1 MiB, or a line naming a developer's home directory. Binary test
# data is allowed by path below.
set -euo pipefail

allowed_binary=(
  internal/jcs/testdata/es6-numbers.txt.gz
)
max_bytes=1048576

failed=0
text_files="$(git grep -I --name-only -e '' -- .)"
while IFS= read -r -d '' path; do
  [[ -f "$path" ]] || continue
  size="$(wc -c <"$path")"
  if ((size > max_bytes)); then
    printf '%s: %d bytes, over %d; generated output does not belong in the repository\n' "$path" "$size" "$max_bytes" >&2
    failed=1
  fi
  if ((size > 0)) && ! grep -qxF -- "$path" <<<"$text_files"; then
    allowed=0
    for a in "${allowed_binary[@]}"; do [[ "$path" == "$a" ]] && allowed=1; done
    if ((allowed == 0)); then
      printf '%s: binary file; add binary test data to scripts/check-tracked-files.sh by path\n' "$path" >&2
      failed=1
    fi
  fi
done < <(git ls-files -z -- .)

if git grep -n -I -E '(/home/|/Users/)[A-Za-z0-9._-]+|(^|[^A-Za-z0-9._-])/root(/|$|[^A-Za-z0-9._-])' -- . ':!scripts/check-tracked-files.sh' >&2; then
  printf 'the lines above name a home directory; use a relative path\n' >&2
  failed=1
fi
exit "$failed"
