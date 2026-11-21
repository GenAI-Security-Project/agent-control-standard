#!/usr/bin/env bash
# Refuses tracked files that look like local build output: a binary file, a
# file over 1 MiB, or a line naming a developer's home directory. Binary test
# data is allowed by path below. Also refuses a Dockerfile FROM line whose
# image has no digest, because a tag can move to another image, and a golang
# image whose Go differs from the go line of either go.mod.
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
# from_instructions prints each FROM instruction as file, line and
# instruction, separated by tabs. FROM is case-insensitive and may continue on
# the next line. As in Docker, a comment line never continues and is dropped
# inside an instruction.
from_instructions='
  FNR == 1 { sub(/^\xef\xbb\xbf/, "") }
  { sub(/\r$/, "") }
  /^[ \t]*#/ { next }
  { gsub(/[ \t]+/, " ") }
  joined != "" { $0 = joined " " $0; joined = "" }
  /\\$/ { sub(/\\$/, ""); joined = $0; next }
  tolower($1) == "from" { print FILENAME "\t" FNR "\t" $0 }'
# scratch and an earlier stage of the same file name no image.
unpinned="$(git ls-files -z -- ':(icase)*dockerfile*' ':(icase)*containerfile*' ':!:*.dockerignore' | xargs -0r awk "$from_instructions" | awk -F '\t' '
  {
    n = split($3, word, " "); image = ""
    for (i = 2; i <= n; i++) if (word[i] !~ /^--/) { image = tolower(word[i]); break }
    if (image != "scratch" && !(($1, image) in stage) && image !~ /@sha256:[0-9a-f]{64}$/) print $1 ":" $2 ": " $3
    if (tolower(word[n - 1]) == "as") stage[$1, tolower(word[n])] = 1
  }')"
if [[ -n "$unpinned" ]]; then
  printf '%s\nthe FROM lines above name an image by tag only; pin each image by its sha256 digest\n' "$unpinned" >&2
  failed=1
fi
# The image's Go must be the Go that CI tests with.
# The image is the first word after FROM that is not a flag such as --platform.
image_go="$(awk "$from_instructions" Dockerfile | cut -f 3 | awk '{ for (i = 2; i <= NF; i++) if ($i !~ /^--/) { print $i; break } }' | { grep -o -i -E '^((docker\.io/)?library/)?golang:[0-9.]+' || true; } | head -n 1 | cut -d: -f2)"
if [[ -z "$image_go" ]]; then
  echo 'no FROM line names a golang:<version> image; the Dockerfile must build with the Go that CI tests with' >&2
  failed=1
fi
for mod in go.mod examples/custom-engine/go.mod; do
  module_go="$(sed -n -E 's/^go ([0-9.]+)$/\1/p' "$mod")"
  if [[ -n "$image_go" && "$image_go" != "$module_go" ]]; then
    printf 'Dockerfile builds with Go %s, and %s requires Go %s; move both together\n' "$image_go" "$mod" "$module_go" >&2
    failed=1
  fi
done
exit "$failed"
