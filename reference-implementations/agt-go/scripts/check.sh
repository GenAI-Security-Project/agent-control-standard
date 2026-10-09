#!/usr/bin/env bash
set -euo pipefail

umask 077
mkdir -p .acs/checks
log="$(mktemp ".acs/checks/check-$(date +%Y%m%d-%H%M%S).XXXXXX")"
mv "$log" "$log.log"
log="$log.log"
log="$(pwd)/$log"
printf 'Checking the Guardian with AGT and Go...\n'
inline=0
if [[ -t 1 && "${CI:-}" != true ]]; then inline=1; fi
set +e
ACS_CHECK_PROGRESS=1 "$@" --no-print-directory check-all 2>&1 | {
  active=''
  while IFS= read -r line || [[ -n "$line" ]]; do
    printf '%s\n' "$line" >>"$log" || exit 1
    case "$line" in
      '[check] RUN: '*)
        if [[ "$inline" == 1 && -n "$active" ]]; then printf '\n'; fi
        active="${line#'[check] RUN: '}"
        if [[ "$inline" == 1 ]]; then
          printf '%s... ' "$active"
        else
          printf '%s...\n' "$active"
        fi
        ;;
      '[check] PASS: '*)
        stage="${line#'[check] PASS: '}"
        if [[ "$inline" == 1 && "$stage" == "$active" ]]; then
          printf 'PASS\n'
        else
          if [[ "$inline" == 1 && -n "$active" ]]; then printf '\n'; fi
          printf '%s... PASS\n' "$stage"
        fi
        if [[ "$stage" == "$active" ]]; then active=''; fi
        ;;
    esac
  done
  if [[ -n "$active" ]]; then
    if [[ "$inline" == 1 ]]; then printf 'FAIL\n'; else printf '%s... FAIL\n' "$active"; fi
  fi
}
statuses=("${PIPESTATUS[@]}")
set -e
status="${statuses[0]}"
if [[ "$status" == 0 ]]; then
  status="${statuses[1]}"
fi
if [[ "$status" == 0 ]]; then
  printf 'PASS: All checks passed for AGT and Go.\nDetails: %s\n' "$log"
else
  printf 'FAIL: Checks stopped with exit code %s.\n' "$status" >&2
  tail -n 80 "$log" >&2
  printf 'Full details: %s\n' "$log" >&2
  exit "$status"
fi
