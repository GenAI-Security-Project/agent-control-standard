#!/usr/bin/env bash
set -euo pipefail

module="$(cd "$(dirname "$0")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/acs-image.XXXXXX")"
container=""
cleanup() {
  if [ -n "$container" ]; then docker rm -f "$container" >/dev/null; fi
  rm -f "$scratch/hmac-secret"
  rmdir "$scratch"
}
trap cleanup EXIT
openssl rand 32 >"$scratch/hmac-secret"
chmod 600 "$scratch/hmac-secret"
container="$(docker run --detach --platform "${IMAGE_PLATFORM:?set IMAGE_PLATFORM through make image-check}" --publish 127.0.0.1::8787 \
  --user "$(id -u):$(id -g)" \
  --tmpfs "/data:uid=$(id -u),gid=$(id -g),mode=0700" \
  --mount "type=bind,src=$scratch/hmac-secret,dst=/run/secrets/acs-hmac,readonly" \
  --env ACS__SECURITY__HMAC_KEY_ID=conformance "${IMAGE:?set IMAGE through make image-check}")"
port="$(docker port "$container" 8787/tcp | sed 's/.*://')"
url="http://127.0.0.1:$port/acs"
for attempt in $(seq 1 30); do
  if [ "$(docker inspect --format '{{.State.Running}}' "$container")" != true ]; then
    docker logs "$container"
    exit 1
  fi
  if curl --fail --silent "${url%/acs}/readyz" >/dev/null; then break; fi
  if [ "$attempt" -eq 30 ]; then docker logs "$container"; exit 1; fi
  sleep 1
done
ACS_CONFORMANCE_GUARDIAN_URL="$url" \
ACS_CONFORMANCE_HMAC_SECRET_FILE="$scratch/hmac-secret" \
ACS_CONFORMANCE_HMAC_KEY_ID=conformance \
  "$module/scripts/check-conformance-report.sh"
