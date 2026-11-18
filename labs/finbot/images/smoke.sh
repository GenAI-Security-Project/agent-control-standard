#!/bin/sh
# smoke.sh: checks a running lab end to end in replay mode with no model key (issue #588, LAB-15).
#
# Version 1.0.0. Owner: Rock Lambros. Run after `./lab.sh init` and `./lab.sh up`, from any directory:
#   labs/finbot/images/smoke.sh
# The labs workflow's smoke job runs it, and so does anyone rerunning the stack check by hand. Until LAB-16's module 1
# lands, the model call is a scripted POST /v1/responses through FinBot's own base URL, answered by replay.
#
# Prints one DONE or NOT YET: line per check. Exit 0 when every check passes, 1 otherwise.
set -u
cd "$(dirname "$0")/.."

status=0
pass() { printf 'DONE: %s\n' "$1"; }
fail() { printf 'NOT YET: %s\n' "$1"; status=1; }
in_service() {
    service=$1
    shift
    docker compose -f compose.yaml exec -T "$service" "$@"
}
env_value() {
    [ -f .env ] || return 0
    sed -n "s/^$1=//p" .env | tail -n 1
}

admin_ip=$(env_value LAB_GATEWAY_ADMIN_IP)
admin_ip=${admin_ip:-10.88.47.10}
uid=$(id -u)
[ "$uid" -ne 0 ] || uid=10001
finbot_port=$(env_value LAB_PORT_FINBOT)
viewer_port=$(env_value LAB_PORT_VIEWER)

if [ -e state/secrets/openai.key ] || [ "$(env_value ACS_UPSTREAM)" = openai ]; then
    fail "a model key or the openai upstream is configured. The smoke run needs replay with no key"
else
    pass "replay upstream, no model key anywhere in the bundle"
fi

running=$(docker compose -f compose.yaml ps --status running --services 2>/dev/null | sort | tr '\n' ' ')
for service in acs-gateway acs-guardian acs-viewer finbot opa redis; do
    case " $running" in
        *" $service "*) pass "$service is running" ;;
        *) fail "$service is not running" ;;
    esac
done

# Review focus 1: FinBot's own tools run inside FinBot, so FinBot's network must not reach the admin port, the
# Guardian, or OPA.
probe='import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    socket.create_connection((host, port), 3).close()
except OSError:
    sys.exit(1)'
for target in "$admin_ip 8091" "acs-gateway 8091" "acs-guardian 8787" "opa 8181"; do
    # shellcheck disable=SC2086
    if in_service finbot python -c "$probe" $target >/dev/null 2>&1; then
        fail "finbot reached $target"
    else
        pass "finbot can't reach $target"
    fi
done
if in_service finbot python -c "$probe" acs-gateway 8080 >/dev/null 2>&1; then
    pass "finbot reaches the gateway's model port"
else
    fail "finbot can't reach the gateway's model port"
fi

if ./lab.sh _epoch | grep -q '^DONE'; then
    pass "the lab CLI bumps the epoch over the acs-net admin port"
else
    fail "the lab CLI couldn't bump the epoch"
fi

for service_file in "acs-guardian /run/acs/guardian.key" "acs-guardian /run/acs/hmac.key" \
                    "acs-gateway /run/acs/hmac.key" "acs-gateway /run/acs/admin.token"; do
    # shellcheck disable=SC2086
    set -- $service_file
    got=$(in_service "$1" stat -c '%a %u' "$2" 2>/dev/null || true)
    if [ "$got" = "600 $uid" ]; then
        pass "$1 $2 is 0600 and owned by uid $uid"
    else
        fail "$1 $2 is '$got', expected '600 $uid'"
    fi
done
for service in acs-guardian acs-gateway; do
    got=$(in_service "$service" id -u 2>/dev/null || true)
    [ "$got" = "$uid" ] && pass "$service runs as uid $uid" || fail "$service runs as uid '$got'"
done
for service in acs-gateway acs-viewer; do
    listing=$(in_service "$service" ls -A /lab/state/secrets 2>&1 || true)
    [ -z "$listing" ] && pass "$service can't see state/secrets" || fail "$service sees state/secrets: $listing"
done

before=$(wc -l < state/model-inputs.jsonl 2>/dev/null || echo 0)
reply=$(in_service finbot python -c '
import json, os, urllib.request
base = os.environ["OPENAI_BASE_URL"].rstrip("/")
body = json.dumps({"model": "gpt-5-nano", "input": [{"role": "user", "content": "lab smoke check"}]}).encode()
request = urllib.request.Request(base + "/responses", data=body, headers={
    "Content-Type": "application/json", "Authorization": "Bearer " + os.environ["OPENAI_API_KEY"]})
with urllib.request.urlopen(request, timeout=30) as response:
    answer = json.load(response)
print(answer["output"][0]["content"][0]["text"])
' 2>&1)
if [ -n "$reply" ] && printf '%s' "$reply" | grep -qv Traceback; then
    pass "a model call through FinBot's base URL got a replay answer: $reply"
else
    fail "the model call through FinBot's base URL failed: $reply"
fi
after=$(wc -l < state/model-inputs.jsonl 2>/dev/null || echo 0)
[ "$after" -gt "$before" ] && pass "the model input log recorded the call" || fail "the model input log didn't grow"
if grep -q '"acs_audit_event": *"replay_miss"' state/audit.log 2>/dev/null; then
    pass "the audit log marks the unrecorded call as a replay miss"
else
    fail "no replay_miss line in state/audit.log"
fi

if curl -fsS "http://127.0.0.1:${finbot_port:-8000}/healthz" >/dev/null 2>&1; then
    pass "FinBot answers on 127.0.0.1:${finbot_port:-8000}"
else
    fail "FinBot doesn't answer on 127.0.0.1:${finbot_port:-8000}"
fi
if curl -fsS "http://127.0.0.1:${viewer_port:-8095}/api/rows?after=0" >/dev/null 2>&1; then
    pass "the viewer answers on 127.0.0.1:${viewer_port:-8095}"
else
    fail "the viewer doesn't answer on 127.0.0.1:${viewer_port:-8095}"
fi

exit "$status"
