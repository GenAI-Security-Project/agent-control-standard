#!/bin/sh
# smoke.sh: checks a running lab end to end in replay mode with no model key (issue #588, LAB-15).
#
# Version 1.0.0. Owner: Rock Lambros. Run after `./lab.sh init` and `./lab.sh up`, from any directory:
#   labs/finbot/images/smoke.sh
# The labs workflow's smoke job runs it, and so does anyone rerunning the stack check by hand. Until LAB-16's module 1
# lands, the model call is a scripted POST /v1/responses through FinBot's own base URL, answered by replay.
#
# Prints one DONE or NOT YET: line per check, plus NOTE: lines that record what FinBot can reach without checking
# it. Exit 0 when every check passes, 1 otherwise. The NOTE: lines never change the exit code.
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
approver_port=$(env_value LAB_PORT_APPROVER)
viewer_port=$(env_value LAB_PORT_VIEWER)
jaeger_port=$(env_value LAB_PORT_JAEGER)

# lab reset keeps the model key by default, so this line names the one command that deletes it.
if [ -e state/secrets/openai.key ]; then
    fail "state/secrets/openai.key holds a model key. The smoke run needs replay with no key: run ./lab.sh reset --delete-model-key, then init and up"
elif [ "$(env_value ACS_UPSTREAM)" = openai ]; then
    fail "the openai upstream is configured. The smoke run needs replay: run ./lab.sh upstream replay"
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

# The accepted residual from the LAB-15 review: finbot-net isn't internal, so FinBot can reach the approver port, the
# host's published ports and the internet. FinBot's own tools make no network call at 1450fc4, so this is recorded on
# every run, never checked, and a change in what FinBot reaches shows in the log. "@gateway" is the container's default
# route, which is the host on a Linux bridge network. host.docker.internal is the host on Docker Desktop.
reach_probe='# lab-reach-record
import socket, struct, sys, threading, time
def default_route():
    with open("/proc/net/route") as f:
        for line in f.read().splitlines()[1:]:
            fields = line.split()
            if fields[1] == "00000000":
                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    raise OSError("no default route")
# The 2-second bound covers the name lookup too. getaddrinfo takes no timeout, so it runs on a daemon thread, which
# the interpreter abandons at exit if the resolver never answers.
def connect(host, port, bound):
    deadline = time.monotonic() + bound
    found = []
    def lookup():
        try:
            found.append(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError as e:
            found.append(e)
    worker = threading.Thread(target=lookup, daemon=True)
    worker.start()
    worker.join(bound)
    if not found:
        raise TimeoutError()
    if isinstance(found[0], OSError):
        raise found[0]
    error = OSError("no address")
    for family, kind, proto, _, address in found[0]:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError()
        try:
            with socket.socket(family, kind, proto) as sock:
                sock.settimeout(left)
                sock.connect(address)
            return
        except OSError as e:
            error = e
    raise error
args = sys.argv[1:]
for host, port in zip(args[::2], args[1::2]):
    try:
        address = default_route() if host == "@gateway" else host
        connect(address, int(port), 2)
        print(f"reaches {host}:{port}")
    except OSError as e:
        print(f"cannot reach {host}:{port} ({type(e).__name__})")'
reach_targets="acs-gateway 8090"
for port in "${finbot_port:-8000}" "${approver_port:-8090}" "${viewer_port:-8095}" "${jaeger_port:-16686}"; do
    reach_targets="$reach_targets host.docker.internal $port @gateway $port"
done
# 11434 is Ollama's default port. On Docker Desktop FinBot could send model traffic there without the gateway.
reach_targets="$reach_targets host.docker.internal 11434 @gateway 11434 example.com 443"
printf 'NOTE: what FinBot reaches from finbot-net, recorded and not checked (the residual the LAB-15 review accepted)\n'
# shellcheck disable=SC2086
if reach=$(in_service finbot python -c "$reach_probe" $reach_targets 2>&1); then
    printf '%s\n' "$reach" | sed 's/^/NOTE: finbot /'
else
    printf 'NOTE: the reachability probe did not run: %s\n' "$(printf '%s' "$reach" | tail -n 1)"
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
# The service itself is PID 1 after the entrypoint's exec. A shell from `exec` would start as root, so it reads
# PID 1's real and effective uid instead of its own.
for service in acs-guardian acs-gateway acs-viewer; do
    got=$(in_service "$service" sh -c "sed -n 's/^Uid:[[:space:]]*\([0-9]*\)[[:space:]]*\([0-9]*\).*/\1 \2/p' /proc/1/status" \
          2>/dev/null || true)
    [ "$got" = "$uid $uid" ] && pass "$service runs as uid $uid" || fail "$service runs as uid '$got'"
done
for service in acs-gateway acs-guardian acs-viewer; do
    # Listed as root, so an empty answer means the tmpfs hides the files, not that permissions do.
    listing=$(docker compose -f compose.yaml exec -T -u 0 "$service" ls -A /lab/state/secrets 2>&1 || true)
    [ -z "$listing" ] && pass "$service can't see state/secrets" || fail "$service sees state/secrets: $listing"
done

# Module 1's model path. Every check below needs a positive result this run produced, never the absence of an error,
# so leftovers from an earlier local run can't pass it (final review R1). The call carries a fresh nonce, which also
# gives it a conversation of its own, so the gateway opens a new session and a new transcript for it.
nonce=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
audit_before=0
[ ! -f state/audit.log ] || audit_before=$(wc -c < state/audit.log | tr -d ' ')
transcripts_before=$(mktemp)
ls state/transcripts 2>/dev/null | sort > "$transcripts_before"
# The call passes only on HTTP 200 with the replay miss response, and prints its id and text so this shell checks
# them too. Anything else raises, which exits nonzero.
expected="resp_replay_miss: I couldn't complete that action."
if reply=$(in_service finbot python -c '
import json, os, sys, urllib.request
base = os.environ["OPENAI_BASE_URL"].rstrip("/")
body = json.dumps({"model": "gpt-5-nano", "input": [{"role": "user", "content": "lab smoke check " + sys.argv[1]}]})
request = urllib.request.Request(base + "/responses", data=body.encode(), headers={
    "Content-Type": "application/json", "Authorization": "Bearer " + os.environ["OPENAI_API_KEY"]})
with urllib.request.urlopen(request, timeout=30) as response:
    assert response.status == 200, response.status
    answer = json.load(response)
print(answer["id"] + ": " + answer["output"][0]["content"][0]["text"])
' "$nonce" 2>&1) && [ "$reply" = "$expected" ]; then
    pass "a model call through FinBot's base URL got the replay answer: $reply"
else
    fail "the model call through FinBot's base URL didn't get the replay answer: $reply"
fi
if grep -q "lab smoke check $nonce" state/model-inputs.jsonl 2>/dev/null; then
    pass "the model input log recorded this run's call"
else
    fail "the model input log has no line for this run's call"
fi
if [ -f state/audit.log ] && tail -c "+$((audit_before + 1))" state/audit.log | grep -q '"acs_audit_event": *"replay_miss"'; then
    pass "the audit log marks this run's unrecorded call as a replay miss"
else
    fail "no replay miss line in state/audit.log since this run started"
fi

# The session this call opened left a transcript named by its session id, one no earlier run created. acs-verify
# (LAB-11) checks its ML-DSA-65 decisions with the key document alone plus the HMAC secret for the requests.
# Interface pin on acs-verify's first output line.
new_transcripts=$(ls state/transcripts 2>/dev/null | sort | comm -13 "$transcripts_before" -)
rm -f "$transcripts_before"
if [ -n "$new_transcripts" ]; then
    pass "the call left a new transcript: $(printf '%s' "$new_transcripts" | tr '\n' ' ')"
    if [ "$(cat state/image-source 2>/dev/null)" = built ]; then
        export LAB_RUNTIME_IMAGE=acs-lab-runtime:local LAB_FINBOT_IMAGE=acs-lab-finbot:local
    fi
    [ "$(id -u)" -eq 0 ] || export LAB_UID="$(id -u)" LAB_GID="$(id -g)"
    for name in $new_transcripts; do
        verified=$(docker compose -f compose.yaml run --rm -T --entrypoint python lab -m acs.testing.verify \
                   "/lab/state/transcripts/$name" --keys /lab/state/keys/guardian-keys.json \
                   --hmac-secret /lab/state/secrets/hmac.key 2>/dev/null || true)
        if printf '%s\n' "$verified" | grep -q '^acs-verify: PASS' && printf '%s' "$verified" | grep -q 'ML-DSA-65'; then
            pass "acs-verify passes $name's ML-DSA-65 decisions"
        else
            fail "acs-verify didn't pass $name: $verified"
        fi
    done
else
    fail "the call left no new transcript"
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
