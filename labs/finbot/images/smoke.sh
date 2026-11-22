#!/bin/sh
# smoke.sh: checks a running lab end to end in replay mode with no model key (issue #588, LAB-15).
#
# Version 1.2.0. Owner: Rock Lambros. Run after `./lab.sh init` and `./lab.sh up`, from any directory:
#   labs/finbot/images/smoke.sh
# The labs workflow's smoke job runs it, and so does anyone rerunning the stack check by hand. The model path is
# module 1 itself, played with lab mode, lab run s1 and lab check 1 (issue #589, LAB-16), answered by replay.
#
# Prints one DONE or NOT YET: line per check, plus a NOTE: line that records, without checking, that FinBot reaches the
# gateway's approver port. Exit 0 when every check passes, 1 otherwise. The NOTE: line never changes the exit code.
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

# FinBot joins only internal networks (Rock, 2026-11-22, C-17), so it must reach nothing outside the compose networks:
# a public address, a public name, the host's published ports, or a model served on the host. Each of those is a check.
# The approver port shares finbot-net and its token guards it, so that one is recorded and not checked. "@gateway" is
# the container's default route, which is the host on a Linux bridge network and absent on an internal one.
# host.docker.internal is the host on Docker Desktop.
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
for port in "${approver_port:-8090}" "${viewer_port:-8095}" "${jaeger_port:-16686}"; do
    reach_targets="$reach_targets host.docker.internal $port @gateway $port"
done
# 1.1.1.1 is a public address, so no name lookup stands between FinBot and the connect. 11434 is Ollama's default port.
reach_targets="$reach_targets host.docker.internal 11434 @gateway 11434 example.com 443 1.1.1.1 443"
# shellcheck disable=SC2086
if reach=$(in_service finbot python -c "$reach_probe" $reach_targets 2>&1); then
    # A here-document, not a pipe, so the loop runs in this shell and fail sets status.
    while IFS= read -r line; do
        case $line in
            "reaches acs-gateway:"* | "cannot reach acs-gateway:"*) printf 'NOTE: finbot %s\n' "$line" ;;
            "cannot reach "*) target=${line#cannot reach }
                              pass "finbot can't reach ${target%% *}, outside the compose networks" ;;
            "reaches "*) fail "finbot reached ${line#reaches }, outside the compose networks" ;;
            *) fail "the reachability probe printed $line" ;;
        esac
    done <<REACH
$reach
REACH
else
    fail "the reachability probe did not run: $(printf '%s' "$reach" | tail -n 1)"
fi
# The positive control (review round 4, M3). FinBot failing to reach 1.1.1.1 proves isolation only when the gateway,
# on upstream-net in the same run, does reach it. Otherwise the runner itself can't see out, and the checks above
# pass for the wrong reason.
control=$(in_service acs-gateway python -c "$reach_probe" 1.1.1.1 443 2>&1 || true)
case $control in
    "reaches 1.1.1.1:443") pass "acs-gateway reaches 1.1.1.1:443, so the runner can see out" ;;
    *) fail "acs-gateway can't reach 1.1.1.1:443, so the runner can't see out and FinBot's checks above show nothing: $control" ;;
esac

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

# Module 1 as an attendee plays it (LAB-16 Task 16). Each mode change recreates the gateway and bumps the epoch over
# the acs-net admin port, and each run starts FinBot from empty data and replays s1 from its recording. lab check 1
# then judges both runs. A step passes only on exit 0, so a replay miss, a timeout or a NOT YET check fails it. The
# step's own output goes to stderr, so stdout keeps one DONE or NOT YET line per check.
transcripts_before=$(mktemp)
for step in "mode off" "run s1" "mode enforce" "run s1" "check 1"; do
    # The enforce run's transcripts are the new ones, so the list is taken just before it.
    [ "$step" != "run s1" ] || ls state/transcripts 2>/dev/null | sort > "$transcripts_before"
    # shellcheck disable=SC2086
    if output=$(./lab.sh $step 2>&1); then
        pass "./lab.sh $step"
    else
        fail "./lab.sh $step exited $?: $(printf '%s' "$output" | grep -E '^(NOT YET|DONE)' | tail -n 1)"
    fi
    printf '%s\n' "$output" | sed "s|^|lab $step: |" >&2
done

# The enforce run's session left a transcript named by its session id, one no earlier run created. acs-verify
# (LAB-11) checks its ML-DSA-65 decisions with the key document alone plus the HMAC secret for the requests.
# Interface pin on acs-verify's first output line.
new_transcripts=$(ls state/transcripts 2>/dev/null | sort | comm -13 "$transcripts_before" -)
rm -f "$transcripts_before"
if [ -n "$new_transcripts" ]; then
    pass "the enforce run left a new transcript: $(printf '%s' "$new_transcripts" | tr '\n' ' ')"
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
    fail "the enforce run left no new transcript"
fi

# The model port takes only FinBot's per-lab client token (final review R8). redis shares finbot-net and holds no
# token, so its busybox wget, with no Authorization header, must get the gateway's 401, not an answer and not an error.
no_token=$(in_service redis wget -q -O /dev/null --post-data '{}' --header 'Content-Type: application/json' \
           http://acs-gateway:8080/v1/responses 2>&1 || true)
case $no_token in
    *" 401 "*) pass "a call to the model port without the client token gets 401" ;;
    *) fail "a call to the model port without the client token didn't get 401: $no_token" ;;
esac

if curl -fsS "http://127.0.0.1:${viewer_port:-8095}/api/rows?after=0" >/dev/null 2>&1; then
    pass "the viewer answers on 127.0.0.1:${viewer_port:-8095}"
else
    fail "the viewer doesn't answer on 127.0.0.1:${viewer_port:-8095}"
fi

exit "$status"
