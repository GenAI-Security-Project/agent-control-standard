#!/bin/sh
# lab.sh: the FinBot lab's only host command (issue #588, LAB-15). macOS and Linux. Windows is untested.
#
# Version 1.0.0. Owner: Rock Lambros.
#
# The host needs only Docker. This script runs the Docker lifecycle verbs itself and hands every other verb to the lab
# CLI inside a container, `docker compose run --rm lab <verb>`, so no container ever gets the Docker socket.
#
# Command table:
#   init                          lab init in the container: secrets, Guardian keys, key document, .env, state/
#   up                            pull the images (build them locally when the pull fails), then start and wait
#   down                          stop the lab, keeping state/
#   reset [--delete-model-key]    stop the lab, drop FinBot's data, then wipe state/ in the container. Your model key
#                                 stays unless you confirm at the prompt or pass --delete-model-key
#   doctor                        check Docker, Compose v2, memory, architecture, ports and images on this host
#   logs [SERVICE...]             docker compose logs
#   mode off|shadow|enforce       set ACS_LAB_MODE, recreate acs-gateway, bump the epoch
#   upstream replay|openai        set the model upstream, recreate acs-gateway, bump the epoch
#   sign hmac|mldsa               set decision signing, recreate acs-guardian and acs-gateway, bump the epoch
#   traces on|off                 start or stop Jaeger and point the gateway's spans at it
#   claims check [PATH] [FLAGS]   the claims ledger check, with PATH mounted read only at /scan. FLAGS:
#                                 --require-signed, --digest
#   anything else                 docker compose run --rm lab <args>
#
# Exit 0 means pass, 1 not yet, 2 the environment is broken. Checks print lines starting DONE or NOT YET:.
set -eu

# Resolve the caller's paths before moving to the bundle, so `claims check ./dir` means the caller's ./dir.
CALLER_DIR=$(pwd)
case $0 in */*) cd "$(dirname "$0")" ;; esac
BUNDLE_DIR=$(pwd)

LOCAL_RUNTIME_IMAGE=acs-lab-runtime:local
LOCAL_FINBOT_IMAGE=acs-lab-finbot:local
# Published ports and the .env variable that moves each one (PREMORTEM P9).
PORTS="LAB_PORT_FINBOT:8000 LAB_PORT_APPROVER:8090 LAB_PORT_VIEWER:8095 LAB_PORT_JAEGER:16686"
MIN_MEMORY_BYTES=6442450944

say() { printf '%s\n' "$1"; }

# The attendee's own ids, so files the services write under state/ stay the attendee's on Linux. Root keeps the
# image default, since the entrypoint never runs a service as uid 0.
if [ "$(id -u)" -ne 0 ]; then
    LAB_UID=$(id -u)
    LAB_GID=$(id -g)
    export LAB_UID LAB_GID
fi

need_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        say "NOT YET: Docker isn't installed. Install Docker Desktop (macOS) or Docker Engine (Linux), then rerun."
        exit 2
    fi
}

env_value() {
    # The last value .env gives a name, or nothing. .env is written by the lab CLI and read by compose.
    [ -f .env ] || return 0
    sed -n "s/^$1=//p" .env | tail -n 1
}

use_local_images() {
    LAB_RUNTIME_IMAGE=$LOCAL_RUNTIME_IMAGE
    LAB_FINBOT_IMAGE=$LOCAL_FINBOT_IMAGE
    export LAB_RUNTIME_IMAGE LAB_FINBOT_IMAGE
}

if [ -f state/image-source ] && [ "$(cat state/image-source)" = built ]; then
    use_local_images
fi

compose() {
    if [ "$(env_value ACS_UPSTREAM)" = openai ]; then
        docker compose -f compose.yaml -f compose.openai.yaml "$@"
    else
        docker compose -f compose.yaml "$@"
    fi
}

lab() {
    compose run --rm lab "$@"
}

ensure_images() {
    # Rock 2026-11-17: ghcr first, a local build when the pull fails (missing, not public, or offline). The choice is
    # recorded so every later command uses the same images, and lab doctor reports it.
    [ ! -f state/image-source ] || return 0
    mkdir -p state
    if compose --profile cli pull; then
        say pulled > state/image-source
    else
        say "The published images can't be pulled. Building them locally, which takes a few minutes."
        use_local_images
        compose --profile cli build
        say built > state/image-source
    fi
}

recreate() {
    compose up -d --wait --no-deps "$@"
}

need_value() {
    if [ "$#" -lt 2 ]; then
        say "NOT YET: lab $1 needs a value. Run ./lab.sh help for the choices."
        exit 2
    fi
}

port_state() {
    # Prints free, lab (held by this lab's own running service), in-use, or a one-line reason the probe failed.
    # The probe binds the port in a throwaway container from the pinned redis image, which compose pulls anyway,
    # so the check sees what compose itself would see.
    if compose port "$1" "$3" >/dev/null 2>&1; then
        say lab
        return 0
    fi
    if probe=$(docker run --rm -p "127.0.0.1:$2:9" --entrypoint true "$PROBE_IMAGE" 2>&1); then
        say free
    elif printf '%s' "$probe" | grep -qi 'allocated\|in use'; then
        say in-use
    else
        printf '%s\n' "$probe" | tail -n 1
    fi
}

doctor() {
    status=0
    if ! docker info >/dev/null 2>&1; then
        say "NOT YET: Docker isn't running. Start Docker Desktop or the Docker service, then rerun."
        exit 2
    fi
    say "DONE: Docker is installed and running"
    version=$(docker compose version --short 2>/dev/null || true)
    case $version in
        v2.* | 2.* | v[3-9].* | [3-9].*) say "DONE: Docker Compose $version" ;;
        *) say "NOT YET: Docker Compose v2 is missing. Install the compose plugin."; status=2 ;;
    esac
    memory=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)
    case $memory in '' | *[!0-9]*) memory=0 ;; esac
    if [ "$memory" -ge "$MIN_MEMORY_BYTES" ]; then
        say "DONE: Docker has $((memory / 1073741824)) GiB of memory"
    else
        say "NOT YET: Docker has $((memory / 1073741824)) GiB of memory. Give it at least 6 GiB in Docker Desktop's resources."
        [ "$status" -ne 0 ] || status=1
    fi
    arch=$(docker info --format '{{.Architecture}}' 2>/dev/null || true)
    case $arch in
        x86_64 | aarch64 | amd64 | arm64) say "DONE: architecture $arch" ;;
        *) say "NOT YET: architecture $arch. The lab images are built for x86_64 and aarch64 only."
           [ "$status" -ne 0 ] || status=1 ;;
    esac
    PROBE_IMAGE=$(compose config --images 2>/dev/null | grep '^redis' | head -n 1 || true)
    for entry in $PORTS; do
        name=${entry%%:*}
        default=${entry#*:}
        port=$(env_value "$name")
        port=${port:-$default}
        case $name in
            LAB_PORT_FINBOT) service=finbot ;;
            LAB_PORT_APPROVER) service=acs-gateway ;;
            LAB_PORT_VIEWER) service=acs-viewer ;;
            *) service=jaeger ;;
        esac
        state=$(port_state "$service" "$port" "$default")
        case $state in
            free) say "DONE: port $port is free" ;;
            lab) say "DONE: port $port is held by the running lab" ;;
            in-use) say "NOT YET: port $port is in use. Set $name in labs/finbot/.env"
                    [ "$status" -ne 0 ] || status=1 ;;
            *) say "NOT YET: port $port couldn't be checked: $state"
               [ "$status" -ne 0 ] || status=1 ;;
        esac
    done
    for image in $(compose --profile traces --profile cli config --images 2>/dev/null | sort -u); do
        if docker image inspect "$image" >/dev/null 2>&1; then
            say "DONE: image $image is here"
        elif docker manifest inspect "$image" >/dev/null 2>&1; then
            say "DONE: image $image can be pulled"
        else
            case $image in
                *acs-lab-*) say "DONE: image $image will be built locally by ./lab.sh up" ;;
                *) say "NOT YET: image $image can't be found or pulled. Check the network, then rerun."
                   [ "$status" -ne 0 ] || status=1 ;;
            esac
        fi
    done
    if [ -f state/image-source ]; then
        say "DONE: images came from $(cat state/image-source) (pulled from ghcr, or built locally)"
    else
        say "DONE: images not fetched yet. ./lab.sh up pulls them, or builds them when the pull fails"
    fi
    exit "$status"
}

claims() {
    # check [PATH] [--require-signed] [--digest], in any order. PATH is mounted read only at /scan. Every flag goes
    # through to the check, and anything the wrapper can't pass through is refused, never dropped: a lost
    # --require-signed would turn the signing gate into an unsigned check that still prints DONE.
    if [ "${1:-}" != check ]; then
        lab claims "$@"
        return
    fi
    shift
    path=
    flags=
    for arg in "$@"; do
        case $arg in
            --require-signed | --digest) flags="$flags $arg" ;;
            -*) say "NOT YET: lab claims check takes PATH, --require-signed and --digest, got $arg."; exit 2 ;;
            *) [ -z "$path" ] || { say "NOT YET: lab claims check takes one PATH, got $path and $arg."; exit 2; }
               path=$arg ;;
        esac
    done
    if [ -z "$path" ]; then
        # shellcheck disable=SC2086
        lab claims check $flags
        return
    fi
    target=$path
    case $target in /*) ;; *) target=$CALLER_DIR/$target ;; esac
    if [ ! -e "$target" ]; then
        say "NOT YET: $path doesn't exist."
        exit 2
    fi
    if [ -d "$target" ]; then
        target=$(cd "$target" && pwd)
    else
        target=$(cd "$(dirname "$target")" && pwd)/$(basename "$target")
    fi
    case $target in
        # docker's -v splits on a colon, so the mount would name another path.
        *:*) say "NOT YET: $path has a colon in it, which a Docker mount can't take. Move or rename it."; exit 2 ;;
    esac
    # shellcheck disable=SC2086
    compose run --rm -v "$target:/scan:ro" lab claims check /scan $flags
}

reset_lab() {
    # Every question comes before anything stops, so Ctrl-C at the prompt leaves the lab as it was.
    wipe_flag=
    case $# in
        0) ;;
        1) [ "$1" = --delete-model-key ] || { say "NOT YET: lab reset takes only --delete-model-key, got $1."; exit 2; }
           wipe_flag=--delete-model-key ;;
        *) say "NOT YET: lab reset takes only --delete-model-key."; exit 2 ;;
    esac
    if [ -z "$wipe_flag" ] && [ -f state/secrets/openai.key ]; then
        say "Your model key is in labs/finbot/state/secrets/openai.key. lab init can't make it again."
        if [ -t 0 ]; then
            printf 'Delete it with the rest of state/? [y/N] '
            answer=
            read -r answer || answer=
            case $answer in
                y | Y | yes | YES | Yes) wipe_flag=--delete-model-key ;;
            esac
        else
            # No one to ask, so the key stays. Deleting it takes the explicit flag.
            say "No terminal to ask on, so the key stays. Run ./lab.sh reset --delete-model-key to delete it too."
        fi
    fi
    if [ -n "$wipe_flag" ] && [ "$(env_value ACS_UPSTREAM)" = openai ]; then
        # .env survives the wipe, so the openai upstream would outlive its key and the next up would fail on it.
        lab _set upstream replay
    fi
    compose --profile traces --profile cli down --volumes
    if [ -n "$wipe_flag" ]; then
        lab _wipe "$wipe_flag"
    else
        lab _wipe
    fi
}

usage() {
    sed -n '/^# Command table:/,/^# Exit 0/p' "$BUNDLE_DIR/lab.sh" | sed 's/^# \{0,1\}//'
}

need_docker

verb=${1:-help}
[ "$#" -eq 0 ] || shift
case $verb in
    help | -h | --help)
        usage ;;
    doctor)
        doctor ;;
    up)
        if [ ! -f state/secrets/hmac.key ]; then
            say "NOT YET: run ./lab.sh init first. It creates the lab's secrets and keys."
            exit 1
        fi
        if [ -z "$(env_value LAB_CLIENT_TOKEN)" ] || [ ! -f state/secrets/client.token ]; then
            # compose defaults the variable to empty, so a hand-edited or copied .env would start FinBot with no key
            # and every model call would get a 401. init --force writes both again and leaves openai.key alone.
            say "NOT YET: FinBot's client token is missing from labs/finbot/.env or state/secrets/client.token. Run ./lab.sh init --force to write it again. That replaces the lab's keys and keeps your model key."
            exit 1
        fi
        if [ "$(env_value ACS_UPSTREAM)" = openai ] && [ ! -f state/secrets/openai.key ]; then
            say "NOT YET: the openai upstream needs your model key in labs/finbot/state/secrets/openai.key (mode 0600). Put it back, or run ./lab.sh upstream replay."
            exit 2
        fi
        if [ -f state/image-source ] && [ "$(cat state/image-source)" = built ]; then
            # A local build goes stale when the bundle changes, so up rebuilds it. The layer cache keeps it quick.
            compose --profile cli build
        else
            ensure_images
        fi
        compose up -d --wait ;;
    down)
        compose --profile traces --profile cli down ;;
    reset)
        reset_lab "$@" ;;
    logs)
        compose logs "$@" ;;
    mode)
        need_value mode "$@"
        ensure_images
        lab _set mode "$1"
        recreate acs-gateway
        lab _epoch ;;
    upstream)
        need_value upstream "$@"
        if [ "$1" = openai ] && [ ! -f state/secrets/openai.key ]; then
            say "NOT YET: lab upstream openai needs your model key in labs/finbot/state/secrets/openai.key (mode 0600)."
            exit 2
        fi
        ensure_images
        lab _set upstream "$1"
        recreate acs-gateway
        lab _epoch ;;
    sign)
        need_value sign "$@"
        ensure_images
        lab _set sign "$1"
        recreate acs-guardian acs-gateway
        lab _epoch ;;
    traces)
        need_value traces "$@"
        ensure_images
        lab _set traces "$1"
        if [ "$1" = on ]; then
            recreate jaeger acs-gateway
        else
            compose --profile traces rm --stop --force jaeger
            recreate acs-gateway
        fi ;;
    claims)
        ensure_images
        claims "$@" ;;
    *)
        ensure_images
        lab "$verb" "$@" ;;
esac
