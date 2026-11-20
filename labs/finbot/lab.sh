#!/bin/sh
# lab.sh: the FinBot lab's only host command (issue #588, LAB-15). macOS and Linux. Windows is untested.
#
# Version 1.3.0. Owner: Rock Lambros. LAB-16 (issue #589) added the run and record verbs.
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
#   run SCENARIO [FLAGS]          start FinBot from empty data, then drive one scenario: s1, s2, s3, s4a, s4b, s5 or s6.
#                                 FLAGS: --answer approve|reject, --clean
#   record STEM SCENARIO [FLAGS]  owner only: run SCENARIO on OpenAI with capture on, into replay/recordings/STEM.jsonl.
#                                 Reads the model key from pass into a directory outside the bundle for
#                                 the take, and deletes it after. Any later command cleans up a take cut short
#   check N                       module N's check, 1 to 7, over the runs you made
#   policy N starter|solution     put module N's starter or solution policy live, 3 to 6
#   forge                         module 7: write an HMAC-signed allow into a copy of a transcript
#   verify                        module 7: verify a transcript against the Guardian's pinned fingerprint
#   downgrade                     module 7: try to talk the gateway down to HMAC
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
# FinBot's named volumes. compose.yaml fixes the project name, acs-finbot-lab, so these names are fixed too.
FINBOT_VOLUMES="acs-finbot-lab_finbot-data acs-finbot-lab_finbot-uploads acs-finbot-lab_finbot-cache acs-finbot-lab_redis-data"
PROJECT_NAME=acs-finbot-lab
MODEL_KEY=state/secrets/openai.key
# lab record writes the take's directory here first and deletes it last, so a take that no trap could close, such
# as one ended by SIGKILL or a power cut, is found and cleaned up by the next command.
TAKE_MARKER=state/capture-take
# Set only while lab record holds a capture take open. compose() then adds the OpenAI and capture overlays.
CAPTURE_OVERLAY=
CAPTURE_STARTED=
TAKE_DIR=

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
    if [ -n "$CAPTURE_OVERLAY" ]; then
        docker compose -f compose.yaml -f compose.openai.yaml -f replay/compose.capture.yaml "$@"
    elif [ "$(env_value ACS_UPSTREAM)" = openai ]; then
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

need_init() {
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
}

need_standing_model_key() {
    if [ "$(env_value ACS_UPSTREAM)" = openai ] && [ ! -f "$MODEL_KEY" ]; then
        say "NOT YET: the openai upstream needs your model key in labs/finbot/state/secrets/openai.key (mode 0600). Put it back, or run ./lab.sh upstream replay."
        exit 2
    fi
}

refuse_drive() {
    # Attendee text is never echoed back, so nothing odd in it reaches the terminal either.
    say "NOT YET: lab $1 takes $2 with a scenario of s1, s2, s3, s4a, s4b, s5 or s6, then only --answer approve, --answer reject or --clean, each once."
    exit 2
}

drive_args() {
    # Sets DRIVE_ARGS from the scenario and its flags. Every word is checked against a fixed set before Docker
    # runs, so the string splits back into exactly those words (LAB-16 review focus 7).
    verb_name=$1
    shape=$2
    shift 2
    [ "$#" -ge 1 ] || refuse_drive "$verb_name" "$shape"
    case $1 in
        s[1-6] | s[1-6][ab]) DRIVE_ARGS=$1 ;;
        *) refuse_drive "$verb_name" "$shape" ;;
    esac
    shift
    answer=
    clean=
    while [ "$#" -gt 0 ]; do
        case $1 in
            --answer)
                [ -z "$answer" ] && [ "$#" -ge 2 ] || refuse_drive "$verb_name" "$shape"
                case $2 in
                    approve | reject) answer=$2 ;;
                    *) refuse_drive "$verb_name" "$shape" ;;
                esac
                DRIVE_ARGS="$DRIVE_ARGS --answer $answer"
                shift 2 ;;
            --clean)
                [ -z "$clean" ] || refuse_drive "$verb_name" "$shape"
                clean=1
                DRIVE_ARGS="$DRIVE_ARGS --clean"
                shift ;;
            *) refuse_drive "$verb_name" "$shape" ;;
        esac
    done
}

reset_finbot() {
    # FinBot's integer vendor and invoice ids reach the model, and replay matches the exact text, so every run starts
    # FinBot from empty volumes and the ids repeat (LAB-16 open question 2). --force skips volumes a first run lacks.
    compose rm --stop --force finbot redis
    # shellcheck disable=SC2086
    docker volume rm --force $FINBOT_VOLUMES >/dev/null
    compose up -d --wait finbot
}

run_scenario() {
    drive_args run SCENARIO "$@"
    need_project_name
    need_init
    need_standing_model_key
    ensure_images
    reset_finbot
    # shellcheck disable=SC2086
    lab _drive $DRIVE_ARGS
}

set_take_parent() {
    # Sets TAKE_PARENT, the directory a take's key directory goes in: the user's temp directory, or /tmp when TMPDIR
    # is unset. It must be absolute and outside the bundle, which the lab CLI mounts whole and whose state/ the
    # Guardian and the viewer also mount (review m1).
    TAKE_PARENT=${TMPDIR:-/tmp}
    case $TAKE_PARENT in
        /*) ;;
        *) say "NOT YET: TMPDIR is a relative path, and the take's model key needs an absolute temp directory outside labs/finbot. Unset TMPDIR or set it to one, then rerun."
           exit 2 ;;
    esac
    if ! resolved=$(cd -P "$TAKE_PARENT" 2>/dev/null && pwd -P); then
        say "NOT YET: TMPDIR names $TAKE_PARENT, which isn't a directory. Unset TMPDIR or set it to one, then rerun."
        exit 2
    fi
    bundle=$(cd -P "$BUNDLE_DIR" && pwd -P)
    case $resolved/ in
        "$bundle"/*) say "NOT YET: TMPDIR is inside labs/finbot, where the lab's containers could read the take's model key. Unset TMPDIR or point it outside the bundle, then rerun."
                     exit 2 ;;
    esac
    TAKE_PARENT=$resolved
}

remove_take_dir() {
    # Only the files a take writes, then the directory itself, so nothing else in it is ever removed.
    rm -f "$1/openai.key" "$1/pass.status" && rmdir "$1"
}

recover_take() {
    # lab.sh's dispatch runs this before every verb but help, so a take that no trap could close is cleaned up by
    # whatever command comes next, reset included, before its wipe can erase the marker. $1 is "stopping" for down
    # and reset, which remove the gateway themselves. It calls only shell functions and docker, never lab.sh, so
    # none of its exits can run it again.
    if [ -L "$TAKE_MARKER" ]; then
        say "NOT YET: state/capture-take is a symlink, and lab.sh never writes one. Delete state/capture-take, then rerun."
        exit 2
    fi
    [ -f "$TAKE_MARKER" ] || return 0
    left=$(sed -n 1p "$TAKE_MARKER")
    set_take_parent
    # state/ is writable by the gateway, so the marker is trusted only when it names a take directory in this
    # user's temp directory, and only that directory's own files are removed.
    case $left in
        "$TAKE_PARENT"/acs-lab-take.*) name=${left#"$TAKE_PARENT"/} ;;
        *) name=/ ;;
    esac
    case $name in
        */* | *[!A-Za-z0-9.-]*)
            say "NOT YET: state/capture-take names a path that isn't a capture take directory in $TAKE_PARENT, so it was left alone. If that path holds openai.key, delete it, then delete state/capture-take."
            exit 2 ;;
    esac
    if [ -L "$left" ]; then
        say "NOT YET: the capture take directory $left is a symlink, so it was left alone. Delete $left and state/capture-take, then rerun."
        exit 2
    fi
    # test -O isn't POSIX, so the owner comes from ls's numeric listing.
    owner=
    # The name was checked above to hold only letters, digits, dots and dashes, so ls's output parses safely.
    # shellcheck disable=SC2012
    [ ! -d "$left" ] || owner=$(ls -ldn "$left" | { read -r _ _ uid _; printf '%s' "$uid"; })
    if [ -e "$left" ] && { [ ! -d "$left" ] || [ "$owner" != "$(id -u)" ]; }; then
        say "NOT YET: $left isn't a directory this user owns, so it was left alone. Delete $left and state/capture-take, then rerun."
        exit 2
    fi
    what="its model key was already gone"
    if [ -d "$left" ]; then
        [ ! -e "$left/openai.key" ] || what="deleted its model key"
        if ! remove_take_dir "$left"; then
            say "NOT YET: an interrupted capture take left its directory at $left, and it couldn't be deleted. Delete $left and state/capture-take, then rerun."
            exit 2
        fi
    fi
    # Say only what happened. A gateway Docker restarts later can't find its key's bind source, so it can't serve
    # the key, and the next up recreates it on replay.
    if [ "${1:-}" = stopping ]; then
        tail=", and the lab is stopping."
    elif ! ids=$(compose ps -q acs-gateway 2>/dev/null); then
        tail=". Docker isn't answering, so the gateway goes back on replay at the next ./lab.sh up."
    elif [ -z "$ids" ]; then
        tail=", and the gateway wasn't running."
    elif recreate acs-gateway; then
        tail=" and put the gateway back on replay."
    else
        say "NOT YET: an interrupted capture take was cleaned up, and the gateway couldn't be put back on replay. Run ./lab.sh down, then ./lab.sh up."
        exit 2
    fi
    rm -f "$TAKE_MARKER"
    say "Cleaned up an interrupted capture take: $what$tail"
}

end_take() {
    # The EXIT trap of lab record, so it runs however the take ends: success, a failed step, Ctrl-C, a hangup or a
    # kill. A TERM sent to this shell alone waits for the running docker command to return before the trap runs.
    # Ctrl-C and a closed terminal signal the whole process group, so they don't wait.
    status=$?
    trap - EXIT HUP INT TERM
    done_cleaning=1
    if [ -n "$TAKE_DIR" ] && [ -d "$TAKE_DIR" ] && ! remove_take_dir "$TAKE_DIR"; then
        say "NOT YET: the take's key directory $TAKE_DIR couldn't be deleted. Delete it by hand now."
        status=2
        done_cleaning=
    fi
    if [ -n "$CAPTURE_STARTED" ]; then
        CAPTURE_OVERLAY=
        unset LAB_CAPTURE_SCENARIO LAB_CAPTURE_KEY_FILE
        # Back on the upstream .env names, which record requires to be replay, so the gateway holds no key at all.
        if ! recreate acs-gateway; then
            say "NOT YET: the gateway couldn't be recreated without capture, so it may still be recording. Run ./lab.sh up, which recreates it."
            status=2
            done_cleaning=
        fi
    fi
    # The marker goes last, and stays when cleanup failed, so the next command tries again.
    [ -z "$done_cleaning" ] || rm -f "$TAKE_MARKER"
    exit "$status"
}

write_model_key() {
    # Rock 2026-11-19: the key lives in pass as openai/api-key and exists on disk only for one take. It goes from
    # pass to the file through a pipe and never sits in a shell variable or an argument, so even xtrace (sh -x, or
    # an exported SHELLOPTS=xtrace) can't print it (review I1). pass's stderr is dropped because, under an inherited
    # SHELLOPTS, pass's own trace would carry the key. Only the entry's first line is the key: entries often carry
    # notes below it.
    { set +x; } 2>/dev/null
    key_file=$TAKE_DIR/openai.key
    # Created empty, exclusive and owner only before anything reaches it. mktemp already made the directory 0700.
    (umask 077 && set -C && : > "$key_file")
    (umask 077 && { rc=0; pass show openai/api-key 2>/dev/null || rc=$?; printf '%s\n' "$rc" > "$TAKE_DIR/pass.status"; } \
        | sed -n 1p > "$key_file")
    pass_status=1
    read -r pass_status < "$TAKE_DIR/pass.status" || pass_status=1
    rm -f "$TAKE_DIR/pass.status"
    if [ "$pass_status" != 0 ]; then
        say "NOT YET: pass couldn't give openai/api-key. Run pass show openai/api-key yourself to see why, then rerun."
        exit 2
    fi
    # pass show on a folder prints a tree and exits 0, so the first line must look like a key (review M4).
    if ! grep -Eq '^sk-[A-Za-z0-9_-]+$' "$key_file"; then
        say "NOT YET: the first line of the pass entry openai/api-key doesn't look like an OpenAI key: sk- followed by letters, digits, _ and -. Check the entry, then rerun."
        exit 2
    fi
}

need_project_name() {
    # FinBot's reset removes volumes by name, and a different project name would make it remove nothing, so FinBot
    # would keep its ids and replay would miss with no error (review M1).
    if [ -n "${COMPOSE_PROJECT_NAME:-}" ] && [ "$COMPOSE_PROJECT_NAME" != "$PROJECT_NAME" ]; then
        say "NOT YET: COMPOSE_PROJECT_NAME is set to another project, so FinBot's reset would remove nothing. Unset it, then rerun."
        exit 2
    fi
}

record_take() {
    if [ "$#" -lt 2 ]; then
        say "NOT YET: lab record takes STEM SCENARIO, then only --answer approve, --answer reject or --clean."
        exit 2
    fi
    stem=$1
    shift
    # The gateway's own rule for a recording name: letters, digits, _ and -, up to 64.
    case $stem in
        '' | *[!A-Za-z0-9_-]*) say "NOT YET: a recording name takes only letters, digits, _ and -."; exit 2 ;;
    esac
    if [ "${#stem}" -gt 64 ]; then
        say "NOT YET: a recording name is at most 64 characters."
        exit 2
    fi
    drive_args record "STEM SCENARIO" "$@"
    need_project_name
    need_init
    if [ -e "replay/recordings/$stem.jsonl" ] || [ -L "replay/recordings/$stem.jsonl" ]; then
        say "NOT YET: replay/recordings/$stem.jsonl exists, and capture never writes over a recording. Delete it or pick another name."
        exit 2
    fi
    if [ "$(env_value ACS_UPSTREAM)" = openai ]; then
        # Outside a take the key file is gone, so a standing openai upstream couldn't recreate the gateway after it.
        say "NOT YET: lab record turns OpenAI on for the take only. Run ./lab.sh upstream replay first."
        exit 2
    fi
    if [ -e "$MODEL_KEY" ] || [ -L "$MODEL_KEY" ]; then
        say "NOT YET: labs/finbot/state/secrets/openai.key is a plaintext copy of a key whose home is pass. Delete it, then rerun."
        exit 2
    fi
    if ! command -v pass >/dev/null 2>&1; then
        say "NOT YET: lab record reads the model key from pass, as openai/api-key, and pass isn't installed."
        exit 2
    fi
    ensure_images
    mkdir -p replay/recordings
    # dash skips the EXIT trap on a signal it has no trap for, so each signal exits through it (review I2).
    trap end_take EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    set_take_parent
    TAKE_DIR=$(mktemp -d "$TAKE_PARENT/acs-lab-take.XXXXXX")
    # The marker comes before the key, so a take cut off at any later point is found by the next command. noclobber,
    # so a marker or link planted since the dispatch's cleanup is refused, never written through (review m2).
    if ! (set -C && printf '%s\n' "$TAKE_DIR" > "$TAKE_MARKER") 2>/dev/null; then
        say "NOT YET: state/capture-take appeared while this take started. Delete state/capture-take, then rerun."
        exit 2
    fi
    write_model_key
    CAPTURE_OVERLAY=1
    LAB_CAPTURE_SCENARIO=$stem
    LAB_CAPTURE_KEY_FILE=$TAKE_DIR/openai.key
    export LAB_CAPTURE_SCENARIO LAB_CAPTURE_KEY_FILE
    CAPTURE_STARTED=1
    recreate acs-gateway
    reset_finbot
    # shellcheck disable=SC2086
    lab _drive $DRIVE_ARGS --capture "$stem"
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
# The CLI's _ verbs are lab.sh's own, called through lab(). From the host, _drive would drive a FinBot that run never
# reset, so the replay ids wouldn't repeat. Refused before any Docker call, and the verb itself is never echoed.
case $verb in
    _*) say "NOT YET: verbs that start with _ are the lab's own. To run a scenario, use ./lab.sh run <scenario>."
        exit 2 ;;
esac
# One call for every verb, so a verb added to the table below is covered without a line of its own (review R1).
case $verb in
    help | -h | --help) ;;
    down | reset) recover_take stopping ;;
    *) recover_take ;;
esac
case $verb in
    help | -h | --help)
        usage ;;
    doctor)
        doctor ;;
    up)
        need_init
        need_standing_model_key
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
    run)
        run_scenario "$@" ;;
    record)
        record_take "$@" ;;
    *)
        ensure_images
        lab "$verb" "$@" ;;
esac
