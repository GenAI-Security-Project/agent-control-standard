#!/bin/sh
# lab-entrypoint: copy each named secret into place, owned by the service user, then drop root and run the command.
#
# Version 1.0.0. Owner: Rock Lambros. Issue #588 (LAB-15).
#
# Compose mounts a secret file at /run/secrets/<name> with the host's owner and mode, which on Docker Desktop and on a
# Linux host with another uid never match the service user. acs.client and the gateway refuse a key file that isn't
# 0600 and owned by their own uid, so the copy is what lets them start. Settings:
#
#   LAB_SECRETS     space-separated name:file pairs. /run/secrets/<name> becomes /run/acs/<file>, mode 0600.
#   LAB_STATE_DIRS  space-separated absolute paths (tmpfs mounts) handed to the service user, mode 0700.
#   LAB_UID, LAB_GID  the service user, default 10001. lab.sh sets them to the attendee's own ids.
#
# Exit 2 means the environment is broken (the lab CLI contract): a missing secret, a bad name, or a bad uid.
set -eu

fail() {
    printf 'lab-entrypoint: %s\n' "$1" >&2
    exit 2
}

uid=${LAB_UID-10001}
gid=${LAB_GID-10001}
# Numbers only, and never root, so setpriv can't be pointed at an account by name or keep the process privileged.
case $uid in '' | *[!0-9]*) fail "LAB_UID must be a number, got '$uid'" ;; esac
case $gid in '' | *[!0-9]*) fail "LAB_GID must be a number, got '$gid'" ;; esac
[ "$uid" -ne 0 ] || fail "LAB_UID must not be 0"
[ "$gid" -ne 0 ] || fail "LAB_GID must not be 0"
[ "$#" -gt 0 ] || fail "no command to run"

if [ "$(id -u)" -ne 0 ]; then
    # The viewer and the lab CLI start as the attendee and need no copy. Anything that names a secret needs root.
    [ -z "${LAB_SECRETS:-}" ] || fail "copying LAB_SECRETS needs the container to start as root"
    [ -z "${LAB_STATE_DIRS:-}" ] || fail "owning LAB_STATE_DIRS needs the container to start as root"
    exec "$@"
fi

umask 077
mkdir -p /run/acs
chown "$uid:$gid" /run/acs
chmod 0700 /run/acs

for pair in ${LAB_SECRETS:-}; do
    name=${pair%%:*}
    file=${pair#*:}
    # Plain names only, so a setting can't read or write outside /run/secrets and /run/acs.
    case $name in '' | *[!A-Za-z0-9._-]* | .*) fail "bad secret name '$name'" ;; esac
    case $file in '' | *[!A-Za-z0-9._-]* | .*) fail "bad secret file name '$file'" ;; esac
    [ "$pair" != "$name" ] || fail "LAB_SECRETS entry '$pair' needs the form name:file"
    src=/run/secrets/$name
    [ -f "$src" ] && [ -r "$src" ] || fail "missing secret $name"
    dest=/run/acs/$file
    rm -f "$dest"
    cp "$src" "$dest"
    chown "$uid:$gid" "$dest"
    chmod 0600 "$dest"
done

for dir in ${LAB_STATE_DIRS:-}; do
    case $dir in /run/* | /tmp/*) ;; *) fail "LAB_STATE_DIRS entry '$dir' must sit under /run or /tmp" ;; esac
    case $dir in *..*) fail "LAB_STATE_DIRS entry '$dir' must not hold '..'" ;; esac
    mkdir -p "$dir"
    chown "$uid:$gid" "$dir"
    chmod 0700 "$dir"
done

exec setpriv --reuid "$uid" --regid "$gid" --clear-groups -- "$@"
