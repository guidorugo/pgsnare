#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests the pgsnare image, as a registry hands it out.
#
#   deploy/tests/image/test.sh IMAGE [BINARY]
#
# IMAGE names the image by digest. BINARY is the file that the `binary`
# stage of deploy/Dockerfile wrote for the same build; when it is given,
# the binary inside the image must be that very file.
#
# What is checked:
#
#   1. The image names a numeric user that is not 0, its entry point is
#      pgsnare, and its health check is `pgsnare healthcheck` in exec form.
#   2. The files of the image: pgsnare is owned by root and cannot be
#      written, no file has the setuid or setgid bit, nothing but the home
#      directory of the user belongs to anyone but root, nothing outside a
#      sticky directory can be written by everybody, no package manager
#      cache is left, and the CA certificates are there. (The base has a
#      shell and a package manager: the owner chose it. The process cannot
#      use them to install anything: it is not root, holds no capability and
#      has a read-only root filesystem.)
#   3. The binary asks for no interpreter and no shared library.
#   4. With a read-only root filesystem, without capabilities and with
#      `no-new-privileges`, the container finds a PostgreSQL container by
#      name, becomes `healthy` through the health check of the image, lets
#      a client log in, reports a seeded token as `token_hit`, and ends with
#      status 0 on SIGTERM.
#
# Checks 1 and 3, and the setuid check of 2, are also run against the
# PostgreSQL image, which must fail them. The other checks of 2 are run
# against a list of files made up in the test, which each of them must
# refuse: a check that cannot fail proves nothing.
#
# The test starts containers of the Compose project in compose.yaml and
# removes them, with their volume and network, when it ends.

set -euo pipefail

image="${1:?usage: test.sh IMAGE [BINARY]}"
binary="${2:-}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker="${DOCKER:-docker}"
project="${PGSNARE_IMAGE_TEST_PROJECT:-pgsnare-image-test}"

failed=0
fail() {
    echo "image-test: FAILED: $*" >&2
    failed=1
}
die() {
    echo "image-test: $*" >&2
    exit 1
}

[[ "$image" =~ ^[a-z0-9][a-z0-9.:/_-]*@sha256:[0-9a-f]{64}$ ]] \
    || die "the image must be named by digest: NAME@sha256:..."
if [[ -n "$binary" && ! -f "$binary" ]]; then
    die "$binary: no such file"
fi

# The image that every static check must reject.
reference="$(sed -nE 's/^  image: (postgres:[^[:space:]]+@sha256:[0-9a-f]{64})$/\1/p' "$here/compose.yaml" | head -n 1)"
[[ -n "$reference" ]] || die "could not read the PostgreSQL image from compose.yaml"

export PGSNARE_IMAGE="$image"
PGSNARE_IMAGE_TEST_PASSWORD="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
PGSNARE_IMAGE_TEST_TOKEN="image-test-bait-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export PGSNARE_IMAGE_TEST_PASSWORD PGSNARE_IMAGE_TEST_TOKEN
token="$PGSNARE_IMAGE_TEST_TOKEN"

compose() {
    "$docker" compose --file "$here/compose.yaml" --project-name "$project" "$@"
}

work="$(mktemp -d)"
created=()
cleanup() {
    compose --profile setup --profile client down --volumes --remove-orphans --timeout 5 >/dev/null 2>&1 || true
    if [[ "${#created[@]}" -gt 0 ]]; then
        "$docker" rm --force "${created[@]}" >/dev/null 2>&1 || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

case "$(uname -m)" in
    x86_64) arch=amd64 machine='X86-64' ;;
    aarch64 | arm64) arch=arm64 machine='AArch64' ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac

echo "image-test: pulling $image"
"$docker" pull --quiet "$image" >/dev/null
"$docker" pull --quiet "$reference" >/dev/null

# --- The checks that need no running container --------------------------------
#
# Each prints what is wrong and returns 1, or prints nothing and returns 0.

# user_is_numeric IMAGE
user_is_numeric() {
    local user
    user="$("$docker" image inspect --format '{{.Config.User}}' "$1")"
    if ! [[ "$user" =~ ^[1-9][0-9]*(:[0-9]+)?$ ]]; then
        echo "the user of the image is \"$user\": it must be a number other than 0"
        return 1
    fi
}

# starts_pgsnare IMAGE
starts_pgsnare() {
    local entrypoint check
    entrypoint="$("$docker" image inspect --format '{{json .Config.Entrypoint}}' "$1")"
    check="$("$docker" image inspect --format '{{json .Config.Healthcheck}}' "$1")"
    if [[ "$entrypoint" != '["/usr/local/bin/pgsnare"]' ]]; then
        echo "the entry point is $entrypoint"
        return 1
    fi
    # Exec form is `CMD`. `CMD-SHELL` would need a shell.
    if ! grep -qF '"Test":["CMD","/usr/local/bin/pgsnare","healthcheck"]' <<<"$check"; then
        echo "the health check is $check"
        return 1
    fi
}

# listing IMAGE NAME: exports the files of the image to $work/NAME.tar and
# writes one line for each to $work/NAME.list: type and mode, owner and
# group, size, name.
# The container it creates for that is never started; its id is left in
# `listed`.
listed=""
listing() {
    listed="$("$docker" create "$1")"
    created+=("$listed")
    "$docker" export --output "$work/$2.tar" "$listed"
    tar --list --verbose --numeric-owner --file "$work/$2.tar" \
        | sed -E 's/^([^ ]+) +([^ ]+) +([^ ]+) +[^ ]+ +[^ ]+ (.*)$/\1 \2 \3 \4/; s/ (->|link to) .*$//' \
        > "$work/$2.list"
}

# The lines of a list are "MODE OWNER SIZE NAME". MODE is the ten characters
# of `ls -l`: the type, then three for the owner, the group and everybody
# else; the fourth, the seventh and the tenth hold x, s or S, x, s or S, and
# x, t or T.
list_names() {
    sed -E 's/^[^ ]+ [^ ]+ [^ ]+ //'
}

# no_setuid NAME: no file has the setuid or the setgid bit.
no_setuid() {
    local found
    found="$(awk 'substr($1, 4, 1) ~ /[sS]/ || substr($1, 7, 1) ~ /[sS]/' "$work/$1.list" | list_names | sed -n '1,5p')"
    if [[ -n "$found" ]]; then
        echo "the image holds files with the setuid or setgid bit:"
        echo "$found" | sed 's/^/    /'
        return 1
    fi
}

# only_root_owns NAME: nothing belongs to anybody but root, except the home
# directory of the user.
only_root_owns() {
    local found
    found="$(awk '{ split($2, owner, "/"); if (owner[1] != "0") print }' "$work/$1.list" | list_names \
        | { grep -Ev '^home/nonroot/?$' || true; } | sed -n '1,5p')"
    if [[ -n "$found" ]]; then
        echo "the image holds files that belong to somebody but root:"
        echo "$found" | sed 's/^/    /'
        return 1
    fi
}

# not_writable_by_all NAME: no file or directory can be written by everybody,
# except a directory with the sticky bit, such as /tmp.
not_writable_by_all() {
    local found
    found="$(awk '$1 ~ /^[-d]/ && substr($1, 9, 1) == "w" && substr($1, 10, 1) !~ /[tT]/' "$work/$1.list" | list_names | sed -n '1,5p')"
    if [[ -n "$found" ]]; then
        echo "the image holds files that everybody can write:"
        echo "$found" | sed 's/^/    /'
        return 1
    fi
}

# no_package_cache NAME: no package index or downloaded package is left.
no_package_cache() {
    local found
    found="$(awk '$1 !~ /^d/' "$work/$1.list" | list_names \
        | { grep -E '^(var/cache/apk|var/cache/apt|var/lib/apt/lists)/' || true; } | sed -n '1,5p')"
    if [[ -n "$found" ]]; then
        echo "the image keeps a package manager cache:"
        echo "$found" | sed 's/^/    /'
        return 1
    fi
}

# pgsnare_is_sealed NAME: pgsnare belongs to root and nobody can write it.
pgsnare_is_sealed() {
    if ! grep -qE '^-r-xr-xr-x 0/0 [1-9][0-9]* usr/local/bin/pgsnare$' "$work/$1.list"; then
        echo "/usr/local/bin/pgsnare is not a file of root, with mode 0555:"
        grep -E ' usr/local/bin/pgsnare$' "$work/$1.list" | sed 's/^/    /' || true
        return 1
    fi
}

# has_certificates NAME: the file that holds the CA certificates exists.
has_certificates() {
    if ! grep -qE ' etc/ssl/certs/ca-certificates\.crt$' "$work/$1.list"; then
        echo "the image has no /etc/ssl/certs/ca-certificates.crt"
        return 1
    fi
}

# is_static FILE
is_static() {
    local header
    if ! header="$(readelf --file-header --wide "$1" 2>/dev/null)"; then
        echo "the file is not an ELF binary"
        return 1
    fi
    if ! grep -qE "Machine:.*$machine" <<<"$header"; then
        echo "the binary is not built for $arch"
        return 1
    fi
    if readelf --program-headers --wide "$1" | grep -q 'INTERP'; then
        echo "the binary asks for an interpreter"
        return 1
    fi
    if readelf --dynamic --wide "$1" | grep -q 'NEEDED'; then
        echo "the binary asks for a shared library"
        return 1
    fi
}

# must_pass WHAT COMMAND...: the image under test.
must_pass() {
    local what="$1" reason
    shift
    if reason="$("$@")"; then
        echo "image-test: ok: $what"
    else
        fail "$what"
        echo "$reason" | sed 's/^/    /' >&2
    fi
}

# must_reject WHAT COMMAND...: the same check against the reference.
must_reject() {
    local what="$1"
    shift
    if "$@" >/dev/null; then
        fail "the check \"$what\" accepted the PostgreSQL image, so it proves nothing"
    else
        echo "image-test: ok: the check \"$what\" rejects the PostgreSQL image"
    fi
}

echo "image-test: the image must name a numeric user, pgsnare and its health check"
[[ "$("$docker" image inspect --format '{{.Architecture}}' "$image")" == "$arch" ]] \
    || fail "the image is not built for $arch, the architecture of this machine"
must_pass "a numeric user that is not 0" user_is_numeric "$image"
must_reject "a numeric user that is not 0" user_is_numeric "$reference"
must_pass "entry point and health check are pgsnare" starts_pgsnare "$image"
must_reject "entry point and health check are pgsnare" starts_pgsnare "$reference"

echo "image-test: the files of the image"
listing "$image" image
container="$listed"
listing "$reference" reference
reference_container="$listed"
grep -qE '^-[^ ]+ [^ ]+ [1-9][0-9]* usr/local/bin/pgsnare$' "$work/image.list" \
    || fail "the image does not hold /usr/local/bin/pgsnare"
must_pass "pgsnare is a file of root that nobody can write" pgsnare_is_sealed image
must_pass "no file has the setuid or the setgid bit" no_setuid image
must_reject "no file has the setuid or the setgid bit" no_setuid reference
must_pass "only root owns files, apart from the home directory" only_root_owns image
must_pass "nothing but a sticky directory can be written by everybody" not_writable_by_all image
must_pass "no package manager cache is left" no_package_cache image
must_pass "the CA certificates are there" has_certificates image

# The checks that the PostgreSQL image does not fail by itself are shown to
# fail on a list made up for the purpose.
cat >"$work/made-up.list" <<'LIST'
-rwsr-xr-x 0/0 100 usr/bin/su
-rwxr-xr-x 0/0 100 usr/local/bin/pgsnare
-rwxr-xr-x 1000/1000 100 usr/local/bin/other
-rw-rw-rw- 0/0 100 etc/anything
drwxrwxrwx 0/0 0 var/anything/
-rw-r--r-- 0/0 100 var/cache/apk/APKINDEX.tar.gz
-rw-r--r-- 0/0 100 var/lib/apt/lists/index
LIST
must_reject "pgsnare is a file of root that nobody can write" pgsnare_is_sealed made-up
must_reject "no file has the setuid or the setgid bit" no_setuid made-up
must_reject "only root owns files, apart from the home directory" only_root_owns made-up
must_reject "nothing but a sticky directory can be written by everybody" not_writable_by_all made-up
must_reject "no package manager cache is left" no_package_cache made-up
must_reject "the CA certificates are there" has_certificates made-up
# A sticky directory and the home directory are allowed.
cat >"$work/allowed.list" <<'LIST'
drwxrwxrwt 0/0 0 tmp/
drwx------ 65532/65532 0 home/nonroot/
LIST
must_pass "a sticky directory and the home directory are allowed" bash -c \
    "$(declare -f list_names not_writable_by_all only_root_owns); work='$work'; not_writable_by_all allowed && only_root_owns allowed"

echo "image-test: the binary must need no interpreter and no library"
"$docker" cp --follow-link "$container:/usr/local/bin/pgsnare" "$work/pgsnare" >/dev/null
"$docker" cp --follow-link "$reference_container:/usr/bin/bash" "$work/reference" >/dev/null
must_pass "a static binary for $arch" is_static "$work/pgsnare"
must_reject "a static binary for $arch" is_static "$work/reference"
if [[ -n "$binary" ]]; then
    inside="$(sha256sum "$work/pgsnare" | cut -d' ' -f1)"
    outside="$(sha256sum "$binary" | cut -d' ' -f1)"
    if [[ "$inside" == "$outside" ]]; then
        echo "image-test: ok: the binary of the image is the exported binary, sha256 $inside"
    else
        fail "the binary of the image ($inside) is not the exported binary ($outside)"
    fi
fi

# --- The image at work ---------------------------------------------------------

echo "image-test: starting PostgreSQL and the image, confined"
uid="$("$docker" image inspect --format '{{.Config.User}}' "$image")"
uid="${uid%%:*}"
[[ "$uid" == 65532 ]] || fail "the image runs as user $uid, and compose.yaml prepares its files for user 65532"

compose --profile setup run --rm --no-deps -T claim
compose --profile setup run --rm --no-deps -T setup
compose up --detach --wait --quiet-pull postgres
compose up --detach --no-deps pgsnare
proxy="$(compose ps --quiet --all pgsnare)"
[[ -n "$proxy" ]] || die "the pgsnare container was not created"

show_proxy() {
    echo "image-test: the last lines of pgsnare, and of its health check:" >&2
    "$docker" logs --tail 30 "$proxy" 2>&1 | sed 's/^/    /' >&2 || true
    "$docker" inspect --format '{{json .State}}' "$proxy" 2>&1 | cut -c 1-2000 | sed 's/^/    /' >&2 || true
}

# Healthy through the health check that the image carries: compose.yaml
# gives the service none.
tries=0
while :; do
    health="$("$docker" inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} {{.State.Running}}' "$proxy")"
    case "$health" in
        "healthy true") echo "image-test: ok: healthy through the health check of the image"; break ;;
        none*) fail "the container has no health check: the image lost it on the way"; break ;;
        *false) fail "pgsnare stopped instead of becoming healthy"; break ;;
    esac
    tries=$((tries + 1))
    if [[ "$tries" -ge 90 ]]; then
        fail "pgsnare is not healthy after 90 seconds: $health"
        break
    fi
    sleep 1
done
if [[ "$failed" -ne 0 ]]; then
    show_proxy
    exit 1
fi

# What the container was given, and what the kernel says about process 1.
given="$("$docker" inspect --format '{{.HostConfig.ReadonlyRootfs}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}} {{json .Config.Healthcheck.Test}}' "$proxy")"
[[ "$given" == 'true ["ALL"] ["no-new-privileges:true"] ["CMD","/usr/local/bin/pgsnare","healthcheck"]' ]] \
    || fail "the container is not confined as the test means it to be: $given"
pid="$("$docker" inspect --format '{{.State.Pid}}' "$proxy")"
if [[ "$pid" =~ ^[1-9][0-9]*$ ]] && process="$(cat "/proc/$pid/status" 2>/dev/null)"; then
    grep -qE "^Name:[[:space:]]+pgsnare\$" <<<"$process" \
        || fail "process 1 of the container is not pgsnare"
    grep -qE "^Uid:([[:space:]]+$uid){4}\$" <<<"$process" \
        || fail "pgsnare does not run as user $uid"
    for set in CapInh CapPrm CapEff CapBnd CapAmb; do
        grep -qE "^$set:[[:space:]]+0+\$" <<<"$process" \
            || fail "pgsnare holds capabilities: $(grep -E "^$set:" <<<"$process" | tr '\t' ' ')"
    done
    grep -qE "^NoNewPrivs:[[:space:]]+1\$" <<<"$process" \
        || fail "pgsnare may gain privileges: no_new_privs is not set"
    echo "image-test: the kernel shows pgsnare as user $uid, without capabilities, with no_new_privs"
else
    fail "could not read the state of process 1 of the container from /proc"
fi

# psql_to HOST ARGUMENTS...: the database itself is `postgres`, and the
# proxy is `pgsnare`.
psql_to() {
    local host="$1"
    shift
    compose --profile client run --rm --no-deps -T client \
        --no-psqlrc --no-password --quiet --tuples-only --no-align \
        --dbname "host=$host port=5432 user=postgres dbname=postgres sslmode=disable" "$@"
}
logged() {
    "$docker" logs "$proxy" 2>&1 | grep -F -- "$1" | grep -qF -- "${2:-}"
}

echo "image-test: a client must log in through the image, and a seeded token must be reported"
psql_to postgres --command \
    "CREATE TABLE image_test_bait (v text); INSERT INTO image_test_bait VALUES ('$token')" >/dev/null

# The proxy found the database by its name, and the login went through.
answer="$(psql_to pgsnare --command 'SELECT 41 + 1' 2>&1)" || true
if [[ "$answer" == 42 ]]; then
    echo "image-test: ok: a client logged in through pgsnare"
else
    fail "a client could not log in through pgsnare:"
    echo "$answer" | sed 's/^/    /' >&2
fi

# Nothing was read yet, so nothing may be reported yet.
if logged '"kind":"token_hit"'; then
    fail "a token_hit was reported before the token was read, so the next check proves nothing"
fi
if ! psql_to pgsnare --command "SELECT v FROM image_test_bait" 2>&1 | grep -qxF "$token"; then
    fail "the session that read the token did not get its row"
fi
tries=0
until logged '"kind":"token_hit"' '"token_id":"image-test-seeded"'; do
    tries=$((tries + 1))
    if [[ "$tries" -ge 50 ]]; then
        fail "no token_hit event for the seeded token"
        break
    fi
    sleep 0.2
done
[[ "$tries" -ge 50 ]] || echo "image-test: ok: the seeded token was reported as token_hit"
if "$docker" logs "$proxy" 2>&1 | grep -qF -- "$token"; then
    fail "the output of pgsnare holds the value of the token"
fi

echo "image-test: pgsnare must end with status 0 on SIGTERM"
"$docker" kill --signal TERM "$proxy" >/dev/null
status="$(timeout 60 "$docker" wait "$proxy" 2>/dev/null)" || status="none after 60 seconds"
if [[ "$status" == 0 ]]; then
    echo "image-test: ok: exit status 0 on SIGTERM"
else
    fail "exit status on SIGTERM: $status"
fi
[[ "$("$docker" inspect --format '{{.State.OOMKilled}}' "$proxy")" == false ]] \
    || fail "pgsnare did not stay within its memory limit"

if [[ "$failed" -ne 0 ]]; then
    show_proxy
    echo "image-test: FAILED" >&2
    exit 1
fi
echo "image-test: passed"
