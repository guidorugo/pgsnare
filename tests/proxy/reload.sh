#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Writes the token file that the reload checks of tests/itest.sh change
# while pgsnare runs. tests/proxy/setup.sh writes its first version; the
# test then runs this script in the setup container again for each change.
#
# Usage:
#   reload.sh initial|signal|watch|broken
#
#   initial  one token, itest-reload-base
#   signal   adds itest-reload-signal, written so that a watch of the file
#            cannot see the change: in place (same inode), with the same
#            size and the time of change it had before. Only SIGHUP makes
#            pgsnare read it.
#   watch    adds itest-reload-watch, as a new file renamed into place, which
#            the watch of the files sees. Prints the moment of the rename, in
#            seconds since the epoch.
#   broken   a file that is not valid YAML, renamed into place
#
# The values are made up for these tests and planted nowhere.

set -eu

state=/var/lib/postgresql
dir="$state/config/reload"
file="$dir/tokens.yaml"
# Outside the directories pgsnare watches, so that writing here changes
# nothing it looks at.
scratch="$state/scratch"
# Every version but the broken one has exactly this many bytes.
size=512

umask 077
mkdir -p "$dir" "$scratch"

entry() {
    printf '  - id: %s\n    values: ["%s"]\n' "$1" "$2"
}

base() {
    echo "tokens:"
    entry itest-reload-base itest-bait-reload-base-6c2e17
}

signalled() {
    base
    entry itest-reload-signal itest-bait-reload-signal-d81f4a
}

watched() {
    signalled
    entry itest-reload-watch itest-bait-reload-watch-37b09e
}

# pad FILE: fills FILE up to $size bytes with a comment.
pad() {
    have="$(wc -c < "$1")"
    if [ "$have" -gt "$((size - 2))" ]; then
        echo "reload: the token file would be longer than $size bytes" >&2
        exit 1
    fi
    {
        printf '#'
        head -c "$((size - have - 2))" /dev/zero | tr '\0' ' '
        echo
    } >> "$1"
}

new="$scratch/tokens.yaml"
case "${1:-}" in
    initial)
        base > "$new"
        pad "$new"
        mv "$new" "$file"
        ;;
    signal)
        signalled > "$new"
        pad "$new"
        if [ "$(wc -c < "$file")" -ne "$(wc -c < "$new")" ]; then
            echo "reload: the file to replace does not have $size bytes" >&2
            exit 1
        fi
        touch -r "$file" "$scratch/time"
        cat "$new" > "$file"
        touch -r "$scratch/time" "$file"
        rm -f "$new" "$scratch/time"
        ;;
    watch)
        watched > "$new"
        pad "$new"
        mv "$new" "$file"
        date +%s.%N
        ;;
    broken)
        {
            echo "tokens:"
            echo "  - id: itest-reload-broken"
            echo '    values: ["itest-bait-reload-broken-5e9a04"'
        } > "$new"
        mv "$new" "$file"
        ;;
    *)
        echo "Usage: reload.sh initial|signal|watch|broken" >&2
        exit 2
        ;;
esac
