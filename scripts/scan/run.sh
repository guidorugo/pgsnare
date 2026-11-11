#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Scans the repository for secrets and for private network addresses, and
# fails if it finds either. Run it with `make scan`.
#
# Two things are scanned:
#
#   1. The working tree: every file that git tracks or would add. Ignored
#      files, such as build output, are left out. Symbolic links are scanned
#      as the path they point to, and file names are scanned too.
#   2. The history: the changes and the message of every commit reachable
#      from HEAD.
#
# Findings are printed without the matched text, so a leak is not repeated
# in a build log.
#
# Environment:
#   SCAN_REQUIRE_HISTORY=1   fail if the complete history cannot be scanned.
#                            CI sets this.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
secrets_config="$root/.gitleaks.toml"
addresses_config="$root/scripts/scan/private-addresses.toml"
require_history="${SCAN_REQUIRE_HISTORY:-0}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tree="$work/tree"
no_ignore_file="$work/no-ignore-file"
mkdir -p "$tree" "$no_ignore_file"

cd "$root"

have_git=false
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    have_git=true
fi

# Lists the files to scan, NUL-separated.
list_files() {
    if "$have_git"; then
        git ls-files -z --cached --others --exclude-standard
    else
        # Without git there is no ignore list, so skip the known build and
        # fuzzing output directories instead.
        find . \
            \( -name .git -o -name target \
               -o -path './crates/*/fuzz/artifacts' \
               -o -path './crates/*/fuzz/corpus' \
               -o -path './crates/*/fuzz/coverage' \) -prune \
            -o \( -type f -o -type l \) -print0
    fi
}

# Copy the files into a scratch tree, so the scanner sees exactly this set.
count=0
names="$work/names"
: > "$names"
while IFS= read -r -d '' file; do
    file="${file#./}"
    if [[ -L "$file" ]]; then
        mkdir -p "$tree/$(dirname "$file")"
        readlink "$file" > "$tree/$file"
    elif [[ -f "$file" ]]; then
        mkdir -p "$tree/$(dirname "$file")"
        cp "$file" "$tree/$file"
    else
        # Tracked but deleted in the working tree.
        continue
    fi
    printf '%s\n' "$file" >> "$names"
    count=$((count + 1))
done < <(list_files)

if [[ "$count" -eq 0 ]]; then
    echo "scan: found no files to scan in $root" >&2
    exit 1
fi

# File names and commit messages are scanned as two extra files.
cp "$names" "$tree/FILE-NAMES-OF-THIS-REPOSITORY"
if "$have_git" && git rev-parse --verify --quiet HEAD >/dev/null; then
    git log --format='%H%n%B' HEAD > "$tree/COMMIT-MESSAGES-OF-THIS-REPOSITORY"
fi

failed=0

# run_gitleaks <what> <gitleaks arguments...>
run_gitleaks() {
    local what="$1"
    shift
    echo "scan: $what"
    if ! gitleaks "$@" --no-banner --no-color --redact --verbose --log-level warn; then
        echo "scan: FAILED: $what" >&2
        failed=1
    fi
}

echo "scan: working tree, $count files"
cd "$tree"
run_gitleaks "secrets in the working tree" \
    dir . --config "$secrets_config"
run_gitleaks "private network addresses in the working tree" \
    dir . --config "$addresses_config" \
    --ignore-gitleaks-allow --gitleaks-ignore-path "$no_ignore_file"
cd "$root"

history_scanned=false
if "$have_git" && git rev-parse --verify --quiet HEAD >/dev/null; then
    if [[ "$(git rev-parse --is-shallow-repository)" == "true" ]]; then
        echo "scan: this is a shallow clone, so its history is incomplete" >&2
    else
        commits="$(git rev-list --count HEAD)"
        echo "scan: history, $commits commits reachable from HEAD"
        run_gitleaks "secrets in the history" \
            git "$root" --config "$secrets_config" --log-opts="--full-history HEAD"
        run_gitleaks "private network addresses in the history" \
            git "$root" --config "$addresses_config" --log-opts="--full-history HEAD" \
            --ignore-gitleaks-allow --gitleaks-ignore-path "$no_ignore_file"
        history_scanned=true
    fi
fi

if ! "$have_git"; then
    echo "scan: no usable git repository here" >&2
fi
if ! "$history_scanned"; then
    if [[ "$require_history" == "1" ]]; then
        echo "scan: FAILED: the history could not be scanned" >&2
        failed=1
    else
        echo "scan: NOTE: the history was not scanned"
    fi
fi

if [[ "$failed" -ne 0 ]]; then
    echo "scan: FAILED, see the findings above" >&2
    exit 1
fi
echo "scan: clean"
