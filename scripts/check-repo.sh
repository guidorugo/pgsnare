#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks the repository rules that no compiler enforces. `make lint` runs it.
#
#   1. Every Rust source file and shell script carries the SPDX licence line.
#   2. rust-toolchain.toml and Dockerfile.dev name the same Rust version.
#   3. Every workflow gives its token read-only access at the top level,
#      never runs on `pull_request_target`, and uses only actions that are
#      local or pinned to a full commit SHA and written by GitHub.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

failed=0
fail() {
    echo "check: $*" >&2
    failed=1
}

# --- 1. SPDX licence line -------------------------------------------------
spdx='SPDX-License-Identifier: Apache-2.0'
while IFS= read -r -d '' file; do
    # The line comes first, or second after a `#!` line.
    if ! head -n 2 "$file" | grep -qE "^(//|#) ${spdx}\$"; then
        fail "$file: missing the line '$spdx' at the top"
    fi
done < <(find . \
    \( -name .git -o -name target \
       -o -path './crates/*/fuzz/artifacts' \
       -o -path './crates/*/fuzz/corpus' \
       -o -path './crates/*/fuzz/coverage' \) -prune \
    -o -type f \( -name '*.rs' -o -name '*.sh' \) -print0)

# --- 2. One Rust version --------------------------------------------------
toolchain="$(sed -nE 's/^channel = "([^"]+)"$/\1/p' rust-toolchain.toml)"
image="$(sed -nE 's/^FROM rust:([0-9]+\.[0-9]+\.[0-9]+)-.*$/\1/p' Dockerfile.dev)"
if [[ -z "$toolchain" || -z "$image" ]]; then
    fail "could not read the Rust version from rust-toolchain.toml and Dockerfile.dev"
elif [[ "$toolchain" != "$image" ]]; then
    fail "rust-toolchain.toml pins Rust $toolchain but Dockerfile.dev uses $image"
fi
if ! sed -nE 's/^FROM (.*)$/\1/p' Dockerfile.dev | grep -qE '@sha256:[0-9a-f]{64}$'; then
    fail "Dockerfile.dev: the base image is not pinned by digest"
fi

# --- 3. Workflows ---------------------------------------------------------
# Actions from these owners are written by GitHub. An action from a verified
# publisher needs its owner added here, which makes the choice reviewable.
allowed_owners='actions github'

shopt -s nullglob globstar
for file in .github/workflows/*.yml .github/workflows/*.yaml .github/actions/**/action.yml; do
    while IFS= read -r line; do
        number="${line%%:*}"
        action="$(sed -E 's/^[0-9]+:[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*//; s/[[:space:]]+#.*$//; s/^["'"'"']//; s/["'"'"']$//' <<<"$line")"
        case "$action" in
            ./*) continue ;;
        esac
        if ! [[ "$action" =~ ^([A-Za-z0-9_.-]+)/[A-Za-z0-9_./-]+@[0-9a-f]{40}$ ]]; then
            fail "$file:$number: '$action' is not pinned to a full commit SHA"
            continue
        fi
        owner="${BASH_REMATCH[1]}"
        if ! grep -qwF -- "$owner" <<<"$allowed_owners"; then
            fail "$file:$number: actions from '$owner' are not on the allowed list"
        fi
    done < <(grep -nE '^[[:space:]]*(-[[:space:]]+)?uses:' "$file" || true)

    if grep -qE 'pull_request_target' "$file"; then
        fail "$file: pull_request_target runs untrusted code with secrets and is not allowed"
    fi
done

for file in .github/workflows/*.yml .github/workflows/*.yaml; do
    # The top-level block must be exactly `permissions:` with `contents: read`.
    block="$(awk '
        /^permissions:[[:space:]]*$/ { inside = 1; next }
        inside && /^[[:space:]]+[^[:space:]#]/ { print; next }
        inside && /^[^[:space:]]/ { inside = 0 }
    ' "$file" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    if [[ "$block" != "contents: read" ]]; then
        fail "$file: the top-level permissions must be exactly 'contents: read'"
    fi
done

if [[ "$failed" -ne 0 ]]; then
    exit 1
fi
echo "check: repository rules hold"
