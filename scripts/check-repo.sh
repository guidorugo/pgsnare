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
#   4. Every image that a file under deploy/ or examples/ names is pinned by
#      digest, and a Rust image there has the version of rust-toolchain.toml.
#   5. No job outside the six workflows of the required checks carries the
#      name of one, and no job outside release.yml is given permissions of
#      its own.

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

# --- 4. Images under deploy/ and examples/ ---------------------------------
# A tag can be moved to another image, and a digest cannot. So every image
# that these files name is named by digest, and whoever changes one changes
# a line of this repository.
digest='@sha256:[0-9a-f]{64}'

# pinned FILE:LINE REFERENCE STAGES: a reference in a Dockerfile is an
# earlier stage of the same file by its name, the empty image `scratch`, or
# an image with a digest. A Rust image has the version of rust-toolchain.toml.
pinned() {
    local where="$1" reference="$2" stages="$3"
    if [[ "$reference" == scratch || " $stages " == *" $reference "* ]]; then
        return 0
    fi
    if ! [[ "$reference" =~ ^[a-z0-9][a-z0-9._/:-]*${digest}$ ]]; then
        fail "$where: the image '$reference' is not pinned by digest"
        return 0
    fi
    if [[ "$reference" =~ ^((docker\.io/)?library/)?rust[:@] ]]; then
        if ! [[ "$reference" =~ ^((docker\.io/)?library/)?rust:([0-9]+\.[0-9]+\.[0-9]+)[-@] ]]; then
            fail "$where: the Rust image '$reference' names no full version"
        elif [[ "${BASH_REMATCH[3]}" != "$toolchain" ]]; then
            fail "$where: rust-toolchain.toml pins Rust $toolchain but this image is ${BASH_REMATCH[3]}"
        fi
    fi
}

while IFS= read -r -d '' file; do
    stages=""
    number=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        number=$((number + 1))
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ ^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]+(.*)$ ]]; then
            reference=""
            stage=""
            previous=""
            read -r -a words <<<"${BASH_REMATCH[1]}"
            for word in "${words[@]}"; do
                if [[ -z "$reference" ]]; then
                    [[ "$word" == --* ]] || reference="$word"
                elif [[ "$previous" == [Aa][Ss] ]]; then
                    stage="$word"
                fi
                previous="$word"
            done
            pinned "$file:$number" "$reference" "$stages"
            stages="$stages $stage"
        fi
        # `COPY --from=` and `RUN --mount=...,from=` read from an image too.
        rest="$line"
        while [[ "$rest" =~ (^|[[:space:],-])from=([^[:space:],]+)(.*)$ ]]; do
            rest="${BASH_REMATCH[3]}"
            pinned "$file:$number" "${BASH_REMATCH[2]}" "$stages"
        done
    done < "$file"
done < <(find deploy examples -type f \
    \( -name 'Dockerfile' -o -name 'Dockerfile.*' -o -name '*.Dockerfile' \
       -o -name 'Containerfile' -o -name 'Containerfile.*' \) \
    ! -name '*.dockerignore' -print0 2>/dev/null)

# An `image:` in a Compose file, a manifest or the values of a chart has a
# digest, or is a variable that must be set and has no default:
# `${NAME:?message}`. Only a template of a chart may compose the name: what
# it renders is checked where the chart is rendered.
while IFS= read -r hit; do
    file="${hit%%:*}"
    rest="${hit#*:}"
    number="${rest%%:*}"
    value="$(sed -E 's/^[[:space:]]*(-[[:space:]]+)?"?image"?:[[:space:]]*//; s/[[:space:]]+#.*$//; s/[[:space:]]+$//; s/,$//' <<<"${rest#*:}")"
    case "$value" in
        \"*\") value="${value#\"}"; value="${value%\"}" ;;
        \'*\') value="${value#\'}"; value="${value%\'}" ;;
    esac
    # No value, or the start of a mapping: a group of settings, not a name.
    if [[ -z "$value" || ( "$value" == \{* && "$value" != \{\{* ) ]]; then
        continue
    fi
    if [[ "$value" =~ ^\$\{[A-Z_][A-Z0-9_]*:\?[^}]*\}$ ]]; then
        continue
    fi
    if [[ "$value" == *'{{'* && "$file" == deploy/chart/*/templates/* ]]; then
        continue
    fi
    if ! [[ "$value" =~ ^[a-z0-9][a-z0-9._/:-]*${digest}$ ]]; then
        fail "$file:$number: the image '$value' is neither pinned by digest nor a variable that must be set"
    fi
done < <(grep -rnE --include='*.yaml' --include='*.yml' --include='*.json' --include='*.tpl' \
    '^[[:space:]]*(-[[:space:]]+)?"?image"?:' deploy examples 2>/dev/null || true)

# --- 5. Jobs ------------------------------------------------------------------
# `main` accepts a pull request when the checks with these names pass. Each
# is the one job of the workflow with the same name. A job of that name in
# another workflow could pass in its place.
required_checks='lint test deny scan itest fuzz'

for file in .github/workflows/*.yml .github/workflows/*.yaml; do
    base="$(basename "$file")"
    base="${base%.*}"
    # The key of a job, or the name of a job or of a step.
    while IFS= read -r line; do
        number="${line%%:*}"
        name="$(sed -E 's/^[0-9]+:[[:space:]]*(-[[:space:]]+)?//; s/^["'"'"']?name["'"'"']?[[:space:]]*:[[:space:]]*//; s/[[:space:]]+#.*$//; s/[[:space:]]+$//; s/[[:space:]]*:$//; s/^["'"'"']//; s/["'"'"']$//' <<<"$line")"
        for check in $required_checks; do
            if [[ "$name" == "$check" && "$check" != "$base" ]]; then
                fail "$file:$number: '$check' is the name of a required check and belongs to $check.yml alone"
            fi
        done
    done < <(grep -nE '^[[:space:]]+((-[[:space:]]+)?["'"'"']?name["'"'"']?[[:space:]]*:|["'"'"']?[A-Za-z0-9_-]+["'"'"']?[[:space:]]*:[[:space:]]*(#.*)?$)' "$file" || true)

    # The token is read-only for every job: the top-level block says so, and
    # a job says nothing else. Only the workflow that publishes a release
    # may give a job more, and it is reviewed for that.
    if [[ "$base" != release ]]; then
        while IFS= read -r line; do
            number="${line%%:*}"
            if ! [[ "$line" =~ ^[0-9]+:[[:space:]]+permissions:[[:space:]]*\{[[:space:]]*\}[[:space:]]*(#.*)?$ ]]; then
                fail "$file:$number: only release.yml may give a job permissions of its own"
            fi
        done < <(grep -nE '^[[:space:]]+["'"'"']?permissions["'"'"']?[[:space:]]*:' "$file" || true)
    fi
done

if [[ "$failed" -ne 0 ]]; then
    exit 1
fi
echo "check: repository rules hold"
