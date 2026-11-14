#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests the rules of scripts/check-repo.sh for images and for jobs: each
# rule must accept what it is meant to accept and refuse what it is meant
# to refuse.
#
#   deploy/tests/rules/repo.sh
#
# The test copies the script into a small tree of its own, checks that the
# script accepts that tree, and then breaks one rule at a time. The script
# must fail each time, and name the fault. Nothing in the repository is
# changed.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

digest="@sha256:$(printf '%064d' 0 | tr 0 a)"
toolchain="$(sed -nE 's/^channel = "([^"]+)"$/\1/p' "$root/rust-toolchain.toml")"
[[ -n "$toolchain" ]] || { echo "rules: could not read the Rust version" >&2; exit 1; }

failed=0
cases=0

# tree: a new copy of the tree that the script accepts. It prints its path.
tree() {
    local dir
    dir="$(mktemp -d "$work/tree.XXXXXX")"
    mkdir -p "$dir/scripts" "$dir/.github/workflows" "$dir/deploy/tests" \
        "$dir/deploy/chart/pgsnare/templates" "$dir/examples/compose"
    cp "$root/scripts/check-repo.sh" "$dir/scripts/check-repo.sh"
    cp "$root/rust-toolchain.toml" "$root/Dockerfile.dev" "$dir/"
    cat > "$dir/deploy/Dockerfile" <<DOCKERFILE
FROM rust:$toolchain-slim-trixie$digest AS build
RUN --mount=type=bind,from=registry.example.com/tools:1.0.0$digest,target=/tools true
FROM scratch AS binary
COPY --from=build /out/pgsnare /pgsnare
from --platform=linux/amd64 registry.example.com/base:1.0.0$digest as image
COPY --from=build /out/pgsnare /usr/local/bin/pgsnare
FROM binary
DOCKERFILE
    cat > "$dir/deploy/tests/compose.yaml" <<COMPOSE
services:
  database:
    image: postgres:18.6-trixie$digest
  quoted:
    image: "postgres:18.6-trixie$digest"   # a comment
  proxy:
    image: \${PGSNARE_IMAGE:?name the image by digest}
COMPOSE
    cat > "$dir/deploy/tests/manifest.json" <<JSON
{
  "image": "registry.example.com/pgsnare$digest",
  "properties": { "image": { "type": "object" } }
}
JSON
    printf 'image:\n  repository: registry.example.com/pgsnare\n  digest: ""\n' \
        > "$dir/deploy/chart/pgsnare/values.yaml"
    printf 'spec:\n  containers:\n    - image: "{{ .Values.image.repository }}@{{ .Values.image.digest }}"\n' \
        > "$dir/deploy/chart/pgsnare/templates/deployment.yaml"
    cat > "$dir/.github/workflows/lint.yml" <<'WORKFLOW'
name: lint
permissions:
  contents: read
jobs:
  lint:
    name: lint
    runs-on: ubuntu-24.04
    steps:
      - run: "true"
WORKFLOW
    cat > "$dir/.github/workflows/deploy.yml" <<'WORKFLOW'
name: deploy
permissions:
  contents: read
jobs:
  image-test:
    name: image-test
    runs-on: ubuntu-24.04
    permissions: {}
    steps:
      - name: Run the lint of something else
        run: "true"
WORKFLOW
    cat > "$dir/.github/workflows/release.yml" <<'WORKFLOW'
name: release
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-24.04
    permissions:
      contents: write
    steps:
      - run: "true"
WORKFLOW
    echo "$dir"
}

# check DIRECTORY: runs the script of that tree. Its output is in $work/out.
check() {
    bash "$1/scripts/check-repo.sh" >"$work/out" 2>&1
}

# refused WHAT MESSAGE DIRECTORY: the script must fail and say MESSAGE.
refused() {
    cases=$((cases + 1))
    if check "$3"; then
        echo "rules: FAILED: accepted: $1" >&2
        failed=1
    elif ! grep -qF -- "$2" "$work/out"; then
        echo "rules: FAILED: refused for another reason: $1" >&2
        sed 's/^/    /' "$work/out" >&2
        failed=1
    else
        echo "rules: ok: refused: $1"
    fi
}

# --- The tree as it should be ----------------------------------------------------
dir="$(tree)"
cases=$((cases + 1))
if check "$dir"; then
    echo "rules: ok: accepted: a tree that keeps every rule"
else
    echo "rules: FAILED: the tree that keeps every rule was refused" >&2
    sed 's/^/    /' "$work/out" >&2
    failed=1
fi

# --- Images in a Dockerfile ------------------------------------------------------
unpinned="is not pinned by digest"

# dockerfile WHAT MESSAGE LINE...: a Dockerfile under deploy/ with these lines.
dockerfile() {
    local what="$1" message="$2" dir
    shift 2
    dir="$(tree)"
    printf '%s\n' "$@" > "$dir/deploy/Dockerfile"
    refused "$what" "$message" "$dir"
}

dockerfile "FROM with a tag alone" "$unpinned" "FROM postgres:18.6-trixie"
dockerfile "FROM without a tag" "$unpinned" "FROM postgres"
dockerfile "FROM with a variable" "$unpinned" "ARG BASE=postgres:18" 'FROM ${BASE}'
dockerfile "FROM with a platform and a tag alone" "$unpinned" "FROM --platform=linux/amd64 debian:13"
dockerfile "FROM in lower case with a tag alone" "$unpinned" "from debian:13 as base"
dockerfile "FROM a stage that comes later" "$unpinned" "FROM later" "FROM scratch AS later"
dockerfile "FROM a digest that is too short" "$unpinned" "FROM debian:13@sha256:abcdef"
dockerfile "COPY --from an image with a tag alone" "$unpinned" \
    "FROM scratch" "COPY --from=busybox:1.37 /bin/sh /sh"
dockerfile "RUN --mount from an image with a tag alone" "$unpinned" \
    "FROM scratch" "RUN --mount=type=bind,from=alpine:3,target=/x true"
dockerfile "COPY --from a stage by its number" "$unpinned" \
    "FROM scratch AS first" "FROM scratch" "COPY --from=0 /a /a"
dockerfile "a Rust image of another version" "rust-toolchain.toml pins Rust $toolchain" \
    "FROM rust:1.0.0-slim-trixie$digest"
dockerfile "a Rust image without a version" "names no full version" \
    "FROM rust$digest"

dir="$(tree)"
mkdir -p "$dir/examples/compose"
echo "FROM debian:13" > "$dir/examples/compose/receiver.Dockerfile"
refused "a Dockerfile under examples/ with a tag alone" "$unpinned" "$dir"

# --- Images in other files -------------------------------------------------------
loose="is neither pinned by digest nor a variable that must be set"

# image WHAT FILE LINE: FILE, in a new tree, holds LINE.
image() {
    local dir
    dir="$(tree)"
    mkdir -p "$dir/$(dirname "$2")"
    printf '%s\n' "$3" > "$dir/$2"
    refused "$1" "$loose" "$dir"
}

image "an image with a tag alone" deploy/tests/compose.yaml "    image: postgres:18.6-trixie"
image "an image in a list item" deploy/tests/pod.yaml "    - image: postgres:18.6-trixie"
image "an image in quotes" examples/compose/compose.yaml "    image: 'registry.example.com/pgsnare:1.0.0'"
image "an image in JSON" deploy/tests/pod.json '  "image": "postgres:18.6-trixie",'
image "a variable that may be unset" deploy/tests/compose.yaml '    image: ${PGSNARE_IMAGE}'
image "a variable with a default" deploy/tests/compose.yaml '    image: ${PGSNARE_IMAGE:-postgres:18}'
image "a variable that may be empty" deploy/tests/compose.yaml '    image: ${PGSNARE_IMAGE?name it}'
image "a variable followed by a tag" deploy/tests/compose.yaml '    image: ${PGSNARE_IMAGE:?name it}:latest'
image "a template outside the templates of a chart" deploy/tests/pod.yaml \
    '    image: "{{ .Values.image }}"'
image "a template in the values of a chart" deploy/chart/pgsnare/values.yaml \
    'image: "{{ .Values.other }}"'

# --- Jobs ------------------------------------------------------------------------
required="is the name of a required check"
raised="only release.yml may give a job permissions of its own"

# workflow WHAT MESSAGE NAME LINE...: a workflow NAME.yml with these lines
# after its top-level permissions.
workflow() {
    local what="$1" message="$2" name="$3" dir
    shift 3
    dir="$(tree)"
    printf '%s\n' "name: $name" "permissions:" "  contents: read" "$@" \
        > "$dir/.github/workflows/$name.yml"
    refused "$what" "$message" "$dir"
}

workflow "a job with the key of a required check" "$required" deploy \
    "jobs:" "  lint:" "    runs-on: ubuntu-24.04"
workflow "a job with the key of a required check, in quotes" "$required" deploy \
    "jobs:" '  "itest":' "    runs-on: ubuntu-24.04"
workflow "a job with the name of a required check" "$required" deploy \
    "jobs:" "  first:" "    name: test" "    runs-on: ubuntu-24.04"
workflow "a job with the name of a required check, in quotes" "$required" deploy \
    "jobs:" "  first:" '    name: "fuzz"   # a comment' "    runs-on: ubuntu-24.04"
workflow "a required check in the workflow of another" "$required" lint \
    "jobs:" "  lint:" "    runs-on: ubuntu-24.04" "  scan:" "    runs-on: ubuntu-24.04"
workflow "a job with permissions of its own" "$raised" deploy \
    "jobs:" "  first:" "    runs-on: ubuntu-24.04" "    permissions:" "      packages: write"
workflow "a job with permissions on one line" "$raised" deploy \
    "jobs:" "  first:" "    runs-on: ubuntu-24.04" "    permissions: write-all"
workflow "a job that repeats the read-only permissions" "$raised" lint \
    "jobs:" "  lint:" "    runs-on: ubuntu-24.04" "    permissions:" "      contents: read"

if [[ "$failed" -ne 0 ]]; then
    echo "rules: FAILED" >&2
    exit 1
fi
echo "rules: passed, $cases cases"
