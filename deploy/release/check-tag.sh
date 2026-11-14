#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Decides whether a tag may become a release. The first job of the release
# workflow runs it, and nothing is built unless it passes.
#
#   deploy/release/check-tag.sh REF
#
# REF is the full name of the tag that started the workflow, such as
# refs/tags/v1.2.3. The repository is checked out at that tag, with its
# whole history. Three things must hold:
#
#   - the tag is `v` and a version: three numbers, and at most -rc.N
#   - that version is the version of the workspace in Cargo.toml
#   - the tag names the commit that is checked out, and that commit is on
#     the main branch as the remote has it
#
# On success it prints one line, `version=1.2.3`, for the outputs of the job.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=deploy/release/lib.sh
source "$here/lib.sh"

[[ "$#" -eq 1 ]] || die "usage: check-tag.sh REF"
ref="$1"

[[ "$ref" == refs/tags/v* ]] || die "'$ref' is not a tag that begins with v"
version="${ref#refs/tags/v}"
check_version "$version"

mapfile -t declared < <(sed -nE '/^\[workspace\.package\]/,/^\[/{s/^version = "([^"]*)"$/\1/p}' "$root/Cargo.toml")
[[ "${#declared[@]}" -eq 1 ]] || die "Cargo.toml does not declare one version of the workspace"
[[ "${declared[0]}" == "$version" ]] \
    || die "the tag says $version and Cargo.toml says ${declared[0]}: raise the version by pull request first"

git=(git -C "$root")
head="$("${git[@]}" rev-parse --verify --quiet 'HEAD^{commit}')" || die "no commit is checked out"
tagged="$("${git[@]}" rev-parse --verify --quiet "$ref^{commit}")" || die "$ref is not a tag of this repository"
[[ "$head" == "$tagged" ]] || die "the commit that is checked out is not the commit of $ref"
main="$("${git[@]}" rev-parse --verify --quiet 'refs/remotes/origin/main^{commit}')" \
    || die "the main branch of the remote is not known here: check out the whole history"
"${git[@]}" merge-base --is-ancestor "$head" "$main" \
    || die "the commit of $ref is not on the main branch: a release is cut from main only"

say "v$version is the version of Cargo.toml, on a commit of main"
echo "version=$version"
