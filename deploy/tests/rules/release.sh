#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests what cannot be rehearsed: the release workflow itself, which runs
# for a version tag only, and the check that decides whether a tag may
# become a release.
#
#   deploy/tests/rules/release.sh
#
# The first part reads .github/workflows/release.yml as text and holds it
# to the rules below. Each rule is also tried on a copy of the workflow in
# which it is broken, and must name that copy.
#
#   - the workflow starts on the push of a version tag and on nothing else
#   - `publish` is the only job that can write, and it names the
#     environment `release`
#   - a job that can write, and the job that verifies, compile nothing and
#     build no image
#   - no cache is restored anywhere
#   - no expression is written into a script, here and in deploy.yml
#   - the release is created as a draft
#
# The second part runs deploy/release/check-tag.sh in repositories made
# for the test.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
workflow="$root/.github/workflows/release.yml"
check_tag="$root/deploy/release/check-tag.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cases=0
failed=0

good() {
    cases=$((cases + 1))
    echo "ok   $1"
}

bad() {
    cases=$((cases + 1))
    failed=$((failed + 1))
    echo "FAIL $1"
}

# --- The rules ----------------------------------------------------------------

# The lines of one job, without comments.
job() {
    awk -v job="$2" '
        /^jobs:/ { jobs = 1; next }
        jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { inside = ($1 == job ":") ; next }
        jobs && inside && !/^[[:space:]]*#/ { print }
    ' "$1"
}

job_names() {
    awk '/^jobs:/ { jobs = 1; next } jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { sub(":", "", $1); print $1 }' "$1"
}

# The lines of every script of a workflow: what follows `run:`.
scripts() {
    awk '
        function indent(line) { match(line, /^ */); return RLENGTH }
        block && (/^[[:space:]]*$/ || indent($0) > depth) { print; next }
        { block = 0 }
        /^[[:space:]]*(- )?run:/ {
            depth = indent($0)
            rest = $0
            sub(/^[[:space:]]*(- )?run:[[:space:]]*/, "", rest)
            if (rest ~ /^[|>][+-]?[[:space:]]*$/) { block = 1 } else { print rest }
        }
    ' "$1"
}

# Prints one line for each rule that FILE breaks.
rules() {
    local file="$1" name text writers=0

    # What starts it: exactly the push of a tag that begins with v and a digit.
    if [[ "$(awk '/^on:/ { on = 1; next } on && /^[^[:space:]#]/ { on = 0 } on && !/^[[:space:]]*(#.*)?$/ { print }' "$file")" \
        != $'  push:\n    tags:\n      - "v[0-9]*"' ]]; then
        echo "trigger: the workflow starts on something else than the push of a version tag"
    fi
    if grep -Eq '^[[:space:]]*(workflow_dispatch|workflow_call|workflow_run|schedule|pull_request|release|branches)[[:space:]]*:' "$file"; then
        echo "trigger: the workflow names another trigger"
    fi

    while read -r name; do
        text="$(job "$file" "$name")"
        if grep -Eq '^[[:space:]]+[a-z-]+:[[:space:]]*write([[:space:]]|$)' <<<"$text" \
            || grep -Eq 'permissions:[[:space:]]*(write-all|\{[^}]*write)' <<<"$text"; then
            writers=$((writers + 1))
            [[ "$name" == publish ]] || echo "write: the job $name can write"
            grep -Eqx '    environment: release' <<<"$text" \
                || echo "environment: the job $name can write outside the environment release"
        fi
        if [[ "$name" == publish || "$name" == verify ]] \
            && grep -Eq '(^|[^a-z])(cargo|rustc|rustup|make|docker|buildx|build\.sh)([^a-z]|$)' <<<"$text"; then
            echo "build: the job $name compiles or builds"
        fi
        if [[ "$name" != check ]] && ! grep -Eq '^    needs:.*[^a-z-]check[^a-z-]|^    needs:[[:space:]]*(build|check)$' <<<"$text"; then
            echo "order: the job $name does not wait for an earlier job"
        fi
    done < <(job_names "$file")
    [[ "$writers" -eq 1 ]] || echo "write: $writers jobs can write, not one"
    grep -Eq '^    if: github\.repository == '"'guidorugo/pgsnare'"'$' <<<"$(job "$file" check)" \
        || echo "repository: the first job runs in any repository"

    if grep -Eiq 'actions/cache|restore-keys|cache-from|cache-to' "$file"; then
        echo "cache: a cache is restored"
    fi
    if [[ "$(scripts "$file" | grep -Fc '${{' || true)" -ne 0 ]]; then
        echo "expression: an expression is written into a script"
    fi
    if [[ "$(grep -c 'gh release create' "$file")" -ne "$(grep -c 'gh release create .* --draft ' "$file")" ]]; then
        echo "draft: the release is published at once"
    fi
    if grep -Eq 'secrets\.' "$file"; then
        echo "secret: the workflow reads a secret of the repository"
    fi
}

# holds FILE: FILE breaks no rule.
holds() {
    local out
    out="$(rules "$1")"
    if [[ -z "$out" ]]; then
        good "${1##*/} keeps to the rules"
    else
        bad "${1##*/} breaks a rule: $out"
    fi
}

# breaks RULE DESCRIPTION SED-EXPRESSION...: the workflow with the change
# breaks the rule named.
breaks() {
    local rule="$1" description="$2" copy="$work/release.yml" arguments=() expression broken
    shift 2
    for expression in "$@"; do
        arguments+=(-e "$expression")
    done
    sed -E "${arguments[@]}" "$workflow" > "$copy"
    if cmp --silent "$workflow" "$copy"; then
        bad "$description: the test changed nothing"
    elif broken="$(rules "$copy")" && grep -q "^$rule:" <<<"$broken"; then
        good "$description: refused"
    else
        bad "$description: accepted"
    fi
}

holds "$workflow"
if [[ "$(job_names "$workflow" | tr '\n' ' ')" == "check build image-test image-scan publish verify " ]]; then
    good "the workflow has the six jobs that the rules know"
else
    bad "the workflow has other jobs than the rules know: $(job_names "$workflow" | tr '\n' ' ')"
fi

breaks trigger "a start by hand" 's/^on:$/on:\n  workflow_dispatch:/'
breaks trigger "a start on every push" '/^    tags:$/d' '/^      - "v\[0-9\]\*"$/d'
breaks trigger "a start on a branch" 's/^    tags:$/    branches:/'
breaks trigger "a start on any tag" 's/^      - "v\[0-9\]\*"$/      - "*"/'
breaks trigger "a start on a nightly schedule" 's/^  push:$/  schedule:\n    - cron: "0 0 * * *"\n  push:/'
breaks write "a build job that can push packages" 's/^    needs: check$/    needs: check\n    permissions:\n      packages: write/'
breaks write "a verifying job that can write" 's/^      packages: read$/      packages: write/'
breaks write "a job with every permission" 's/^    needs: check$/    needs: check\n    permissions: write-all/'
breaks environment "publishing outside the environment" '/^    environment: release$/d'
breaks build "a publishing job that compiles" 's/^          deploy\/release\/publish\.sh (.*)$/          cargo build --release\n          deploy\/release\/publish.sh \1/'
breaks build "a publishing job that builds an image" 's/^(        run: deploy\/tools\/install\.sh "\$RUNNER_TEMP\/bin" crane cosign syft helm)$/\1 \&\& deploy\/tests\/image\/build.sh out/'
breaks order "a publishing job that waits for nothing" '/^    needs: \[check, build, image-test, image-scan\]$/d'
breaks repository "a first job that runs in a fork" "/^    if: github\\.repository == 'guidorugo\\/pgsnare'\$/d"
breaks cache "a build that restores a cache" 's/^      - name: Build the image and export the binary$/      - uses: actions\/cache@0000000000000000000000000000000000000000\n      - name: Build the image and export the binary/'
breaks expression "a tag name written into a script" 's/check-tag\.sh "\$GITHUB_REF"/check-tag.sh "${{ github.ref }}"/'
breaks expression "a version written into a script block" 's/publish\.sh "\$VERSION"/publish.sh "${{ needs.check.outputs.version }}"/'
breaks draft "a release that is published at once" 's/ --draft / /'
breaks secret "a secret of the repository" 's/REGISTRY_TOKEN: \$\{\{ github\.token \}\}/REGISTRY_TOKEN: ${{ secrets.REGISTRY_TOKEN }}/'

# The same rule about expressions, for the workflow that rehearses.
if [[ "$(scripts "$root/.github/workflows/deploy.yml" | grep -Fc '${{' || true)" -ne 0 ]]; then
    bad "deploy.yml writes an expression into a script"
else
    good "deploy.yml writes no expression into a script"
fi
[[ "$(scripts "$root/.github/workflows/deploy.yml" | grep -c 'rehearse\.sh')" -eq 1 ]] \
    && good "the scripts of deploy.yml are read: the rehearsal is among them" \
    || bad "the scripts of deploy.yml were not read"

# The signer that verify.sh accepts is this workflow, by its path.
if grep -Fqx 'release_workflow="$release_repository/.github/workflows/release.yml"' "$root/deploy/release/lib.sh" \
    && grep -Fqx 'release_repository="guidorugo/pgsnare"' "$root/deploy/release/lib.sh" \
    && [[ -f "$root/.github/workflows/release.yml" ]]; then
    good "the signer that verify.sh accepts is the release workflow of this repository"
else
    bad "the signer that verify.sh accepts is not the release workflow of this repository"
fi

# --- The check of a tag -------------------------------------------------------

quiet=(-c user.name=test -c user.email=test@example.com -c commit.gpgsign=false -c tag.gpgsign=false
    -c init.defaultBranch=main -c advice.detachedHead=false)

# repository NAME VERSION: a repository with the script, one commit on main
# as the remote has it, and a later commit that main does not have.
repository() {
    local directory="$work/$1" version="$2"
    rm -rf "$directory"
    mkdir -p "$directory/deploy/release"
    cp "$root/deploy/release/check-tag.sh" "$root/deploy/release/lib.sh" "$directory/deploy/release/"
    printf '[workspace]\nmembers = []\n\n[workspace.package]\nversion = "%s"\nedition = "2024"\n\n[workspace.dependencies]\nversion = "9.9.9"\n' \
        "$version" > "$directory/Cargo.toml"
    git "${quiet[@]}" -C "$directory" init --quiet
    git "${quiet[@]}" -C "$directory" add .
    git "${quiet[@]}" -C "$directory" commit --quiet --message "on main"
    git "${quiet[@]}" -C "$directory" update-ref refs/remotes/origin/main HEAD
    git "${quiet[@]}" -C "$directory" tag on-main
    echo later > "$directory/later"
    git "${quiet[@]}" -C "$directory" add .
    git "${quiet[@]}" -C "$directory" commit --quiet --message "not on main"
    git "${quiet[@]}" -C "$directory" tag off-main
}

# at NAME COMMIT TAG...: checks out COMMIT and gives it the tags.
at() {
    local directory="$work/$1" commit="$2" tag
    shift 2
    git "${quiet[@]}" -C "$directory" checkout --quiet "$commit"
    for tag in "$@"; do
        git "${quiet[@]}" -C "$directory" tag "$tag"
    done
}

accepts() {
    local description="$1" expected="$2" out
    shift 2
    if out="$("$@" 2>"$work/log")" && [[ "$out" == "$expected" ]]; then
        good "$description"
    else
        bad "$description: $(tail -n 1 "$work/log")"
    fi
}

rejects() {
    local reason="$1" description="$2"
    shift 2
    if "$@" >"$work/log" 2>&1; then
        bad "$description: accepted"
    elif grep -Fq -- "$reason" "$work/log"; then
        good "$description: refused"
    else
        bad "$description: it failed, but not for the expected reason ($reason): $(tail -n 1 "$work/log")"
    fi
}

repository good 1.2.3
at good on-main v1.2.3 v1.2.4 1.2.3 v1.2 v1.2.3-beta v01.2.3 v1.2.3.4
accepts "a tag of the version of Cargo.toml, on a commit of main" "version=1.2.3" \
    "$work/good/deploy/release/check-tag.sh" refs/tags/v1.2.3
rejects "Cargo.toml says 1.2.3" "a tag of another version than Cargo.toml" \
    "$work/good/deploy/release/check-tag.sh" refs/tags/v1.2.4
rejects "is not a tag that begins with v" "a tag without the v" \
    "$work/good/deploy/release/check-tag.sh" refs/tags/1.2.3
rejects "is not a tag that begins with v" "a branch with the name of a version" \
    "$work/good/deploy/release/check-tag.sh" refs/heads/v1.2.3
for wrong in v1.2 v1.2.3-beta v01.2.3 v1.2.3.4; do
    rejects "is not a version" "the tag $wrong" \
        "$work/good/deploy/release/check-tag.sh" "refs/tags/$wrong"
done

repository untagged 1.2.3
at untagged on-main
rejects "is not a tag of this repository" "a tag that does not exist" \
    "$work/untagged/deploy/release/check-tag.sh" refs/tags/v1.2.3

repository candidate 2.0.0-rc.1
at candidate on-main v2.0.0-rc.1
accepts "a release candidate" "version=2.0.0-rc.1" \
    "$work/candidate/deploy/release/check-tag.sh" refs/tags/v2.0.0-rc.1

repository branch 1.2.3
at branch off-main v1.2.3
rejects "is not on the main branch" "a tag on a commit that main does not have" \
    "$work/branch/deploy/release/check-tag.sh" refs/tags/v1.2.3

repository elsewhere 1.2.3
at elsewhere on-main v1.2.3
at elsewhere off-main
rejects "is not the commit of" "a tag that names another commit than the one checked out" \
    "$work/elsewhere/deploy/release/check-tag.sh" refs/tags/v1.2.3

repository shallow 1.2.3
at shallow on-main v1.2.3
git "${quiet[@]}" -C "$work/shallow" update-ref -d refs/remotes/origin/main
rejects "the main branch of the remote is not known" "a checkout that does not know main" \
    "$work/shallow/deploy/release/check-tag.sh" refs/tags/v1.2.3

echo "release rules: $cases cases, $failed failed"
[[ "$failed" -eq 0 ]]
