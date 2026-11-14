#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests deploy/tools/install.sh: it must accept the list of the repository,
# refuse a list with a fault, and install nothing whose SHA-256 is not the
# one in the list.
#
#   deploy/tests/rules/tools.sh            the checks that need no network
#   deploy/tests/rules/tools.sh --online   and one download with a wrong sum,
#                                          which must install nothing

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
install="$root/deploy/tools/install.sh"
list="$root/deploy/tools/tools.txt"
online=0
if [[ "${1:-}" == --online ]]; then
    online=1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failed=0
cases=0
sum="$(printf '%064d' 0 | tr 0 a)"
good="https://downloads.example.com/tool-1.0.0.tar.gz"

if "$install" --check >"$work/out" 2>&1; then
    echo "tools: ok: accepted: the list of the repository"
else
    echo "tools: FAILED: the list of the repository was refused" >&2
    sed 's/^/    /' "$work/out" >&2
    failed=1
fi

# refused WHAT MESSAGE LINE...: a list of these lines must be refused.
refused() {
    local what="$1" message="$2"
    shift 2
    cases=$((cases + 1))
    printf '%s\n' "$@" > "$work/list"
    if PGSNARE_TOOLS_LIST="$work/list" "$install" --check >"$work/out" 2>&1; then
        echo "tools: FAILED: accepted: $what" >&2
        failed=1
    elif ! grep -qF -- "$message" "$work/out"; then
        echo "tools: FAILED: refused for another reason: $what" >&2
        sed 's/^/    /' "$work/out" >&2
        failed=1
    else
        echo "tools: ok: refused: $what"
    fi
}

cases=$((cases + 1))
printf '%s\n' "# a comment" "" "tool 1.0.0 amd64 $sum tool $good" "tool 1.0.0 arm64 $sum - https://downloads.example.com/tool" > "$work/list"
if PGSNARE_TOOLS_LIST="$work/list" "$install" --check >"$work/out" 2>&1; then
    echo "tools: ok: accepted: a list without a fault"
else
    echo "tools: FAILED: a list without a fault was refused" >&2
    sed 's/^/    /' "$work/out" >&2
    failed=1
fi

refused "an empty list" "names no tool" "# nothing"
refused "a line with five fields" "six fields" "tool 1.0.0 amd64 $sum $good"
refused "a line with seven fields" "six fields" "tool 1.0.0 amd64 $sum tool $good more"
refused "an address without TLS" "not a plain HTTPS address" \
    "tool 1.0.0 amd64 $sum tool http://downloads.example.com/tool-1.0.0.tar.gz"
refused "an address with a query" "not a plain HTTPS address" \
    "tool 1.0.0 amd64 $sum - https://downloads.example.com/tool?version=1"
refused "a sum that is too short" "not a SHA-256" "tool 1.0.0 amd64 abcdef tool $good"
refused "a sum in upper case" "not a SHA-256" "tool 1.0.0 amd64 ${sum^^} tool $good"
refused "a version that moves" "not three numbers" "tool latest amd64 $sum tool $good"
refused "another architecture" "neither amd64 nor arm64" "tool 1.0.0 riscv64 $sum tool $good"
refused "a member outside the download" "not a plain relative path" \
    "tool 1.0.0 amd64 $sum ../tool $good"
refused "a member with an absolute path" "not a plain relative path" \
    "tool 1.0.0 amd64 $sum /bin/tool $good"
refused "a member of a download that is no archive" "needs a .tar.gz download" \
    "tool 1.0.0 amd64 $sum tool https://downloads.example.com/tool"
refused "a name with a path" "not a plain lower-case name" \
    "../tool 1.0.0 amd64 $sum tool $good"
refused "a tool for one architecture" "one architecture only" "tool 1.0.0 amd64 $sum tool $good"
refused "a tool in two versions" "two versions" \
    "tool 1.0.0 amd64 $sum tool $good" "tool 1.0.1 arm64 $sum tool $good"
refused "a tool listed twice" "listed twice" \
    "tool 1.0.0 amd64 $sum tool $good" "tool 1.0.0 amd64 $sum tool $good"

# A tool that is not in the list is not installed, and nothing is fetched.
cases=$((cases + 1))
if "$install" "$work/bin" no-such-tool >"$work/out" 2>&1 || ! grep -qF "not in the list" "$work/out"; then
    echo "tools: FAILED: a tool that is not in the list was not refused" >&2
    failed=1
else
    echo "tools: ok: refused: a tool that is not in the list"
fi

if [[ "$online" -eq 1 ]]; then
    # The first tool of the list, with one digit of every sum changed. The
    # download is the real one, so only the comparison can stop it.
    cases=$((cases + 1))
    tool="$(sed -nE 's/^([a-z0-9][a-z0-9-]*)[[:space:]].*$/\1/p' "$list" | head -n 1)"
    awk -v tool="$tool" '$1 == tool { digit = substr($4, 1, 1); $4 = (digit == "0" ? "1" : "0") substr($4, 2) } { print }' \
        "$list" > "$work/list"
    if cmp --silent "$list" "$work/list"; then
        echo "tools: FAILED: the test could not change a sum" >&2
        failed=1
    elif PGSNARE_TOOLS_LIST="$work/list" "$install" "$work/wrong" "$tool" >"$work/out" 2>&1; then
        echo "tools: FAILED: $tool was installed although its sum is not the one in the list" >&2
        failed=1
    elif ! grep -qF "the SHA-256 of the download is not the one in the list" "$work/out"; then
        echo "tools: FAILED: $tool was refused for another reason:" >&2
        sed 's/^/    /' "$work/out" >&2
        failed=1
    elif [[ -e "$work/wrong/$tool" ]]; then
        echo "tools: FAILED: $tool was refused and installed all the same" >&2
        failed=1
    else
        echo "tools: ok: refused: a download whose sum is not the one in the list"
    fi
fi

if [[ "$failed" -ne 0 ]]; then
    echo "tools: FAILED" >&2
    exit 1
fi
echo "tools: passed, $cases cases"
