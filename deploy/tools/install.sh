#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Installs tools from the list next to this script, deploy/tools/tools.txt.
#
#   deploy/tools/install.sh DIRECTORY TOOL...   install the named tools
#   deploy/tools/install.sh --check             check the list and stop
#
# A tool is downloaded over HTTPS, and installed only when the SHA-256 of
# the download equals the one in the list. Nothing is installed from a list
# that has a fault anywhere, and a download that fails its check is deleted.
#
# PGSNARE_TOOLS_LIST names another list. Only the test of this script uses
# it: deploy/tests/rules/tools.sh.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
list="${PGSNARE_TOOLS_LIST:-$here/tools.txt}"

# A download larger than this is not a tool of the list.
max_bytes=$((256 * 1024 * 1024))

die() {
    echo "install: $*" >&2
    exit 1
}

usage() {
    die "usage: install.sh DIRECTORY TOOL... | install.sh --check"
}

# --- The list ---------------------------------------------------------------
#
# Every line is checked before anything is downloaded, whichever tools were
# asked for.

names=()
versions=()
arches=()
sums=()
members=()
urls=()

read_list() {
    [[ -f "$list" ]] || die "$list: no such list"
    local number=0 line fields name version arch sum member url extra i
    while IFS= read -r line || [[ -n "$line" ]]; do
        number=$((number + 1))
        [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
        read -r name version arch sum member url extra <<<"$line" || true
        fields="$list:$number"
        [[ -n "${url:-}" && -z "${extra:-}" ]] || die "$fields: a line has six fields"
        [[ "$name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "$fields: the name is not a plain lower-case name"
        [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "$fields: the version is not three numbers"
        [[ "$arch" == amd64 || "$arch" == arm64 ]] || die "$fields: the architecture is neither amd64 nor arm64"
        [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || die "$fields: the sum is not a SHA-256 in lower-case hexadecimal"
        if [[ "$member" != "-" ]]; then
            [[ "$member" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ && ! "$member" =~ (^|/)\.\.?(/|$) ]] \
                || die "$fields: the member is not a plain relative path"
            [[ "$url" =~ \.(tar\.gz|tgz)$ ]] || die "$fields: a member needs a .tar.gz download"
        fi
        [[ "$url" =~ ^https://[A-Za-z0-9.-]+/[A-Za-z0-9._/+%-]+$ ]] || die "$fields: the address is not a plain HTTPS address"
        for i in "${!names[@]}"; do
            if [[ "${names[$i]}" == "$name" ]]; then
                [[ "${arches[$i]}" != "$arch" ]] || die "$fields: $name is listed twice for $arch"
                [[ "${versions[$i]}" == "$version" ]] || die "$fields: $name is listed in two versions"
            fi
        done
        names+=("$name")
        versions+=("$version")
        arches+=("$arch")
        sums+=("$sum")
        members+=("$member")
        urls+=("$url")
    done < "$list"

    [[ "${#names[@]}" -gt 0 ]] || die "$list: the list names no tool"
    local other found
    for i in "${!names[@]}"; do
        found=0
        for other in "${!names[@]}"; do
            if [[ "${names[$other]}" == "${names[$i]}" && "${arches[$other]}" != "${arches[$i]}" ]]; then
                found=1
            fi
        done
        [[ "$found" -eq 1 ]] || die "$list: ${names[$i]} is listed for one architecture only"
    done
}

# --- One tool ---------------------------------------------------------------

install_tool() {
    local wanted="$1" arch="$2" directory="$3" i index=-1
    for i in "${!names[@]}"; do
        if [[ "${names[$i]}" == "$wanted" && "${arches[$i]}" == "$arch" ]]; then
            index="$i"
        fi
    done
    [[ "$index" -ge 0 ]] || die "$wanted: not in the list for $arch"

    local sum="${sums[$index]}" member="${members[$index]}" url="${urls[$index]}"
    local download="$work/download" unpacked="$work/unpacked" tool
    rm -rf "$download" "$unpacked"
    mkdir "$unpacked"

    curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --retry 3 --connect-timeout 20 --max-time 600 --max-filesize "$max_bytes" \
        --output "$download" -- "$url" \
        || die "$wanted: the download failed"
    if [[ "$(stat --format %s "$download")" -gt "$max_bytes" ]]; then
        die "$wanted: the download is larger than $max_bytes bytes"
    fi
    if ! echo "$sum  $download" | sha256sum --check --strict --status -; then
        rm -f "$download"
        die "$wanted: the SHA-256 of the download is not the one in the list; nothing was installed"
    fi

    if [[ "$member" == "-" ]]; then
        tool="$download"
    else
        tar --extract --gzip --file "$download" --directory "$unpacked" \
            --no-same-owner --no-same-permissions -- "$member" \
            || die "$wanted: $member is not in the download"
        tool="$unpacked/$member"
    fi
    [[ -f "$tool" && ! -L "$tool" ]] || die "$wanted: the download does not hold a plain file for it"

    install -D --mode 0755 "$tool" "$directory/$wanted"
    echo "install: $wanted ${versions[$index]} for $arch, in $directory"
}

# --- Main -------------------------------------------------------------------

[[ "$#" -ge 1 ]] || usage
read_list
if [[ "$1" == "--check" ]]; then
    [[ "$#" -eq 1 ]] || usage
    echo "install: the list holds"
    exit 0
fi
[[ "$#" -ge 2 ]] || usage

directory="$1"
shift

case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac

mkdir -p "$directory"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for wanted in "$@"; do
    install_tool "$wanted" "$arch" "$directory"
done
