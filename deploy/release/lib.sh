# SPDX-License-Identifier: Apache-2.0
#
# What publish.sh and verify.sh share: the names of a release, and the checks
# of the arguments both take. Sourced, never run.
#
# shellcheck shell=bash

# Who signs a release without a key: the release workflow of this
# repository, started by a version tag, with a certificate issued for the
# identity token of that run. verify.sh accepts no other signer.
release_repository="guidorugo/pgsnare"
release_workflow="$release_repository/.github/workflows/release.yml"
release_issuer="https://token.actions.githubusercontent.com"

die() {
    echo "release: $*" >&2
    exit 1
}

say() {
    echo "release: $*" >&2
}

need() {
    local tool
    for tool in "$@"; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed"
    done
}

# Three numbers, and at most a release candidate: 1.2.3 or 1.2.3-rc.1. No
# leading zero, no `v`, nothing else. The version becomes part of file
# names, of tags in the registry and of the identity of the signer.
check_version() {
    local version="$1"
    local number='(0|[1-9][0-9]{0,5})'
    [[ "$version" =~ ^$number\.$number\.$number(-rc\.$number)?$ ]] \
        || die "'$version' is not a version: three numbers, and at most -rc.N after them"
}

# The tag of a version, as the identity of the signer names it.
signer_identity() {
    echo "https://github.com/$release_workflow@refs/tags/v$1"
}

# A registry and at most a path under it: ghcr.io/owner, or 127.0.0.1:5000/name.
check_registry() {
    local registry="$1"
    local word='[a-z0-9]+([._-][a-z0-9]+)*'
    [[ "${#registry}" -le 200 && "$registry" =~ ^$word(:[0-9]{2,5})?(/$word)*$ ]] \
        || die "'$registry' is not a registry: a host, at most a port, and at most a path in lower case"
}

# A registry on the loopback interface is spoken to without TLS. That is
# what a rehearsal inside one machine uses, and nothing else may.
is_loopback() {
    [[ "$1" =~ ^(127\.0\.0\.1|localhost)(:[0-9]{2,5})?(/|$) ]]
}

# An artefact in a registry, named by digest and by nothing else.
check_reference() {
    local reference="$1"
    local word='[a-z0-9]+([._-][a-z0-9]+)*'
    [[ "${#reference}" -le 300 && "$reference" =~ ^$word(:[0-9]{2,5})?(/$word)+@sha256:[0-9a-f]{64}$ ]] \
        || die "'$reference' does not name an artefact by digest: registry/path@sha256: and 64 hexadecimal digits"
}

# The signing mode: `keyless`, or `key=FILE`. Sets `mode` and `key`.
read_mode() {
    key=""
    case "$1" in
        keyless)
            mode=keyless
            ;;
        key=?*)
            mode=key
            key="${1#key=}"
            [[ -f "$key" && -r "$key" ]] || die "$key: no such key file"
            ;;
        *)
            die "'$1' is not a signing mode: keyless, or key=FILE"
            ;;
    esac
}

# The files of a release, for the version given: what publish.sh writes and
# what verify.sh expects, no more and no fewer. SHA256SUMS lists them all,
# and SHA256SUMS.sigstore.json is its signature.
release_files() {
    local version="$1"
    printf '%s\n' \
        "pgsnare-$version-chart.tgz" \
        "pgsnare-$version-crates.spdx.json" \
        "pgsnare-$version-digests.txt" \
        "pgsnare-$version-image-amd64.spdx.json" \
        "pgsnare-$version-image-arm64.spdx.json" \
        "pgsnare-$version-linux-amd64.tar.gz" \
        "pgsnare-$version-linux-arm64.tar.gz" \
        "pgsnare-$version-manifests.yaml"
}

# The four artefacts in the registry, as pgsnare-VERSION-digests.txt names
# them: one line each, a name, one blank and a reference by digest.
release_artefacts=(image image-amd64 image-arm64 chart)
