#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Verifies a release of pgsnare: that its files, its image and its chart
# are what the release workflow of this repository signed for one version.
# docs/verifying-a-release.md describes the same steps, done by hand.
#
#   deploy/release/verify.sh VERSION MODE release DIRECTORY
#   deploy/release/verify.sh VERSION MODE files DIRECTORY
#   deploy/release/verify.sh VERSION MODE image REFERENCE
#   deploy/release/verify.sh VERSION MODE chart REFERENCE
#   deploy/release/verify.sh VERSION MODE provenance DIRECTORY
#
#   VERSION    the version that is expected: 1.2.3 or 1.2.3-rc.1
#   MODE       `keyless` for a release: the signer must be the workflow
#              .github/workflows/release.yml of guidorugo/pgsnare, run for
#              the tag vVERSION, and the signature must be in the public
#              transparency log. `key=FILE` for a rehearsal: the signer must
#              hold the private key of the public key in FILE.
#   DIRECTORY  the files of the release, all of them and nothing else
#   REFERENCE  an image or a chart in a registry, by digest:
#              ghcr.io/guidorugo/pgsnare@sha256:...
#
#   files       the signature of SHA256SUMS, then every file against it
#   image       the signature of one image
#   chart       the signature of one chart
#   release     `files`, then the image, the image of each architecture and
#               the chart that the verified files name
#   provenance  with `keyless` only: `files`, then the build provenance that
#               GitHub recorded for every file, the image and the chart. It
#               needs `gh`, logged in.
#
# The signature is checked before anything it covers is read, and a
# reference is accepted by digest only: a tag can be moved.
#
# It needs cosign and sha256sum, and `gh` for `provenance`.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=deploy/release/lib.sh
source "$here/lib.sh"

[[ "$#" -eq 4 ]] || die "usage: verify.sh VERSION MODE release|files|image|chart|provenance DIRECTORY|REFERENCE"
version="$1"
what="$3"
subject="$4"

check_version "$version"
read_mode "$2"
need cosign sha256sum

if [[ "$mode" == key ]]; then
    # A rehearsal has no entry in a transparency log to look for.
    signer=(--key "$key" --insecure-ignore-tlog=true)
else
    signer=(--certificate-identity "$(signer_identity "$version")" --certificate-oidc-issuer "$release_issuer")
fi

# No file of a release is larger than this, and the sums and the digests
# are far smaller: nothing unbounded is read before its signature holds.
max_list_bytes=65536

mapfile -t expected < <(release_files "$version")

# --- The files ----------------------------------------------------------------

verify_files() {
    local directory="$1" file entry listed
    [[ -d "$directory" ]] || die "$directory: no such directory"
    for file in SHA256SUMS SHA256SUMS.sigstore.json; do
        [[ -f "$directory/$file" && ! -L "$directory/$file" ]] || die "$file is not in $directory"
        [[ "$(stat --format %s "$directory/$file")" -le "$max_list_bytes" ]] || die "$file is too large to be one"
    done

    # First the signature of the sums.
    cosign verify-blob "${signer[@]}" --bundle "$directory/SHA256SUMS.sigstore.json" \
        "$directory/SHA256SUMS" >/dev/null 2>"$work/cosign.err" \
        || { tail -n 3 "$work/cosign.err" >&2; die "SHA256SUMS is not signed by the expected signer"; }

    # Then the sums: exactly the files of this version, each once.
    listed="$(sed -nE 's/^[0-9a-f]{64}  ([A-Za-z0-9._-]+)$/\1/p' "$directory/SHA256SUMS" | LC_ALL=C sort)"
    [[ "$(wc -l < "$directory/SHA256SUMS")" -eq "${#expected[@]}" \
        && "$listed" == "$(printf '%s\n' "${expected[@]}" | LC_ALL=C sort)" ]] \
        || die "SHA256SUMS does not list the files of version $version, and only them"

    # Then the directory: every listed file, and nothing that is not listed.
    for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
        [[ -e "$entry" || -L "$entry" ]] || continue
        file="${entry##*/}"
        [[ -f "$entry" && ! -L "$entry" ]] || die "$file is not a plain file"
        case "$file" in
            SHA256SUMS | SHA256SUMS.sigstore.json) continue ;;
        esac
        grep -Fqx -- "$file" <<<"$listed" || die "$file is not a file of the release: no signature covers it"
    done
    (cd "$directory" && sha256sum --check --strict --quiet SHA256SUMS) >&2 \
        || die "a file does not match SHA256SUMS"
    say "the ${#expected[@]} files of $version match the signed sums"
}

# --- An image or a chart ------------------------------------------------------

verify_reference() {
    local kind="$1" reference="$2"
    check_reference "$reference"
    cosign verify "${signer[@]}" "$reference" >/dev/null 2>"$work/cosign.err" \
        || { tail -n 3 "$work/cosign.err" >&2; die "$kind $reference is not signed by the expected signer"; }
    say "$kind $reference is signed by the expected signer"
}

# The references that the verified files name. Sets `reference_of`.
declare -A reference_of
read_digests() {
    local directory="$1" name reference extra lines=0
    local digests="$directory/pgsnare-$version-digests.txt"
    [[ "$(stat --format %s "$digests")" -le "$max_list_bytes" ]] || die "the list of digests is too large to be one"
    while read -r name reference extra; do
        lines=$((lines + 1))
        [[ -z "${extra:-}" && "$name" == "${release_artefacts[$((lines - 1))]:-}" ]] \
            || die "the list of digests does not name the image, the image of each architecture and the chart"
        check_reference "$reference"
        reference_of[$name]="$reference"
    done < "$digests"
    [[ "$lines" -eq "${#release_artefacts[@]}" ]] \
        || die "the list of digests does not name the image, the image of each architecture and the chart"
}

# --- Build provenance ---------------------------------------------------------

verify_provenance() {
    local directory="$1" file subject
    [[ "$mode" == keyless ]] || die "a rehearsal has no build provenance to verify"
    need gh
    verify_files "$directory"
    read_digests "$directory"
    for file in "${expected[@]}"; do
        gh attestation verify "$directory/$file" --repo "$release_repository" \
            --signer-workflow "$release_workflow" --source-ref "refs/tags/v$version" \
            --deny-self-hosted-runners >/dev/null \
            || die "$file has no build provenance from the release workflow at v$version"
    done
    for subject in image chart; do
        gh attestation verify "oci://${reference_of[$subject]}" --repo "$release_repository" \
            --signer-workflow "$release_workflow" --source-ref "refs/tags/v$version" \
            --deny-self-hosted-runners >/dev/null \
            || die "the $subject has no build provenance from the release workflow at v$version"
    done
    say "the files, the image and the chart were built by the release workflow at v$version"
}

# --- Main ---------------------------------------------------------------------

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

case "$what" in
    files)
        verify_files "$subject"
        ;;
    image | chart)
        verify_reference "$what" "$subject"
        ;;
    release)
        verify_files "$subject"
        read_digests "$subject"
        for name in "${release_artefacts[@]}"; do
            verify_reference "$name" "${reference_of[$name]}"
        done
        say "release $version is verified"
        ;;
    provenance)
        verify_provenance "$subject"
        ;;
    *)
        die "'$what' is not one of release, files, image, chart, provenance"
        ;;
esac
