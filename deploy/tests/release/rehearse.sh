#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Rehearses a release: the scripts of deploy/release/ against a registry
# inside this machine, signing with a key that is made here and deleted
# here, without a transparency log and without an identity token. Nothing
# leaves the machine.
#
#   deploy/tests/release/rehearse.sh INPUT [REGISTRY]
#
#   INPUT     what deploy/tests/image/build.sh wrote for amd64 and arm64
#   REGISTRY  127.0.0.1:5000/rehearsal unless given; it must be on the
#             loopback interface
#
# BUILD_SUMS_AMD64 and BUILD_SUMS_ARM64 are what publish.sh asks for: the
# SHA-256 of the two SHA256SUMS-ARCH files, as the build jobs reported it.
#
# It publishes the version of Cargo.toml, verifies it with verify.sh, looks
# at what was published without the help of either script, and then shows
# that both scripts refuse what they must. A refusal counts only when the
# script says why, and the reason is the expected one.
#
# It needs crane, cosign, syft and helm from deploy/tools/tools.txt.

set -euo pipefail

input="${1:?usage: rehearse.sh INPUT [REGISTRY]}"
registry="${2:-127.0.0.1:${PGSNARE_REGISTRY_PORT:-5000}/rehearsal}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
publish="$root/deploy/release/publish.sh"
verify="$root/deploy/release/verify.sh"

[[ "$registry" =~ ^(127\.0\.0\.1|localhost):[0-9]{2,5}/ ]] || {
    echo "rehearse: the registry of a rehearsal is on the loopback interface" >&2
    exit 1
}
input="$(cd "$input" && pwd)"
: "${BUILD_SUMS_AMD64:?the sum of SHA256SUMS-amd64}" "${BUILD_SUMS_ARM64:?the sum of SHA256SUMS-arm64}"

version="$(sed -nE '/^\[workspace\.package\]/,/^\[/{s/^version = "([^"]+)"$/\1/p}' "$root/Cargo.toml")"
image="$registry/pgsnare"
chart="$registry/charts/pgsnare"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
out="$work/out"

checks=0
failed=0

good() {
    checks=$((checks + 1))
    echo "ok   $1"
}

bad() {
    checks=$((checks + 1))
    failed=$((failed + 1))
    echo "FAIL $1"
    if [[ -s "$work/log" ]]; then
        tail -n 12 "$work/log" | sed 's/^/       /'
    fi
}

# passes DESCRIPTION COMMAND...
passes() {
    local description="$1"
    shift
    if "$@" >"$work/log" 2>&1; then
        good "$description"
    else
        bad "$description"
    fi
}

# refuses REASON DESCRIPTION COMMAND...: the command must fail, and say REASON.
refuses() {
    local reason="$1" description="$2"
    shift 2
    if "$@" >"$work/log" 2>&1; then
        bad "$description: it was accepted"
    elif grep -Fq -- "$reason" "$work/log"; then
        good "$description: refused"
    else
        bad "$description: it failed, but not for the expected reason ($reason)"
    fi
}

# Changes one byte of a file.
change_byte() {
    local file="$1" offset="$2" old new=00
    old="$(od --address-radix=n --format=x1 --skip-bytes="$offset" --read-bytes=1 -- "$file" | tr -d ' \n')"
    [[ -n "$old" ]] || { echo "rehearse: $file has no byte $offset" >&2; exit 1; }
    [[ "$old" != 00 ]] || new=ff
    printf "\\x$new" | dd of="$file" bs=1 seek="$offset" conv=notrunc status=none
}

# --- The keys of this rehearsal -----------------------------------------------
#
# Two pairs: the one that signs, and one that must not be accepted in its
# place. Both are deleted with the working directory.

COSIGN_PASSWORD="$(head -c 24 /dev/urandom | base64)"
export COSIGN_PASSWORD
mkdir "$work/signer" "$work/stranger"
(cd "$work/signer" && cosign generate-key-pair >/dev/null 2>&1)
(cd "$work/stranger" && cosign generate-key-pair >/dev/null 2>&1)
key="$work/signer/cosign.key"
public="$work/signer/cosign.pub"
cosign signing-config create --out "$work/signing-config.json" >/dev/null

echo "rehearse: version $version, registry $registry"

# --- What publish.sh refuses, before anything is published --------------------

for wrong in "v$version" 1.0 1.0.0-beta 01.0.0 1.0.0-rc.1.2 "1.0.0 "; do
    refuses "is not a version" "publishing the version '$wrong'" \
        "$publish" "$wrong" "$registry" "key=$key" "$input" "$work/never"
done
refuses "is not a registry" "publishing to a registry with a tag in its name" \
    "$publish" "$version" "$registry:latest" "key=$key" "$input" "$work/never"
refuses "is for a rehearsal with a key" "signing without a key for a registry on the loopback interface" \
    "$publish" "$version" "$registry" keyless "$input" "$work/never"
refuses "is not the file the build reported" "an input that the build did not report" \
    env BUILD_SUMS_AMD64="$(printf '%064d' 0)" "$publish" "$version" "$registry" "key=$key" "$input" "$work/never"

mkdir "$work/altered-input"
cp "$input"/SHA256SUMS-* "$input"/pgsnare-* "$work/altered-input/"
change_byte "$work/altered-input/pgsnare-arm64" 4096
refuses "does not match its sums" "an input with a changed byte in a binary" \
    "$publish" "$version" "$registry" "key=$key" "$work/altered-input" "$work/never"
rm -rf "$work/altered-input"

passes "none of the refused inputs left anything in the registry" \
    bash -c '! crane digest "$1" && ! crane digest "$2" && ! crane digest "$3"' \
    - "$image:$version" "$image:$version-amd64" "$chart:$version"

# --- The rehearsal itself -----------------------------------------------------

passes "publish.sh publishes version $version" \
    "$publish" "$version" "$registry" "key=$key" "$input" "$out"
if [[ "$failed" -ne 0 ]]; then
    echo "rehearse: $failed of $checks checks failed; nothing was published to verify" >&2
    exit 1
fi
passes "verify.sh accepts the release" \
    "$verify" "$version" "key=$public" release "$out"

# --- What was published, seen without the two scripts -------------------------

digests="$out/pgsnare-$version-digests.txt"
reference() {
    sed -nE "s/^$1 (.+)\$/\\1/p" "$digests"
}
image_reference="$(reference image)"
chart_reference="$(reference chart)"

for arch in amd64 arm64; do
    name="pgsnare-$version-linux-$arch"
    passes "the $arch archive holds the binary of the build and the licence, and nothing else" \
        bash -c 'set -euo pipefail
            tar --extract --gzip --to-stdout --file "$1" "$2/pgsnare" | cmp - "$3"
            tar --extract --gzip --to-stdout --file "$1" "$2/LICENSE" | cmp - "$4"
            [[ "$(tar --list --gzip --file "$1" | wc -l)" -eq 3 ]]' \
        - "$out/$name.tar.gz" "$name" "$input/pgsnare-$arch" "$root/LICENSE"
    passes "the SBOM of the $arch image is an SPDX document that lists the base" \
        bash -c 'grep -q "\"spdxVersion\":\"SPDX-" "$1" && grep -q "\"name\":\"base-files\"" "$1"' \
        - "$out/pgsnare-$version-image-$arch.spdx.json"
done
passes "the SBOM of the binaries is an SPDX document that lists a crate of the lock file" \
    bash -c 'grep -q "\"spdxVersion\":\"SPDX-" "$1" && grep -q "\"name\":\"rustls\"" "$1"' \
    - "$out/pgsnare-$version-crates.spdx.json"

passes "the tag of the version names the image of the digest list" \
    bash -c '[[ "$1@$(crane digest "$1:$2")" == "$3" ]]' - "$image" "$version" "$image_reference"
passes "the image is one for linux/amd64 and one for linux/arm64" \
    bash -c 'set -euo pipefail
        crane manifest "$1" > "$2"
        grep -Eq "\"architecture\":[[:space:]]*\"amd64\"" "$2"
        grep -Eq "\"architecture\":[[:space:]]*\"arm64\"" "$2"
        [[ "$(grep -o "\"architecture\"" "$2" | wc -l)" -eq 2 ]]' \
    - "$image_reference" "$work/index.json"

mkdir "$work/pulled"
passes "helm pulls the chart from the registry, and it is the chart of the release" \
    bash -c 'helm pull "oci://$1" --version "$2" --plain-http --destination "$3" \
        && cmp "$3/pgsnare-$2.tgz" "$4"' \
    - "$chart" "$version" "$work/pulled" "$out/pgsnare-$version-chart.tgz"
passes "the chart of the release, given no image, renders the image of the release by digest" \
    bash -c 'helm template check "$1" --values "$2" | grep -Fq "image: \"$3\""' \
    - "$out/pgsnare-$version-chart.tgz" "$root/deploy/release/manifests-values.yaml" "$image_reference"
passes "the plain manifests name the image of the release, by digest" \
    grep -Fq "image: \"$image_reference\"" "$out/pgsnare-$version-manifests.yaml"
passes "no file of the release holds a private key" \
    bash -c '! grep -rlq "PRIVATE KEY" "$1"' - "$out"

# --- What verify.sh refuses ---------------------------------------------------

# A copy of the release with one thing changed.
altered() {
    rm -rf "$work/altered"
    cp -R "$out" "$work/altered"
}
resign() {
    cosign sign-blob --yes --key "$1" --signing-config "$work/signing-config.json" \
        --bundle "$work/altered/SHA256SUMS.sigstore.json" "$work/altered/SHA256SUMS" >/dev/null 2>&1
}
resum() {
    (cd "$work/altered" && sha256sum -- pgsnare-* > SHA256SUMS)
}

altered
change_byte "$work/altered/pgsnare-$version-linux-amd64.tar.gz" 2048
refuses "does not match SHA256SUMS" "a changed byte in a binary" \
    "$verify" "$version" "key=$public" release "$work/altered"

resum
refuses "SHA256SUMS is not signed by the expected signer" "a changed byte in a binary, with the sums written again" \
    "$verify" "$version" "key=$public" release "$work/altered"

resign "$work/stranger/cosign.key"
refuses "SHA256SUMS is not signed by the expected signer" "the same, signed again with another key" \
    "$verify" "$version" "key=$public" release "$work/altered"
passes "the other key does verify what it signed, so the refusal was about the signer" \
    "$verify" "$version" "key=$work/stranger/cosign.pub" files "$work/altered"

altered
echo extra > "$work/altered/pgsnare-$version-linux-riscv64.tar.gz"
refuses "is not a file of the release" "a file that the sums do not list" \
    "$verify" "$version" "key=$public" files "$work/altered"

altered
rm "$work/altered/pgsnare-$version-crates.spdx.json"
refuses "does not match SHA256SUMS" "a release with a file missing" \
    "$verify" "$version" "key=$public" files "$work/altered"

altered
rm "$work/altered/SHA256SUMS.sigstore.json"
refuses "SHA256SUMS.sigstore.json is not in" "a release without a signature" \
    "$verify" "$version" "key=$public" files "$work/altered"

refuses "does not list the files of version" "the files of this version, presented as another version" \
    "$verify" 999.0.0 "key=$public" files "$out"
refuses "is not a version" "a version that is not one" \
    "$verify" "v$version" "key=$public" files "$out"
refuses "no build provenance" "provenance asked of a rehearsal" \
    "$verify" "$version" "key=$public" provenance "$out"

# An image of another digest: the amd64 image with one label more.
other_image="$(crane mutate --label rehearsal=other --tag "$image:other" "$(reference image-amd64)" 2>/dev/null)"
refuses "is not signed by the expected signer" "an image of another digest" \
    "$verify" "$version" "key=$public" image "$other_image"
cosign sign --yes --key "$work/stranger/cosign.key" --signing-config "$work/signing-config.json" \
    "$other_image" >/dev/null 2>&1
refuses "is not signed by the expected signer" "an image of another digest, signed with another key" \
    "$verify" "$version" "key=$public" image "$other_image"
passes "the other key does verify that image, so the refusal was about the signer" \
    "$verify" "$version" "key=$work/stranger/cosign.pub" image "$other_image"
refuses "does not name an artefact by digest" "an image named by tag" \
    "$verify" "$version" "key=$public" image "$image:$version"

# The files of the release, signed by the right key, but naming that image.
altered
sed --in-place "s|^image .*\$|image $other_image|" "$work/altered/pgsnare-$version-digests.txt"
resum
resign "$key"
refuses "image $other_image is not signed by the expected signer" \
    "a release whose signed files name an image that its signer did not sign" \
    "$verify" "$version" "key=$public" release "$work/altered"

# An unsigned chart: the chart of the repository under another version.
mkdir "$work/unsigned"
helm package "$root/deploy/chart/pgsnare" --version 999.0.0 --destination "$work/unsigned" >/dev/null
helm push "$work/unsigned/pgsnare-999.0.0.tgz" "oci://$registry/charts" --plain-http >/dev/null 2>&1
unsigned_chart="$chart@$(crane digest "$chart:999.0.0")"
refuses "is not signed by the expected signer" "an unsigned chart" \
    "$verify" "$version" "key=$public" chart "$unsigned_chart"
passes "the chart of the release, by itself, is accepted" \
    "$verify" "$version" "key=$public" chart "$chart_reference"

# --- A release is never replaced ----------------------------------------------

refuses "exists already" "publishing the same version again" \
    "$publish" "$version" "$registry" "key=$key" "$input" "$work/again"

echo "rehearse: $checks checks, $failed failed"
[[ "$failed" -eq 0 ]]
