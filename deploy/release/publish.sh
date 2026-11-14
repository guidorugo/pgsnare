#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Publishes a release of pgsnare from what a build left behind. It compiles
# nothing and builds no image: it takes the image archives and the binaries
# of both architectures, checks them against the sums the build named, and
# from them makes and signs everything a release consists of.
#
#   deploy/release/publish.sh VERSION REGISTRY MODE INPUT OUTPUT
#
#   VERSION   three numbers, and at most -rc.N: 1.2.3 or 1.2.3-rc.1
#   REGISTRY  where the image and the chart go: ghcr.io/guidorugo for a
#             release. The image becomes REGISTRY/pgsnare and the chart
#             REGISTRY/charts/pgsnare, a path of its own, so that the tag of
#             a chart can never replace the tag of an image.
#   MODE      how to sign: `keyless`, with the identity of the workflow run
#             and an entry in the public transparency log, or `key=FILE`,
#             with the private key in FILE (its password in COSIGN_PASSWORD)
#             and no transparency log
#   INPUT     a directory with what deploy/tests/image/build.sh wrote on
#             each architecture: pgsnare-image-ARCH.tar, pgsnare-ARCH and
#             SHA256SUMS-ARCH, for amd64 and arm64
#   OUTPUT    a directory that is empty or does not exist: the files of the
#             release are written to it
#
# BUILD_SUMS_AMD64 and BUILD_SUMS_ARM64 must hold the SHA-256 of the two
# SHA256SUMS-ARCH files, as the jobs that built them reported it. Nothing is
# published from an input that does not match.
#
# A rehearsal and a release run this script with a different registry and a
# different mode, and differ in nothing else.
#
# What it writes to OUTPUT, for the version V:
#
#   pgsnare-V-linux-amd64.tar.gz       the binary and the licence
#   pgsnare-V-linux-arm64.tar.gz
#   pgsnare-V-crates.spdx.json         SBOM of the binaries: every crate of
#                                      Cargo.lock
#   pgsnare-V-image-amd64.spdx.json    SBOM of the image: the packages of
#   pgsnare-V-image-arm64.spdx.json    its base and the binary
#   pgsnare-V-chart.tgz                the chart, with the digest of the
#                                      image written into its values
#   pgsnare-V-manifests.yaml           the chart rendered with
#                                      deploy/release/manifests-values.yaml
#   pgsnare-V-digests.txt              the image, the image of each
#                                      architecture and the chart, by digest
#   SHA256SUMS                         the sums of all of the above
#   SHA256SUMS.sigstore.json           the signature of SHA256SUMS
#
# What it pushes: the image of each architecture as REGISTRY/pgsnare:V-ARCH,
# the image for both as REGISTRY/pgsnare:V, the chart as
# REGISTRY/charts/pgsnare:V, and a signature of each of the four. A version
# that the registry already holds is refused: a release is never replaced.
#
# It needs crane, cosign, syft and helm from deploy/tools/tools.txt.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
# shellcheck source=deploy/release/lib.sh
source "$here/lib.sh"

[[ "$#" -eq 5 ]] || die "usage: publish.sh VERSION REGISTRY MODE INPUT OUTPUT"
version="$1"
registry="$2"
input="$4"
output="$5"

check_version "$version"
check_registry "$registry"
read_mode "$3"
need crane cosign syft helm sha256sum tar gzip od

plain_http=()
if is_loopback "$registry"; then
    # Signed by the workflow's identity, an artefact goes to a registry
    # over TLS and nowhere else.
    [[ "$mode" == key ]] || die "a registry on the loopback interface is for a rehearsal with a key"
    plain_http=(--plain-http)
fi
if [[ "$mode" == key ]]; then
    [[ -n "${COSIGN_PASSWORD+set}" ]] || die "COSIGN_PASSWORD is not set (it may be empty)"
fi

[[ -d "$input" ]] || die "$input: no such directory"
input="$(cd "$input" && pwd)"
if [[ -e "$output" ]]; then
    [[ -d "$output" && -z "$(ls -A "$output")" ]] || die "$output: not an empty directory"
fi
mkdir -p "$output"
output="$(cd "$output" && pwd)"

image="$registry/pgsnare"
chart="$registry/charts/pgsnare"
arches=(amd64 arm64)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export SYFT_CHECK_FOR_APP_UPDATE=false

# --- The input, by checksum ---------------------------------------------------

sum_of() {
    sha256sum -- "$1" | cut -d' ' -f1
}

# The two bytes of an ELF header that name the machine.
machine_of() {
    od --address-radix=n --format=x1 --skip-bytes=18 --read-bytes=2 -- "$1" | tr -d ' \n'
}

declare -A binary_sum
for arch in "${arches[@]}"; do
    case "$arch" in
        amd64) expected="${BUILD_SUMS_AMD64:-}"; machine=3e00 ;;
        arm64) expected="${BUILD_SUMS_ARM64:-}"; machine=b700 ;;
    esac
    sums="$input/SHA256SUMS-$arch"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "the sum of the $arch build is not given as a SHA-256"
    for file in "$sums" "$input/pgsnare-image-$arch.tar" "$input/pgsnare-$arch"; do
        [[ -f "$file" && ! -L "$file" ]] || die "$file: not in the input"
    done
    [[ "$(sum_of "$sums")" == "$expected" ]] \
        || die "SHA256SUMS-$arch is not the file the build reported; nothing was published"
    # Exactly the two files, and both as the build left them.
    [[ "$(wc -l < "$sums")" -eq 2 ]] \
        && grep -Eqx "[0-9a-f]{64}  pgsnare-image-$arch\.tar" "$sums" \
        && grep -Eqx "[0-9a-f]{64}  pgsnare-$arch" "$sums" \
        || die "SHA256SUMS-$arch does not list the image archive and the binary, and only them"
    (cd "$input" && sha256sum --check --strict --quiet "SHA256SUMS-$arch") >&2 \
        || die "the $arch build does not match its sums; nothing was published"
    [[ "$(od --address-radix=n --format=x1 --read-bytes=4 -- "$input/pgsnare-$arch" | tr -d ' \n')" == 7f454c46 \
        && "$(machine_of "$input/pgsnare-$arch")" == "$machine" ]] \
        || die "pgsnare-$arch is not a binary for $arch"
    binary_sum[$arch]="$(sum_of "$input/pgsnare-$arch")"
done
say "the builds of both architectures match the sums that were reported"

# --- Nothing of this version is in the registry yet ---------------------------

for reference in "$image:$version" "$image:$version-amd64" "$image:$version-arm64" "$chart:$version"; do
    if crane digest "$reference" >/dev/null 2>&1; then
        die "$reference exists already; a release is never replaced"
    fi
done

# --- Archives of the binaries -------------------------------------------------
#
# The same input gives the same archive, byte for byte: sorted names, no
# owner, no time.

for arch in "${arches[@]}"; do
    name="pgsnare-$version-linux-$arch"
    mkdir -p "$work/archive/$name"
    install --mode 0755 "$input/pgsnare-$arch" "$work/archive/$name/pgsnare"
    install --mode 0644 "$root/LICENSE" "$work/archive/$name/LICENSE"
    tar --create --file - --directory "$work/archive" --format=ustar --sort=name \
        --owner=0 --group=0 --numeric-owner --mtime='@0' -- "$name" \
        | gzip --no-name --best > "$output/$name.tar.gz"
done

# --- SBOMs --------------------------------------------------------------------
#
# The binary does not say which crates it was built from, so their list
# comes from the file the build was locked to. It names every crate of the
# workspace's lock file, which is more than the binary links.

names_of() {
    { grep -o '"name":"[^"]*"' "$1" || true; } | cut -d'"' -f4 | LC_ALL=C sort -u
}

crates="$output/pgsnare-$version-crates.spdx.json"
syft scan "file:$root/Cargo.lock" --quiet --output "spdx-json=$crates" \
    --source-name pgsnare --source-version "$version"
sed -nE 's/^name = "([^"]+)"$/\1/p' "$root/Cargo.lock" | LC_ALL=C sort -u > "$work/locked"
names_of "$crates" > "$work/listed"
[[ -s "$work/locked" ]] || die "Cargo.lock names no crate"
missing="$(LC_ALL=C comm -23 "$work/locked" "$work/listed" | head -n 5 | tr '\n' ' ')"
[[ -z "$missing" ]] || die "the SBOM of the binaries lacks crates of Cargo.lock: $missing"

for arch in "${arches[@]}"; do
    sbom="$output/pgsnare-$version-image-$arch.spdx.json"
    syft scan "docker-archive:$input/pgsnare-image-$arch.tar" --quiet --output "spdx-json=$sbom" \
        --source-name pgsnare --source-version "$version"
    # An SBOM that lists nothing looks like one. The base of the image
    # always holds the package that names the distribution.
    names_of "$sbom" > "$work/packages"
    grep -qx 'base-files' "$work/packages" \
        || die "the SBOM of the $arch image does not list the packages of its base"
done
say "wrote the archives and the SBOMs"

# --- The image ----------------------------------------------------------------
#
# The archives are pushed as they are, without a container engine. The
# digest is the one the registry answers with.

digest_of() {
    local digest
    digest="$(crane digest "$1")" || die "$1: the registry names no digest"
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "$1: the registry named no SHA-256 digest"
    echo "$digest"
}

declare -A image_of
for arch in "${arches[@]}"; do
    crane push "$input/pgsnare-image-$arch.tar" "$image:$version-$arch" >/dev/null
    image_of[$arch]="$image@$(digest_of "$image:$version-$arch")"

    crane config "${image_of[$arch]}" > "$work/config-$arch.json"
    grep -Eq "\"architecture\":[[:space:]]*\"$arch\"" "$work/config-$arch.json" \
        && grep -Eq '"os":[[:space:]]*"linux"' "$work/config-$arch.json" \
        || die "the image pushed for $arch is not an image for linux/$arch"

    # A released binary is the file inside the image of that release.
    inside="$(crane export "${image_of[$arch]}" - \
        | tar --extract --to-stdout --file - usr/local/bin/pgsnare | sha256sum | cut -d' ' -f1)"
    [[ "$inside" == "${binary_sum[$arch]}" ]] \
        || die "the binary inside the $arch image is not the binary of the release"
done

crane index append --docker-empty-base \
    --manifest "${image_of[amd64]}" --manifest "${image_of[arm64]}" --tag "$image:$version" >/dev/null
image_digest="$(digest_of "$image:$version")"
image_of[all]="$image@$image_digest"
crane manifest "${image_of[all]}" > "$work/index.json"
[[ "$(grep -o '"digest"' "$work/index.json" | wc -l)" -eq 2 ]] \
    && grep -q "\"${image_of[amd64]#*@}\"" "$work/index.json" \
    && grep -q "\"${image_of[arm64]#*@}\"" "$work/index.json" \
    && grep -Eq '"architecture":[[:space:]]*"amd64"' "$work/index.json" \
    && grep -Eq '"architecture":[[:space:]]*"arm64"' "$work/index.json" \
    || die "the image for both architectures does not list exactly the two images"
say "pushed ${image_of[all]}"

# --- The chart ----------------------------------------------------------------
#
# The chart of the repository names no image. The chart of a release names
# the image of that release, by digest.

mkdir "$work/chart" "$work/packaged"
cp -R "$root/deploy/chart/pgsnare" "$work/chart/pgsnare"
values="$work/chart/pgsnare/values.yaml"
[[ "$(grep -c '^  repository: ghcr\.io/guidorugo/pgsnare$' "$values")" -eq 1 \
    && "$(grep -c '^  digest: ""$' "$values")" -eq 1 ]] \
    || die "values.yaml of the chart does not have the two lines that name the image"
sed --in-place \
    -e "s|^  repository: ghcr\.io/guidorugo/pgsnare\$|  repository: $image|" \
    -e "s|^  digest: \"\"\$|  digest: \"$image_digest\"|" "$values"
helm package "$work/chart/pgsnare" --version "$version" --app-version "$version" \
    --destination "$work/packaged" >/dev/null
package="$work/packaged/pgsnare-$version.tgz"
[[ -f "$package" ]] || die "the chart was not packaged as pgsnare-$version.tgz"
helm show values "$package" > "$work/values.yaml"
grep -qx "  repository: $image" "$work/values.yaml" \
    && grep -qx "  digest: \"$image_digest\"" "$work/values.yaml" \
    || die "the packaged chart does not name the image of this release"
helm show chart "$package" > "$work/Chart.yaml"
grep -qx "version: $version" "$work/Chart.yaml" \
    || die "the packaged chart does not carry the version $version"

helm push "$package" "oci://$registry/charts" "${plain_http[@]}" >&2
chart_reference="$chart@$(digest_of "$chart:$version")"
# What the registry holds under that digest is this very package.
crane manifest "$chart_reference" > "$work/chart.json"
grep -q "\"sha256:$(sum_of "$package")\"" "$work/chart.json" \
    || die "the chart in the registry is not the package that was pushed"
install --mode 0644 "$package" "$output/pgsnare-$version-chart.tgz"
say "pushed $chart_reference"

# --- The plain manifests ------------------------------------------------------

manifests="$output/pgsnare-$version-manifests.yaml"
helm template pgsnare "$package" --namespace pgsnare \
    --values "$here/manifests-values.yaml" > "$manifests"
named="$(grep -Ec '^[[:space:]]*-?[[:space:]]*image:' "$manifests" || true)"
right="$(grep -Fc "image: \"${image_of[all]}\"" "$manifests" || true)"
[[ "$named" -ge 1 && "$named" -eq "$right" ]] \
    || die "the manifests do not name the image of this release, and only it"

# --- The digests, the sums and the signatures ---------------------------------

{
    echo "image ${image_of[all]}"
    echo "image-amd64 ${image_of[amd64]}"
    echo "image-arm64 ${image_of[arm64]}"
    echo "chart $chart_reference"
} > "$output/pgsnare-$version-digests.txt"

mapfile -t files < <(release_files "$version")
for file in "${files[@]}"; do
    [[ -s "$output/$file" ]] || die "$file was not written"
done
(cd "$output" && sha256sum -- "${files[@]}" > SHA256SUMS)

sign=()
if [[ "$mode" == key ]]; then
    # A signing configuration that names no service: no certificate
    # authority, no transparency log, no timestamp authority.
    cosign signing-config create --out "$work/signing-config.json" >/dev/null
    sign=(--key "$key" --signing-config "$work/signing-config.json")
fi

cosign sign-blob --yes "${sign[@]}" --bundle "$output/SHA256SUMS.sigstore.json" \
    "$output/SHA256SUMS" >/dev/null
for reference in "${image_of[all]}" "${image_of[amd64]}" "${image_of[arm64]}" "$chart_reference"; do
    cosign sign --yes "${sign[@]}" "$reference" >/dev/null
done

[[ "$(ls -A "$output" | wc -l)" -eq $((${#files[@]} + 2)) ]] \
    || die "$output holds something that is not a file of the release"
say "signed the sums, the image, the image of each architecture and the chart"
sed 's/^/release: /' "$output/pgsnare-$version-digests.txt" >&2
