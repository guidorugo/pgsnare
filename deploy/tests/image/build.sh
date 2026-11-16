#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds the pgsnare image for the architecture of this machine, for the
# jobs of the deploy workflow.
#
#   deploy/tests/image/build.sh DIRECTORY [ARCHITECTURE]
#
# It writes to DIRECTORY, for the architecture ARCH (amd64 or arm64):
#
#   pgsnare-image-ARCH.tar   the image, as `docker save` writes it
#   pgsnare-ARCH             the binary that the `binary` stage exports
#   THIRD-PARTY-NOTICES      the licence notices the image holds, taken
#                            from the image, the same for both
#                            architectures
#   SHA256SUMS-ARCH          the sums of all of the above
#
# ARCHITECTURE, when given, must be the architecture of this machine: the
# image is built natively and never under emulation. Nothing is pushed
# anywhere.

set -euo pipefail

out="${1:?usage: build.sh DIRECTORY [ARCHITECTURE]}"
expected="${2:-}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
docker="${DOCKER:-docker}"

case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) echo "build: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
if [[ -n "$expected" && "$expected" != "$arch" ]]; then
    echo "build: this machine is $arch, and the image was asked for $expected" >&2
    exit 1
fi

mkdir -p "$out"
out="$(cd "$out" && pwd)"
tag="pgsnare:build-$arch"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# No attestation is attached, so the result is one image and not a list.
build=("$docker" buildx build --file "$root/deploy/Dockerfile" --provenance=false --sbom=false)

# The image says which version it is and which commit it was built from: the
# version of the workspace, which a release tag must equal, and the commit
# that is checked out, when there is a repository to ask.
version="$(sed -nE '/^\[workspace\.package\]/,/^\[/{s/^version = "([0-9A-Za-z.-]+)"$/\1/p}' "$root/Cargo.toml")"
if [[ -z "$version" || "$version" == *$'\n'* ]]; then
    echo "build: Cargo.toml does not declare one version of the workspace" >&2
    exit 1
fi
labels=(--label "org.opencontainers.image.version=$version")
revision="$(git -C "$root" rev-parse --verify --quiet 'HEAD^{commit}' 2>/dev/null || true)"
if [[ "$revision" =~ ^[0-9a-f]{40}$ ]]; then
    labels+=(--label "org.opencontainers.image.revision=$revision")
fi

echo "build: the image for $arch"
"${build[@]}" "${labels[@]}" --tag "$tag" --load "$root"

# The same build stage again, from the cache of the build above.
echo "build: the binary for $arch"
"${build[@]}" --target binary --output "type=local,dest=$work/binary" "$root"

# The licence notices the image holds, next to the binary: the release
# attaches the same file, so it is taken from the image that was built.
echo "build: the notices for $arch"
container="$("$docker" create "$tag")"
"$docker" cp --follow-link "$container:/usr/share/doc/pgsnare/THIRD-PARTY-NOTICES" "$work/notices" >/dev/null
"$docker" rm "$container" >/dev/null
install --mode 0644 "$work/notices" "$out/THIRD-PARTY-NOTICES"

"$docker" save --output "$out/pgsnare-image-$arch.tar" "$tag"
install --mode 0755 "$work/binary/pgsnare" "$out/pgsnare-$arch"
(cd "$out" && sha256sum "pgsnare-image-$arch.tar" "pgsnare-$arch" THIRD-PARTY-NOTICES > "SHA256SUMS-$arch")
sed 's/^/build: /' "$out/SHA256SUMS-$arch"
