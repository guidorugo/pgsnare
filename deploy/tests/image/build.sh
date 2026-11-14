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
#   SHA256SUMS-ARCH          the sums of both
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

echo "build: the image for $arch"
"${build[@]}" --tag "$tag" --load "$root"

# The same build stage again, from the cache of the build above.
echo "build: the binary for $arch"
"${build[@]}" --target binary --output "type=local,dest=$work/binary" "$root"

"$docker" save --output "$out/pgsnare-image-$arch.tar" "$tag"
install --mode 0755 "$work/binary/pgsnare" "$out/pgsnare-$arch"
(cd "$out" && sha256sum "pgsnare-image-$arch.tar" "pgsnare-$arch" > "SHA256SUMS-$arch")
sed 's/^/build: /' "$out/SHA256SUMS-$arch"
