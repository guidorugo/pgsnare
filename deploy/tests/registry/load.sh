#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Puts an image archive into the registry that start.sh started, and prints
# the name of the image by digest: 127.0.0.1:5000/pgsnare@sha256:...
#
#   deploy/tests/registry/load.sh ARCHIVE [NAME]
#
# ARCHIVE is what `docker save` wrote for exactly one image. NAME is the
# repository in the registry, `pgsnare` unless given.
#
# The digest is the one the registry answers with, not one this script
# computes. The local copies are removed afterwards, so that a later
# `docker pull` of the printed name fetches the image from the registry.
# Only the name goes to standard output; everything else goes to standard
# error.

set -euo pipefail

archive="${1:?usage: load.sh ARCHIVE [NAME]}"
name="${2:-pgsnare}"
port="${PGSNARE_REGISTRY_PORT:-5000}"

die() {
    echo "registry: $*" >&2
    exit 1
}

[[ -f "$archive" ]] || die "$archive: no such archive"
[[ "$name" =~ ^[a-z0-9]+([._/-][a-z0-9]+)*$ ]] || die "the name is not a plain repository name"
[[ "$port" =~ ^[0-9]{2,5}$ ]] || die "the port is not a number"

loaded="$(docker load --input "$archive")"
echo "$loaded" >&2
[[ "$(grep -c '^Loaded image' <<<"$loaded")" -eq 1 ]] || die "the archive does not hold exactly one image"
source_image="$(sed -nE 's/^Loaded image( ID)?: (.+)$/\2/p' <<<"$loaded")"
[[ -n "$source_image" ]] || die "could not read the name of the loaded image"

repository="127.0.0.1:$port/$name"
tag="loaded-$(date +%s)-$$"
docker tag "$source_image" "$repository:$tag"
docker push --quiet "$repository:$tag" >&2

# The digest under which the registry serves what was pushed.
accept='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
digest="$(curl --fail --silent --show-error --max-time 20 --head \
    --header "Accept: $accept" "http://127.0.0.1:$port/v2/$name/manifests/$tag" \
    | tr -d '\r' | sed -nE 's/^[Dd]ocker-[Cc]ontent-[Dd]igest:[[:space:]]*(sha256:[0-9a-f]{64})$/\1/p')"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "the registry named no digest for $repository:$tag"

docker image rm "$repository:$tag" >/dev/null
case "$source_image" in
    sha256:*) ;;
    *) docker image rm "$source_image" >/dev/null 2>&1 || true ;;
esac

echo "$repository@$digest"
