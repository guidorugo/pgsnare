#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Scans the pgsnare image for known vulnerabilities.
#
#   deploy/tests/scan/scan.sh IMAGE
#
# IMAGE names the image by digest, in a registry this machine can reach.
# The scanner is `grype`, installed from deploy/tools/tools.txt and found
# on the PATH.
#
# The scan fails when:
#
#   - the vulnerability database cannot be downloaded, cannot be loaded or
#     is older than five days;
#   - the scanner does not find the one package of known-vulnerable.txt
#     vulnerable, or does not fail on it: this is tried first on every run,
#     because a scanner that reports nothing must not pass for a clean image;
#   - the scanner does not recognise the distribution of the base image,
#     and so cannot know its packages;
#   - the image holds a known vulnerability of high or critical severity.
#
# What the scan sees: the packages of the base image. It does not see the
# Rust dependencies inside the binary; `make deny` checks those against the
# advisory database, from Cargo.lock.

set -euo pipefail

image="${1:?usage: scan.sh IMAGE}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() {
    echo "scan: FAILED: $*" >&2
    exit 1
}

[[ "$image" =~ ^[a-z0-9][a-z0-9.:/_-]*@sha256:[0-9a-f]{64}$ ]] \
    || die "the image must be named by digest: NAME@sha256:..."
command -v grype >/dev/null || die "grype is not installed: deploy/tools/install.sh DIRECTORY grype"

# The severity from which a finding fails the scan.
threshold=high
# The distribution of the base image of deploy/Dockerfile.
distribution=debian

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The scanner asks nobody whether a newer scanner exists, and loads the
# database only in the step that says so.
export GRYPE_CHECK_FOR_APP_UPDATE=false
export GRYPE_DB_AUTO_UPDATE=false
export GRYPE_DB_VALIDATE_AGE=true
export GRYPE_DB_MAX_ALLOWED_BUILT_AGE=120h
export GRYPE_DB_CACHE_DIR="$work/db"

echo "scan: $(grype version 2>/dev/null | sed -nE 's/^Version:[[:space:]]*//p' | head -n 1 | sed 's/^/grype /')"

echo "scan: loading the vulnerability database"
grype db update >"$work/update.log" 2>&1 \
    || { tail -n 20 "$work/update.log" >&2; die "the vulnerability database could not be downloaded"; }
grype db status >"$work/status.log" 2>&1 \
    || { tail -n 20 "$work/status.log" >&2; die "the vulnerability database could not be loaded, or is too old"; }
sed 's/^/    /' "$work/status.log"

# --- The scanner must be able to fail -------------------------------------------
echo "scan: the scanner must fail on a package that is known to be vulnerable"
status=0
grype "purl:$here/known-vulnerable.txt" --output json --file "$work/known.json" >"$work/known.log" 2>&1 || status=$?
if [[ "$status" -ne 0 ]]; then
    tail -n 20 "$work/known.log" >&2
    die "the scanner could not scan the known package (exit status $status)"
fi
grep -qE 'GHSA-jfh8-c2jp-5v3q|CVE-2021-44228' "$work/known.json" \
    || die "the scanner did not find the known package vulnerable"
status=0
grype "purl:$here/known-vulnerable.txt" --fail-on "$threshold" --output json --file "$work/known.json" >"$work/known.log" 2>&1 || status=$?
[[ "$status" -ne 0 ]] \
    || die "the scanner found the known package vulnerable and did not fail on it"
echo "scan: ok: it finds the known package vulnerable, and fails on it with status $status"

# --- The image -------------------------------------------------------------------
echo "scan: scanning $image"
status=0
grype "registry:$image" --fail-on "$threshold" \
    --output table --output "json=$work/image.json" 2>"$work/image.log" || status=$?
if [[ ! -s "$work/image.json" ]]; then
    tail -n 20 "$work/image.log" >&2
    die "the scanner wrote no report for the image (exit status $status)"
fi
tr -d ' \n' < "$work/image.json" | grep -qF "\"distro\":{\"name\":\"$distribution\"" \
    || die "the scanner did not recognise the distribution of the base image as $distribution, so it cannot know its packages"
if [[ "$status" -ne 0 ]]; then
    tail -n 20 "$work/image.log" >&2
    die "the image holds a known vulnerability of severity $threshold or above, or the scan failed (exit status $status)"
fi
echo "scan: passed: no known vulnerability of severity $threshold or above"
