#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Checks advisories, bans, licences and sources with cargo-deny, for the
# workspace and for every fuzz crate, which each have their own lock file.
# Run it with `make deny`.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

status=0
for manifest in Cargo.toml crates/*/fuzz/Cargo.toml; do
    [[ -f "$manifest" ]] || continue
    echo "deny: $manifest"
    if ! cargo deny --manifest-path "$manifest" --config deny.toml --locked \
        check advisories bans licenses sources; then
        status=1
    fi
done
exit "$status"
