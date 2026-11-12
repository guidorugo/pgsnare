#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Runs every fuzz target of every crate for a short time. Run it with
# `make fuzz`.
#
# Fuzz targets live in `crates/<crate>/fuzz/`. Each target may have a seed
# corpus in `crates/<crate>/fuzz/seeds/<target>/`, which is tracked in git.
# The corpus the fuzzer grows and any crash it finds are written next to it
# and are not tracked.
#
# Environment:
#   FUZZ_SECONDS   time to fuzz each target (default 30)
#   FUZZ_CRATE     only this crate, for example pgsnare-proto
#   FUZZ_TARGET    only the target with this name

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

seconds="${FUZZ_SECONDS:-30}"
only_crate="${FUZZ_CRATE:-}"
only_target="${FUZZ_TARGET:-}"
toolchain="${PGSNARE_FUZZ_TOOLCHAIN:?run this inside the development image: make fuzz}"

if ! [[ "$seconds" =~ ^[0-9]+$ ]] || [[ "$seconds" -eq 0 ]]; then
    echo "fuzz: FUZZ_SECONDS must be a positive whole number" >&2
    exit 2
fi

ran=0
failed=0
for manifest in crates/*/fuzz/Cargo.toml; do
    [[ -f "$manifest" ]] || continue
    fuzz_dir="$root/$(dirname "$manifest")"
    crate_dir="$(dirname "$fuzz_dir")"
    crate="$(basename "$crate_dir")"
    [[ -z "$only_crate" || "$only_crate" == "$crate" ]] || continue

    # A fuzz crate has its own lock file. It must be committed and current.
    cargo metadata --locked --format-version 1 --manifest-path "$manifest" >/dev/null

    while IFS= read -r target; do
        [[ -n "$target" ]] || continue
        [[ -z "$only_target" || "$only_target" == "$target" ]] || continue

        corpus="$fuzz_dir/corpus/$target"
        mkdir -p "$corpus"
        corpora=("$corpus")
        if [[ -d "$fuzz_dir/seeds/$target" ]]; then
            corpora+=("$fuzz_dir/seeds/$target")
        fi

        echo "fuzz: $crate/$target for ${seconds}s"
        ran=$((ran + 1))
        if ! (cd "$crate_dir" && cargo +"$toolchain" fuzz run "$target" "${corpora[@]}" -- \
            -max_total_time="$seconds" -timeout=10 -rss_limit_mb=2048 -print_final_stats=1); then
            echo "fuzz: FAILED: $crate/$target" >&2
            failed=1
        fi
    done < <(cd "$crate_dir" && cargo +"$toolchain" fuzz list)
done

if [[ "$ran" -eq 0 ]]; then
    if [[ -n "$only_crate" || -n "$only_target" ]]; then
        echo "fuzz: no fuzz target matches FUZZ_CRATE='$only_crate' FUZZ_TARGET='$only_target'" >&2
        exit 2
    fi
    echo "fuzz: no fuzz targets exist yet"
    exit 0
fi

if [[ "$failed" -ne 0 ]]; then
    echo "fuzz: FAILED, crashing inputs are in crates/<crate>/fuzz/artifacts/" >&2
    exit 1
fi
echo "fuzz: $ran target(s) ran clean"
