#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Writes the licence notices of the code that pgsnare ships to the file
# named as the first argument: for every package that is a normal
# dependency of the package pgsnare with its default features, the SQL
# rules among them, on the musl target of the architecture of this
# machine, its name, its version, its licence, its repository, and the
# text of every file in its source directory whose name starts with
# LICENSE, LICENCE, COPYING, COPYRIGHT or NOTICE, in any case.
# The C code that the package pg_query bundles adds the licence and
# copyright files it carries up to three levels below its source.
#
#   scripts/notices.sh FILE
#
# The crates of this repository are left out: the licence of the
# repository goes with them. A package that carries no such file is
# listed with the name of the licence its manifest gives. Nothing is
# written from memory: only files are copied, byte for byte. The result
# is deterministic: the packages are sorted by name and version, and
# the files of a package by name.
#
# It needs cargo and nothing the development image does not hold: no jq
# and no python3 in it, so the metadata is parsed with awk.

set -euo pipefail

export LC_ALL=C

out="${1:?usage: notices.sh FILE}"
case "$out" in
    /*) : ;;
    *) out="$(pwd)/$out" ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# The package the notices are for, and the version it declares. The
# default features of the package enable the SQL rules.
name_of_package=pgsnare
version="$(sed -nE '/^\[workspace\.package\]/,/^\[/{s/^version = "([^"]+)"$/\1/p}' Cargo.toml)"
[[ -n "$version" ]] || { echo "notices: Cargo.toml does not declare one version of the workspace" >&2; exit 1; }

# The image builds the binary for the musl target of the architecture of
# this machine, and the build downloads the sources of the crates of that
# target alone. The resolve of the metadata holds the crates of every
# platform of Cargo.lock, so it is filtered to that target, and every
# source directory the script reads is one the build has downloaded.
case "$(uname -m)" in
    x86_64) target=x86_64-unknown-linux-musl ;;
    aarch64) target=aarch64-unknown-linux-musl ;;
    *) echo "notices: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if ! meta="$(cargo metadata --format-version 1 --locked --filter-platform "$target")"; then
    echo "notices: cargo metadata failed" >&2
    exit 1
fi
[[ -n "$meta" ]] || { echo "notices: cargo metadata wrote nothing" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The metadata is one line of JSON, and the development image holds no
# tool that reads JSON. Newlines never occur raw in JSON, so the line is
# joined, and a walk over the characters writes one line per item that
# is needed: the fields of the packages, and the nodes, the edges and
# the kind of the edges of the resolve, with the index of the package,
# the node or the edge, so that nothing is read by its position in the
# text.
#
#   P <package> <field> <value>   a field of a package
#   N <node> <id>                 a node of the resolve, by the id of its
#                                 package
#   D <node> <edge> <id>          an edge of the resolve, to the id of
#                                 the package it names
#   K <node> <edge> <kind>        the kind of an edge: normal, dev or
#                                 build
awk '
    function value(v) {
        if (key[1] == "packages" && d == 3 && st[3] == "o" && \
            (key[3] == "id" || key[3] == "name" || key[3] == "version" || \
             key[3] == "license" || key[3] == "repository" || \
             key[3] == "manifest_path" || key[3] == "source")) {
            if (v == "null") v = ""
            printf "P\t%d\t%s\t%s\n", ai[2], key[3], v
        }
        if (key[1] == "resolve" && key[2] == "nodes" && d == 4 && st[4] == "o" && key[4] == "id") {
            printf "N\t%d\t%s\n", ai[3], v
        }
        if (key[1] == "resolve" && key[4] == "deps" && d == 6 && st[6] == "o" && key[6] == "pkg") {
            printf "D\t%d\t%d\t%s\n", ai[3], ai[5], v
        }
        if (key[1] == "resolve" && key[6] == "dep_kinds" && d == 8 && st[8] == "o" && key[8] == "kind") {
            if (v == "null") printf "K\t%d\t%d\tnormal\n", ai[3], ai[5]
            else printf "K\t%d\t%d\t%s\n", ai[3], ai[5], v
        }
    }
    { json = json $0 }
    END {
        n = length(json)
        d = 0
        i = 1
        while (i <= n) {
            c = substr(json, i, 1)
            if (c == " " || c == "\t") { i++; continue }
            if (c == "\"") {
                i++
                buf = ""
                while (i <= n) {
                    c = substr(json, i, 1)
                    if (c == "\\") { buf = buf substr(json, i, 2); i += 2; continue }
                    if (c == "\"") { i++; break }
                    buf = buf c
                    i++
                }
                j = i
                while (j <= n && (substr(json, j, 1) == " " || substr(json, j, 1) == "\t")) j++
                if (substr(json, j, 1) == ":") key[d] = buf
                else value(buf)
                continue
            }
            if (c == "{" || c == "[") {
                if (d > 0 && st[d] == "a") ai[d]++
                d++
                st[d] = (c == "{") ? "o" : "a"
                if (st[d] == "a") ai[d] = 0
                key[d] = ""
                i++
                continue
            }
            if (c == "}" || c == "]") { d--; i++; continue }
            if (c == ":" || c == ",") { i++; continue }
            buf = ""
            while (i <= n) {
                c = substr(json, i, 1)
                if (c == " " || c == "\t" || c == "," || c == "}" || c == "]") break
                buf = buf c
                i++
            }
            if (d > 0 && st[d] == "a") ai[d]++
            value(buf)
        }
    }
' <<<"$meta" > "$work/tokens"

# From the packages and the edges, the packages that the binary holds:
# every package reached from pgsnare by an edge that is normal, that is
# not dev and not build. A package that the repository itself declares
# holds no source in the metadata and is left out. One line per
# package, sorted by name and version.
if ! awk -v startname="$name_of_package" -v startver="$version" '
    BEGIN { FS = "\t" }
    $1 == "P" {
        i = $2 + 0
        if (!(i in pkgidx)) { pkgidx[i] = 1; plist[++np] = i }
        pf[i, $3] = $4
        next
    }
    $1 == "N" { node_of[$3] = $2 + 0; next }
    $1 == "D" {
        e_pkg[$2, $3] = $4
        if ($3 > en[$2]) en[$2] = $3
        next
    }
    $1 == "K" && $4 == "normal" { enormal[$2, $3] = 1; next }
    END {
        start = 0
        for (i = 1; i <= np; i++) {
            idx = plist[i]
            if (pf[idx, "name"] == startname && pf[idx, "version"] == startver) start = idx
        }
        if (start == 0 || node_of[pf[start, "id"]] == "") {
            print "notices: the metadata does not name the package " startname " " startver > "/dev/stderr"
            exit 1
        }
        head = 1
        tail = 1
        queue[1] = node_of[pf[start, "id"]]
        seen[queue[1]] = 1
        while (head <= tail) {
            node = queue[head]
            head++
            for (k = 1; k <= en[node]; k++) {
                if (!((node, k) in enormal)) continue
                target = node_of[e_pkg[node, k]]
                if (target == "" || (target in seen)) continue
                seen[target] = 1
                queue[++tail] = target
            }
        }
        count = 0
        for (i = 1; i <= np; i++) {
            idx = plist[i]
            node = node_of[pf[idx, "id"]]
            if (node == "" || !(node in seen)) continue
            if (pf[idx, "source"] != "") {
                count++
                printf "%s\t%s\t%s\t%s\t%s\n", \
                    pf[idx, "name"], pf[idx, "version"], pf[idx, "license"], \
                    pf[idx, "repository"], pf[idx, "manifest_path"]
            }
        }
        if (count == 0) {
            print "notices: the package " startname " holds no dependency to report" > "/dev/stderr"
            exit 1
        }
    }
' "$work/tokens" | sort > "$work/packages"; then
    echo "notices: the packages of the metadata could not be read" >&2
    exit 1
fi

# A file copied as it is, and one newline added when it does not end in
# one, so that the next line of the result is a line of its own.
copy_file() {
    cat -- "$1"
    if [[ -s "$1" && -n "$(tail -c 1 -- "$1")" ]]; then
        printf '\n'
    fi
}

mkdir -p -- "$(dirname -- "$out")"
{
    echo "The licence notices of the packages that pgsnare depends on, with"
    echo "its default features, the SQL rules among them, and of the C code"
    echo "that the package pg_query bundles. The crates of this repository"
    echo "are left out: the licence of the repository goes with them. Only"
    echo "files are copied; no licence text is written from memory."
    while IFS=$'\t' read -r name version license repository manifest; do
        [[ -n "$license" ]] || license="(none)"
        [[ -n "$repository" ]] || repository="(none)"
        dir="${manifest%/*}"
        echo
        echo "$name $version"
        echo "  licence: $license"
        echo "  repository: $repository"
        if ! find "$dir" -maxdepth 1 -type f \
                \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' \
                   -o -iname 'COPYRIGHT*' -o -iname 'NOTICE*' \) \
            | sort > "$work/files"; then
            echo "notices: the files of $dir could not be listed" >&2
            exit 1
        fi
        if [[ -s "$work/files" ]]; then
            while IFS= read -r file; do
                echo "  file: ${file##*/}"
                copy_file "$file"
            done < "$work/files"
        else
            echo "  No licence file in the package; licence: $license"
        fi
        # The C code that pg_query bundles, up to three levels below its
        # source. A file that the search above already copied, in the
        # source itself, is not copied twice.
        if [[ "$name" == pg_query ]]; then
            echo "  C code of the crate:"
            if ! find "$dir" -maxdepth 3 -iname 'LICENSE*' \
                    -o -maxdepth 3 -iname 'COPYRIGHT*' \
                | sort > "$work/cfiles"; then
                echo "notices: the C code of $dir could not be listed" >&2
                exit 1
            fi
            cfiles=()
            while IFS= read -r file; do
                rel="${file#"$dir"/}"
                if [[ "$rel" == */* ]]; then
                    cfiles+=("$rel")
                fi
            done < "$work/cfiles"
            if [[ ${#cfiles[@]} -gt 0 ]]; then
                for rel in "${cfiles[@]}"; do
                    echo "  file: $rel"
                    copy_file "$dir/$rel"
                done
            else
                echo "  no licence or copyright file of the C code in the crate"
            fi
        fi
    done < "$work/packages"
} > "$out"

echo "notices: $out" >&2
