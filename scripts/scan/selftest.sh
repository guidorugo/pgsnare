#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Proves that the scan rules work: every sample that must be flagged is
# flagged, and every sample that must pass does pass. `make scan` runs this
# before it scans the repository.
#
# The samples are assembled at run time from separate pieces, so this file
# contains no private address and no secret, and passes the scan itself.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
secrets_config="$root/.gitleaks.toml"
addresses_config="$root/scripts/scan/private-addresses.toml"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
no_ignore_file="$work/no-ignore-file"
mkdir -p "$no_ignore_file"

failures=0
checks=0

# flagged <config> <text>: succeeds if the scan reports the text.
flagged() {
    local config="$1" text="$2" sample="$work/sample"
    rm -rf "$sample"
    mkdir -p "$sample"
    printf '%s\n' "$text" > "$sample/sample.txt"
    if gitleaks dir "$sample" --config "$config" --no-banner --redact \
        --log-level error --ignore-gitleaks-allow \
        --gitleaks-ignore-path "$no_ignore_file" >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# The descriptions never contain the sample, for the reason given above.
must_flag() {
    local config="$1" description="$2" text="$3"
    checks=$((checks + 1))
    if ! flagged "$config" "$text"; then
        echo "selftest: MISSED: $description" >&2
        failures=$((failures + 1))
    fi
}

must_pass() {
    local config="$1" description="$2" text="$3"
    checks=$((checks + 1))
    if flagged "$config" "$text"; then
        echo "selftest: WRONGLY FLAGGED: $description" >&2
        failures=$((failures + 1))
    fi
}

# Joins its arguments with dots, or with colons.
dotted() { local IFS=.; printf '%s' "$*"; }
coloned() { local IFS=:; printf '%s' "$*"; }

a="$addresses_config"

# --- IPv4 that must be flagged -------------------------------------------
must_flag "$a" "RFC 1918, 8-bit block"                "$(dotted 10 20 30 40)"
must_flag "$a" "RFC 1918, 8-bit block, low end"       "$(dotted 10 0 0 0)"
must_flag "$a" "RFC 1918, 8-bit block, high end"      "$(dotted 10 255 255 255)"
must_flag "$a" "RFC 1918, 12-bit block, low end"      "$(dotted 172 16 0 1)"
must_flag "$a" "RFC 1918, 12-bit block, high end"     "$(dotted 172 31 255 254)"
must_flag "$a" "RFC 1918, 16-bit block"               "$(dotted 192 168 1 10)"
must_flag "$a" "IPv4 link-local"                      "$(dotted 169 254 10 20)"
must_flag "$a" "private address with a prefix length" "$(dotted 10 0 0 0)/8"
must_flag "$a" "private address with a port"          "host=$(dotted 192 168 0 5):5432"
must_flag "$a" "private address in a URL"             "postgres://app@$(dotted 10 1 2 3):5432/db"
must_flag "$a" "private address ending a sentence"    "The server is $(dotted 10 1 2 3)."
must_flag "$a" "private address in quotes"            "listen: \"$(dotted 172 20 0 2)\""
must_flag "$a" "private address after an equals sign" "ADDR=$(dotted 192 168 100 200)"
must_flag "$a" "IPv4-mapped private address"          "::ffff:$(dotted 10 0 0 1)"

# --- IPv6 that must be flagged -------------------------------------------
must_flag "$a" "IPv6 link-local, short form"          "$(coloned fe80 '' 1)"
must_flag "$a" "IPv6 link-local, upper case"          "$(coloned FE80 '' ABCD 1)"
must_flag "$a" "IPv6 link-local, end of the range"    "$(coloned febf '' 1)"
must_flag "$a" "IPv6 link-local with a zone"          "$(coloned fe80 '' 1)%eth0"
must_flag "$a" "IPv6 unique local, fc block"          "$(coloned fc00 '' 1)"
must_flag "$a" "IPv6 unique local, fd block"          "$(coloned fd12 3456 789a '' 1)"
must_flag "$a" "IPv6 unique local, full form"         "$(coloned fd00 0 0 0 0 0 0 1)"
must_flag "$a" "IPv6 unique local in brackets"        "[$(coloned fd00 '' 5)]:5432"
must_flag "$a" "IPv6 unique local prefix"             "$(coloned fd00 '' '')/8"

# --- Text that must pass -------------------------------------------------
must_pass "$a" "documentation range 1"                "$(dotted 192 0 2 5)"
must_pass "$a" "documentation range 2"                "$(dotted 198 51 100 7)"
must_pass "$a" "documentation range 3"                "$(dotted 203 0 113 9)"
must_pass "$a" "documentation range, IPv6"            "$(coloned 2001 db8 '' 1)"
must_pass "$a" "loopback"                             "$(dotted 127 0 0 1)"
must_pass "$a" "loopback, IPv6"                       "$(coloned '' '' 1)"
must_pass "$a" "unspecified address"                  "$(dotted 0 0 0 0):5432"
must_pass "$a" "just below the 12-bit block"          "$(dotted 172 15 255 255)"
must_pass "$a" "just above the 12-bit block"          "$(dotted 172 32 0 1)"
must_pass "$a" "next to the 16-bit block"             "$(dotted 192 169 1 1)"
must_pass "$a" "next to the 8-bit block"              "$(dotted 11 0 0 1)"
must_pass "$a" "next to IPv4 link-local"              "$(dotted 169 253 1 1)"
must_pass "$a" "shared address space, not in scope"   "$(dotted 100 64 0 1)"
must_pass "$a" "five-part number ending like one"     "$(dotted 1 10 0 0 1)"
must_pass "$a" "five-part number starting like one"   "$(dotted 10 1 2 3 4)"
must_pass "$a" "octet out of range"                   "$(dotted 10 0 648 204)"
must_pass "$a" "three-part version"                   "version $(dotted 10 0 1)"
must_pass "$a" "just below IPv6 link-local"           "$(coloned fe7f '' 1)"
must_pass "$a" "just above IPv6 link-local"           "$(coloned fec0 '' 1)"
must_pass "$a" "just below IPv6 unique local"         "$(coloned fbff '' 1)"
must_pass "$a" "just above IPv6 unique local"         "$(coloned fe00 '' 1)"
must_pass "$a" "hardware address"                     "$(coloned fe 80 00 11 22 33)"
must_pass "$a" "hexadecimal text before a colon"      "0000$(coloned fd00 ' 4865 6c6c')"
must_pass "$a" "hexadecimal word, one colon"          "$(coloned fd00 12)"

# --- Secrets -------------------------------------------------------------
s="$secrets_config"
key_body="$(head -c 600 /dev/urandom | base64 | tr -d '\n' | head -c 640)"
must_flag "$s" "private key block" \
    "$(printf -- '-----BEGIN %s KEY-----\n%s\n-----END %s KEY-----' 'RSA PRIVATE' "$key_body" 'RSA PRIVATE')"
must_flag "$s" "cloud access key id" \
    "aws_access_key_id = $(printf '%s%s' 'AKIA' 'Z7VRSQ5TJN2XMPLK')"
must_pass "$s" "ordinary configuration" \
    "listen: $(dotted 192 0 2 5):5432"

if [[ "$failures" -ne 0 ]]; then
    echo "selftest: $failures of $checks checks failed" >&2
    exit 1
fi
echo "selftest: all $checks checks passed"
