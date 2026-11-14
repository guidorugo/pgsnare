#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Checks what `pgsnare token generate` prints against PostgreSQL itself.
# It runs in the client container of the integration tests, which has the
# pgsnare binary and psql: `make itest`.
#
# For every PostgreSQL version it is given:
#
#   1. Names that try to get out of their quotes. A table and two columns
#      are created with such names by psql, which quotes them itself. The
#      whole output of `token generate` for those names is then run by
#      psql. It must run without an error, put its rows into that table,
#      and leave alone the table that the names try to drop.
#   2. The SCRAM-SHA-256 bait. A role is created with the bait as its
#      password. PostgreSQL stores a password as it is only when it reads
#      it as a SCRAM verifier, and hashes anything else. So the stored
#      password must be the bait itself.
#   3. The bcrypt bait. pgcrypto must take it as the salt of a hash, which
#      is how a stored hash is checked, and give back a hash with the same
#      version, cost and salt.
#
# A pass has to mean something, so each check is also made on input that
# must fail it: a name that is not quoted, a verifier with a key that is
# too short, and a salt with a character outside its alphabet.
#
# Usage: check.sh VERSION...
# Environment: PGPASSWORD

set -eu

failed=0
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
    echo "bait: FAILED: $*" >&2
    failed=1
}

# The names. In each, something would end the quotes it is written in and
# drop a table, if it were not quoted for where it stands.
table='itest bait "; DROP TABLE itest_bait_sentinel; -- é'
name_column='na"me'
email_column="e-mail'); DROP TABLE itest_bait_sentinel; --"

# The same names as the command line takes them: a part between double
# quotes, with a double quote in it written twice.
quoted() {
    printf '"%s"' "$(printf '%s' "$1" | sed 's/"/""/g')"
}

for version in "$@"; do
    database="host=pg$version port=5432 user=postgres sslmode=disable dbname=postgres"

    # sql ARGUMENTS...: runs psql and prints results bare. Notices, such
    # as the one about a table that is not there to drop, are left out.
    sql() {
        PGOPTIONS='-c client_min_messages=warning' \
            psql --no-psqlrc --no-password --quiet --tuples-only --no-align \
            --set ON_ERROR_STOP=1 \
            --set table="$table" --set name_column="$name_column" \
            --set email_column="$email_column" \
            --dbname "$database" "$@"
    }

    # --- 1. Names that try to get out of their quotes ----------------------

    sql --command 'DROP TABLE IF EXISTS itest_bait_sentinel' \
        --command 'CREATE TABLE itest_bait_sentinel (id int)' >/dev/null
    # psql quotes the names itself here, with :"name".
    echo 'DROP TABLE IF EXISTS :"table";
CREATE TABLE :"table" (:"name_column" text, :"email_column" text);' | sql --file - >/dev/null

    pgsnare token generate --kind identity --count 3 --domain mail.example \
        --table "$(quoted "$table")" \
        --column "$(quoted "$name_column")" --column "$(quoted "$email_column")" \
        > "$work/identity.sql"

    # Printable ASCII only, whatever the names are made of.
    if LC_ALL=C grep -q '[^ -~]' "$work/identity.sql"; then
        fail "PostgreSQL $version: the script is not plain ASCII"
    fi
    if ! psql --no-psqlrc --no-password --quiet --set ON_ERROR_STOP=1 \
        --dbname "$database" --file "$work/identity.sql" > "$work/out" 2>&1 \
        || [ -s "$work/out" ]; then
        fail "PostgreSQL $version: the script did not run cleanly:"
        sed 's/^/    /' "$work/out" >&2
    fi
    rows="$(echo 'SELECT count(*) FROM :"table"
WHERE :"email_column" = :"name_column" || '"'@mail.example'"';' | sql --file -)"
    if [ "$rows" != "3" ]; then
        fail "PostgreSQL $version: expected 3 planted rows, found $rows"
    fi
    if [ "$(sql --command "SELECT to_regclass('itest_bait_sentinel') IS NOT NULL")" != "t" ]; then
        fail "PostgreSQL $version: a name got out of its quotes and dropped a table"
    fi

    # The same statement with the table name written as it is must not
    # pass: this is what the check above would let through if the names
    # were harmless.
    {
        printf 'INSERT INTO "%s" DEFAULT VALUES;\n' "$table"
    } > "$work/unquoted.sql"
    psql --no-psqlrc --no-password --quiet --dbname "$database" \
        --file "$work/unquoted.sql" > /dev/null 2>&1 || true
    if [ "$(sql --command "SELECT to_regclass('itest_bait_sentinel') IS NOT NULL")" != "f" ]; then
        fail "PostgreSQL $version: the names of this test are harmless, so it shows nothing"
    fi
    echo 'DROP TABLE IF EXISTS :"table";' | sql --file - >/dev/null
    sql --command 'DROP TABLE IF EXISTS itest_bait_sentinel' >/dev/null

    # --- 2. SCRAM-SHA-256 ---------------------------------------------------

    sql --command 'DROP TABLE IF EXISTS itest_bait_values' \
        --command 'CREATE TABLE itest_bait_values (kind text, value text)' \
        --command 'DROP ROLE IF EXISTS itest_bait_role' >/dev/null
    for kind in scram-sha-256 bcrypt; do
        pgsnare token generate --kind "$kind" --table itest_bait_values --column value \
            > "$work/$kind.sql"
        psql --no-psqlrc --no-password --quiet --set ON_ERROR_STOP=1 \
            --dbname "$database" --file "$work/$kind.sql"
        sql --command "UPDATE itest_bait_values SET kind = '$kind' WHERE kind IS NULL" >/dev/null
    done

    # stored PASSWORD: whether PostgreSQL stores this password as it is.
    stored() {
        sql --set password="$1" --file - <<'SQL'
DROP ROLE IF EXISTS itest_bait_role;
SELECT format('CREATE ROLE itest_bait_role PASSWORD %L', :'password') \gexec
SELECT rolpassword = :'password' FROM pg_authid WHERE rolname = 'itest_bait_role';
DROP ROLE itest_bait_role;
SQL
    }
    verifier="$(sql --command "SELECT value FROM itest_bait_values WHERE kind = 'scram-sha-256'")"
    if [ "$(stored "$verifier")" != "t" ]; then
        fail "PostgreSQL $version: the SCRAM-SHA-256 bait is not read as a verifier"
    fi
    # A verifier whose keys are too short is no verifier: it is hashed.
    if [ "$(stored 'SCRAM-SHA-256$4096:AQEBAQEBAQEBAQEBAQEBAQ==$AQEB:AQEB')" != "f" ]; then
        fail "PostgreSQL $version: a broken verifier is stored as it is, so this check shows nothing"
    fi

    # --- 3. bcrypt -----------------------------------------------------------

    sql --command 'CREATE EXTENSION IF NOT EXISTS pgcrypto' >/dev/null
    # salted HASH: whether pgcrypto takes the hash as a salt, and gives a
    # hash that begins with the same version, cost and salt.
    salted() {
        sql --set hash="$1" --file - 2>/dev/null <<'SQL' || echo error
SELECT length(crypt('any password', :'hash')) = 60
   AND left(crypt('any password', :'hash'), 29) = left(:'hash', 29);
SQL
    }
    hash="$(sql --command "SELECT value FROM itest_bait_values WHERE kind = 'bcrypt'")"
    if [ "$(salted "$hash")" != "t" ]; then
        fail "PostgreSQL $version: pgcrypto does not take the bcrypt bait as a salt"
    fi
    # A salt with a character outside the alphabet of bcrypt is refused.
    broken="$(printf '%s' "$hash" | sed 's/^\(.\{10\}\)./\1!/')"
    if [ "$(salted "$broken")" != "error" ]; then
        fail "PostgreSQL $version: pgcrypto takes a broken salt, so this check shows nothing"
    fi
    sql --command 'DROP EXTENSION pgcrypto' \
        --command 'DROP TABLE itest_bait_values' >/dev/null

    if [ "$failed" -eq 0 ]; then
        echo "bait: PostgreSQL $version: the names stay in their quotes, and the SCRAM-SHA-256 and bcrypt bait are taken"
    fi
done

exit "$failed"
