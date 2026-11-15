#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The detection corpus, the part that runs in the client container.
# tests/corpus/run.sh starts it, explains the cases, and judges what this
# script reports together with the events of pgsnare.
#
# Usage: client.sh VERSION
#
# Environment, each a connection string without a database:
#   CORPUS_DIRECT   PostgreSQL VERSION itself
#   CORPUS_PROXIED  the same database through pgsnare
#   CORPUS_RULED    through a listener of pgsnare that the SQL rules apply to
#
# It makes two databases, `corpus_alert` with the values of the tokens that
# alert and `corpus_kill` with those of the tokens that kill, by the
# connection that does not pass through pgsnare. A value is therefore never
# part of a statement of a case: pgsnare reads statements as well, and a
# value in one would be a hit whatever the database answers.
#
# Then it runs every case in every mode against both databases, each run
# with an application name of its own, which the events of pgsnare carry.
# For each run it prints one line:
#
#   run APPLICATION EVENT ID STATE CASE MODE ACTION REASON...
#
# EVENT and ID say what pgsnare must have raised for the run: `token_hit`
# and the id of the token, `rule_hit` and the id of the rule, or `none -`
# for a known gap. STATE is `ok`, `failed` with the reason, or `notrun` for
# a mode the case cannot run in. What the client can see is judged here:
#
#   - A run that must end the session (kill): the session ended before its
#     last statement, and nothing the client received holds the value as it
#     is written, in hexadecimal or in base64.
#   - Every other run: the session lived to its last statement, and a
#     statement failed exactly when the case says that one does.
#
# The last line is `end VERSION CASES`. A case with a broken header gives a
# line `invalid CASE REASON`, and the script ends with status 1.

set -eu

version="${1:?Usage: client.sh VERSION}"
here="$(dirname "$0")"
direct="${CORPUS_DIRECT:?run the corpus with tests/corpus/run.sh}"
proxied="${CORPUS_PROXIED:?run the corpus with tests/corpus/run.sh}"
ruled="${CORPUS_RULED:?run the corpus with tests/corpus/run.sh}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# What a session prints with its last statement: here for psql and the
# tools, and in tests/differential/wire.pl for the extended protocol.
still_open="the session is still open"

# The header lines a case may have.
known=" label describe token modes needs arguments rule expect rows pipeline gap-in kill-passes setup "

# value_of TOKEN ACTION: the value of a token. tests/proxy/setup.sh gives
# pgsnare the same values, as the tokens corpus-alert, corpus-kill,
# corpus-typed-alert and corpus-typed-kill.
value_of() {
    case "$1-$2" in
        plain-alert) echo "corpus-bait-alert-c41f07e9" ;;
        plain-kill) echo "corpus-bait-kill-8d2b56a3" ;;
        typed-alert) echo "7c1e4b02-93a5-4d6f-8e17-5ab0c3d2f619" ;;
        typed-kill) echo "e85d0a34-1f7b-4c29-b6e0-92d4718a3c5f" ;;
    esac
}

# id_of TOKEN ACTION: the id of that token.
id_of() {
    if [ "$1" = typed ]; then
        echo "corpus-typed-$2"
    else
        echo "corpus-$2"
    fi
}

# sql CONNINFO ARGUMENTS...: psql, with nothing but the answers in its output.
sql() {
    target="$1"
    shift
    psql --no-psqlrc --no-password --quiet --tuples-only --no-align --dbname "$target" "$@"
}

# hex TEXT: TEXT in lowercase hexadecimal, as wire.pl prints a message.
hex() {
    printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'
}

# holds FILE TEXT: whether FILE holds TEXT as it is written, in hexadecimal
# of either case, or in base64.
holds() {
    lower="$(hex "$2")"
    upper="$(printf '%s' "$lower" | tr 'a-f' 'A-F')"
    encoded="$(printf '%s' "$2" | base64 | tr -d '\n')"
    for form in "$2" "$lower" "$upper" "$encoded"; do
        if grep -qaF -- "$form" "$1"; then
            return 0
        fi
    done
    return 1
}

# header NAME: the values of the header lines NAME of the case at hand.
header() {
    sed -n "s/^-- $1:[[:space:]]*//p" "$case"
}

# run_sql MODE CONNINFO: runs the statements of $work/body.sql in one
# session, and one more statement after them that tells whether the session
# is still there. What the client received goes to $work/out.
settings=""
run_sql() {
    case "$1" in
        simple)
            {
                cat "$work/body.sql"
                printf "\nSELECT 'the session' || ' is still open';\n"
            } | sql "$2" >"$work/out" 2>&1
            ;;
        extended-text)
            # shellcheck disable=SC2086
            perl /differential/wire.pl "$2" script "$work/body.sql" text $settings >"$work/out" 2>&1
            ;;
        extended-binary)
            # shellcheck disable=SC2086
            perl /differential/wire.pl "$2" script "$work/body.sql" binary $settings >"$work/out" 2>&1
            ;;
    esac
}

# --- The databases ------------------------------------------------------------

for action in alert kill; do
    if ! sql "$direct dbname=postgres" --set ON_ERROR_STOP=1 \
        --command "CREATE DATABASE corpus_$action" >"$work/setup" 2>&1 \
        || ! sql "$direct dbname=corpus_$action" --set ON_ERROR_STOP=1 \
            --set token="$(value_of plain "$action")" --set typed="$(value_of typed "$action")" \
            --file "$here/schema.sql" >"$work/setup" 2>&1; then
        echo "corpus: the databases of the cases could not be made in PostgreSQL $version:" >&2
        sed 's/^/    /' "$work/setup" >&2
        exit 1
    fi
done

# The search for a value must find it where it is, and so must the search
# for the last statement of a session: PostgreSQL itself sends both, in
# every mode.
echo "SELECT v FROM bait;" >"$work/body.sql"
for mode in simple extended-text extended-binary; do
    run_sql "$mode" "$direct dbname=corpus_kill" || true
    if ! holds "$work/out" "$(value_of plain kill)" || ! holds "$work/out" "$still_open"; then
        echo "corpus: the search does not find a value or the end of a session in what PostgreSQL $version itself sends ($mode)" >&2
        exit 1
    fi
done

# --- The cases ----------------------------------------------------------------

numbers=" "
cases=0
invalid=0
for case in "$here"/cases/*.sql; do
    name="$(basename "$case" .sql)"
    number="${name%%-*}"
    cases=$((cases + 1))

    label="$(header label)"
    describe="$(header describe)"
    token="$(header token)"
    token="${token:-plain}"
    modes="$(header modes)"
    modes="${modes:-simple extended-text extended-binary}"
    needs="$(header needs)"
    arguments="$(header arguments)"
    rule="$(header rule)"
    expect="$(header expect)"
    rows="$(header rows)"
    pipeline="$(header pipeline)"
    gap_in="$(header gap-in)"
    kill_passes="$(header kill-passes)"

    problem=""
    case "$number" in
        '' | *[!0-9]*) problem="its name does not begin with a number" ;;
    esac
    case "$numbers" in
        *" $number "*) problem="another case has its number" ;;
    esac
    numbers="$numbers$number "
    for line in $(sed -n 's/^-- \([a-z-]*\):.*/\1/p' "$case"); do
        case "$known" in
            *" $line "*) ;;
            *) problem="its header has a line that is not known: $line" ;;
        esac
    done
    case "$label" in
        hit | gap) ;;
        *) problem="its label is not one of hit and gap" ;;
    esac
    if [ -z "$describe" ]; then
        problem="it has no description"
    fi
    case "$token" in
        plain | typed) ;;
        *) problem="its token is not one of plain and typed" ;;
    esac
    for mode in $modes $gap_in; do
        case "$mode" in
            simple | extended-text | extended-binary) ;;
            *) problem="it names a mode that does not exist: $mode" ;;
        esac
    done
    case "$needs" in
        '') ;;
        pg_dump | replication | login)
            # A tool speaks the protocol it chooses, once.
            if [ "$modes" != simple ]; then
                problem="it runs a tool, and must say that it runs in the mode simple only"
            fi
            ;;
        rules) ;;
        *) problem="it needs something that is not known: $needs" ;;
    esac
    rule_id="${rule%% *}"
    rule_response="${rule##* }"
    if [ "$needs" = rules ]; then
        case "$rule_response" in
            alert | kill) ;;
            *) problem="it must name the rule and what the rule does: alert or kill" ;;
        esac
    elif [ -n "$rule" ]; then
        problem="it names a rule and does not say that it needs the rules"
    fi
    case "$expect" in
        '' | error) ;;
        *) problem="it expects something that is not known: $expect" ;;
    esac
    settings=""
    if [ -n "$pipeline" ]; then
        if [ "$pipeline" != yes ]; then
            problem="its line pipeline does not say yes"
        fi
        settings="pipeline"
    fi
    if [ -n "$rows" ]; then
        case "$rows" in
            *[!0-9]*) problem="its line rows is not a number" ;;
        esac
        settings="$settings rows=$rows"
    fi
    if [ -n "$settings" ]; then
        case " $modes " in
            *" simple "*) problem="it uses what only the extended protocol has, and must leave out the mode simple" ;;
        esac
    fi
    if [ -n "$problem" ]; then
        echo "invalid $name $problem"
        invalid=1
        continue
    fi

    grep -v '^--' "$case" >"$work/body.sql" || true

    for action in alert kill; do
        # What a rule does is the rule's own, not a token's: one round.
        if [ -n "$rule" ] && [ "$action" = kill ]; then
            continue
        fi
        for mode in simple extended-text extended-binary; do
            case "$mode" in
                simple) letter=s ;;
                extended-text) letter=t ;;
                *) letter=b ;;
            esac
            app="corpus-$version-$number-$letter-$(printf '%.1s' "$action")"
            case " $modes " in
                *" $mode "*) ;;
                *)
                    echo "run $app none - notrun $name $mode $action"
                    continue
                    ;;
            esac

            # What the run must raise, and whether it must end the session.
            event=none
            id=-
            ends=no
            if [ "$label" = hit ]; then
                case " $gap_in " in
                    *" $mode "*) ;;
                    *)
                        if [ -n "$rule" ]; then
                            event=rule_hit
                            id="$rule_id"
                            ends="$rule_response"
                        else
                            event=token_hit
                            id="$(id_of "$token" "$action")"
                            ends="$action"
                        fi
                        ;;
                esac
            fi

            base="$proxied"
            if [ -n "$rule" ]; then
                base="$ruled"
            fi
            conninfo="$base dbname=corpus_$action application_name=$app"
            value="$(value_of "$token" "$action")"
            reason=""
            status=0
            : >"$work/out"

            if grep -q '^-- setup:' "$case" \
                && ! header setup | sql "$direct dbname=corpus_$action" --set ON_ERROR_STOP=1 >/dev/null 2>&1; then
                reason="its setup failed"
            fi

            if [ -z "$reason" ]; then
                case "$needs" in
                    pg_dump)
                        # shellcheck disable=SC2086
                        if pg_dump --no-password --dbname "$conninfo" $arguments >"$work/out" 2>&1; then
                            echo "$still_open" >>"$work/out"
                        else
                            status=$?
                        fi
                        ;;
                    replication)
                        # The stream ends by itself at the last change the
                        # slot holds: its setup made one.
                        slot="corpus_${action}_stream"
                        last="$(sql "$direct dbname=corpus_$action" --command "SELECT lsn
                            FROM pg_logical_slot_peek_changes('$slot', NULL, NULL, 'skip-empty-xacts', '1')
                            ORDER BY lsn DESC LIMIT 1" 2>/dev/null)" || last=""
                        if [ -z "$last" ]; then
                            reason="its slot holds no change to stream"
                        elif timeout 60 pg_recvlogical --no-password --dbname "$conninfo" --slot "$slot" \
                            --start --endpos "$last" --no-loop --file - \
                            --option include-xids=0 --option skip-empty-xacts=1 >"$work/out" 2>&1; then
                            echo "$still_open" >>"$work/out"
                        else
                            status=$?
                        fi
                        ;;
                    login)
                        env PGPASSWORD="$value" psql --no-psqlrc --no-password --quiet --tuples-only \
                            --no-align --dbname "$conninfo" --command "SELECT 1" >"$work/out" 2>&1 || status=$?
                        # Without pgsnare this login ends when the database
                        # refuses the password, and that is all of the run.
                        if grep -q 'password authentication failed' "$work/out"; then
                            echo "$still_open" >>"$work/out"
                        fi
                        ;;
                    *)
                        run_sql "$mode" "$conninfo" || status=$?
                        ;;
                esac
            fi

            if [ -z "$reason" ]; then
                alive=no
                if holds "$work/out" "$still_open"; then
                    alive=yes
                fi
                failing=no
                if [ "$mode" = simple ]; then
                    if grep -qa 'ERROR:  ' "$work/out"; then
                        failing=yes
                    fi
                elif grep -q '^E ' "$work/out"; then
                    failing=yes
                fi
                if [ "$ends" = kill ]; then
                    if [ "$alive" = yes ] || [ "$status" -eq 0 ]; then
                        reason="the session was not ended"
                    elif [ "$event" = token_hit ] && holds "$work/out" "$value"; then
                        reason="a form of the value reached the client"
                    elif [ -n "$kill_passes" ] && [ "$mode" != simple ] \
                        && ! holds "$work/out" "$kill_passes"; then
                        reason="nothing of the message reached the client before the session ended, and the case says that the beginning does"
                    fi
                elif [ "$alive" = no ]; then
                    reason="the session did not get to its last statement"
                elif [ "$expect" = error ] && [ "$failing" = no ]; then
                    reason="no statement failed, and the case says that one does"
                elif [ "$expect" != error ] && [ "$failing" = yes ]; then
                    reason="a statement failed"
                fi
            fi

            if [ -n "$reason" ]; then
                echo "run $app $event $id failed $name $mode $action $reason"
                {
                    echo "corpus: PostgreSQL $version: $name ($mode, $action): $reason. What the client received begins:"
                    head -c 2000 "$work/out" | tr -c '[:print:]\n' '?' | cut -c1-240 | head -n 8 | sed 's/^/    /'
                } >&2
            else
                echo "run $app $event $id ok $name $mode $action"
            fi
        done
    done
done

echo "end $version $cases"

# The databases go, and their replication slots with them. Nothing depends
# on it: the run that follows makes the databases of another server.
for action in alert kill; do
    sql "$direct dbname=postgres" --command "DROP DATABASE IF EXISTS corpus_$action WITH (FORCE)" \
        >/dev/null 2>&1 || true
done

exit "$invalid"
