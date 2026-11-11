# SPDX-License-Identifier: Apache-2.0
#
# Sourced by the image's entrypoint while the server is being initialised.
# It selects the login method by role, so that the capture sees SCRAM, MD5
# and cleartext password logins against one server.

cat > "$PGDATA/pg_hba.conf" <<'HBA'
local   all   all                trust
host    all   app_md5     all    md5
host    all   app_plain   all    password
host    all   all         all    scram-sha-256
HBA
