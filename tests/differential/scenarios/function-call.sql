-- SPDX-License-Identifier: Apache-2.0
--
-- Function calls: the client drives large objects with FunctionCall
-- messages, which carry binary arguments and results.

\! head -c 300000 /dev/zero | tr '\0' 'z' > /tmp/pgsnare-scenario-object.in
\lo_import /tmp/pgsnare-scenario-object.in
\set imported :LASTOID
SELECT count(*) AS pages, sum(length(data)) AS bytes FROM pg_largeobject WHERE loid = :imported;
\lo_export :imported /tmp/pgsnare-scenario-object.out
\! cmp /tmp/pgsnare-scenario-object.in /tmp/pgsnare-scenario-object.out && echo 'exported what was imported'
\lo_unlink :imported
SELECT count(*) AS left_over FROM pg_largeobject_metadata WHERE oid = :imported;

-- A function call that fails.
\lo_export 1 /tmp/pgsnare-scenario-object.none
SELECT 'still in step' AS state;
