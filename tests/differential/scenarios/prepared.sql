-- SPDX-License-Identifier: Apache-2.0
--
-- Prepared statements, made with SQL and made by the protocol.

PREPARE by_id (int) AS SELECT $1 AS id, 'row ' || $1 AS label;
EXECUTE by_id(1);
EXECUTE by_id(2);
SELECT name, statement, parameter_types FROM pg_prepared_statements ORDER BY name;
DEALLOCATE by_id;
EXECUTE by_id(3);

-- A statement the protocol prepared lives on across transactions.
SELECT $1::int + 1 AS next \parse next_one
BEGIN;
\bind_named next_one 1 \g
ROLLBACK;
\bind_named next_one 41 \g
SELECT name, from_sql FROM pg_prepared_statements ORDER BY name;
\close_prepared next_one
\bind_named next_one 1 \g

-- A statement with parameters of several types.
SELECT $1::text AS word, $2::numeric * 2 AS doubled, $3::date + 1 AS next_day, $4::bool AS flag \parse several
\bind_named several 'pgsnare' 1.5 '2026-01-31' true \g
