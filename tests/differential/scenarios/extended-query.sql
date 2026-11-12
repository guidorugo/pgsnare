-- SPDX-License-Identifier: Apache-2.0
--
-- The extended query protocol: Parse, Bind, Describe, Execute, Close and
-- Sync, with unnamed and named statements.

SELECT $1::int + $2::int AS sum \bind 40 2 \g

SELECT $1::text AS word, length($1) AS len \bind 'pgsnare' \g

SELECT $1::int AS n WHERE $1::int > 5 \bind 3 \g

SELECT $1::int * 2 AS doubled \parse double_it
\bind_named double_it 21 \g
\bind_named double_it 4 \g
\close_prepared double_it

-- An error in the extended protocol, and the statement after it.
SELECT $1::int / 0 AS boom \bind 1 \g
SELECT $1::text AS still_working \bind 'yes' \g
