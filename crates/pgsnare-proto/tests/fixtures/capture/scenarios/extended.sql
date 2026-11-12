-- SPDX-License-Identifier: Apache-2.0
--
-- Extended query protocol, driven by the meta-commands of psql 18:
-- unnamed and named statements, a description, a close, an error and a
-- pipeline. Every value is synthetic.

SELECT $1::int + $2::int AS sum \bind 40 2 \g

SELECT id, email FROM contacts WHERE id = $1 \parse by_id
\bind_named by_id 1 \g
\bind_named by_id 2 \g
SELECT 1 AS a, 'x'::text AS b \gdesc
\close_prepared by_id

-- An error in the middle of the extended protocol.
SELECT 1/$1::int AS quotient \bind 0 \g

CREATE TEMP TABLE scratch (id int PRIMARY KEY, email text, note text);
INSERT INTO scratch (id, email, note) VALUES ($1, $2, $3) \bind 4 'dave@example.com' 'added by the fixture' \g

\startpipeline
SELECT $1::int AS a \bind 1 \sendpipeline
SELECT $1::int AS b \bind 2 \sendpipeline
\syncpipeline
SELECT $1::text AS c \bind 'three' \sendpipeline
\endpipeline
