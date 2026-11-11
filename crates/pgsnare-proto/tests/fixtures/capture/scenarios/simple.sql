-- SPDX-License-Identifier: Apache-2.0
--
-- Simple query protocol: results, command tags, errors, a notice, a
-- parameter change and a notification. Every value is synthetic.

SELECT 1 AS one, 'text' AS t, NULL::int AS n, ''::text AS empty;
SELECT id, email, note FROM contacts ORDER BY id;
SELECT repeat('x', 1500) AS wide;
SELECT 1 AS first \; SELECT 2 AS second;

CREATE TEMP TABLE scratch (id int PRIMARY KEY, label text);
BEGIN;
INSERT INTO scratch (id, label) VALUES (1, 'one'), (2, 'two'), (3, 'three');
UPDATE scratch SET label = upper(label) WHERE id <= 2;
DELETE FROM scratch WHERE id = 3;
SELECT count(*) FROM scratch;
COMMIT;

-- An error inside a transaction block, and the state it leaves behind.
BEGIN;
SELECT 1/0;
SELECT 1;
ROLLBACK;

-- A syntax error, reported with a cursor position.
SELEC 1;

DO $$ BEGIN RAISE NOTICE 'synthetic notice'; END $$;
SET application_name = 'fixture';
LISTEN fixture_channel;
NOTIFY fixture_channel, 'synthetic payload';
DROP TABLE scratch;
