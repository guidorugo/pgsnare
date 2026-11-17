-- What the cases of the detection corpus read: tests/corpus/run.sh.
--
-- tests/corpus/client.sh runs this in a database of its own for each
-- response, by a connection that does not pass through pgsnare, and gives
-- the values: `token` is a honeytoken of the tests, and `typed` is one that
-- is written as a UUID.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- The value is in the second of three rows, so that a result has a row
-- before it and a row after it.
CREATE TABLE bait (v text, n integer);
INSERT INTO bait VALUES ('an ordinary row', 1), (:'token', 2), ('another ordinary row', 3);

CREATE TABLE bait_typed (u uuid, n integer);
INSERT INTO bait_typed VALUES (:'typed', 1);

-- A field that is larger than the largest message pgsnare holds back
-- (1 MiB), with the value near its end.
CREATE TABLE bait_large (doc text);
INSERT INTO bait_large VALUES (repeat('x', 2097152) || :'token' || repeat('y', 4096));

CREATE TABLE products (id integer, name text);
INSERT INTO products VALUES (1, 'a product'), (2, 'another product');

CREATE VIEW bait_view AS SELECT v AS note FROM bait;
CREATE MATERIALIZED VIEW bait_copy AS SELECT v FROM bait;
CREATE FUNCTION bait_function() RETURNS SETOF text LANGUAGE sql AS 'SELECT v FROM bait';

-- A replication slot, and a change of the row for it to hold.
SELECT pg_create_logical_replication_slot(current_database() || '_slot', 'test_decoding');
UPDATE bait SET n = n;
