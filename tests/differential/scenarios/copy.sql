-- SPDX-License-Identifier: Apache-2.0
--
-- COPY in both directions, in text, CSV and binary format.

CREATE TABLE item (id int, name text, note text);

COPY item FROM STDIN;
1	alpha	first
2	beta	\N
\.

COPY item FROM STDIN WITH (FORMAT csv, HEADER true);
id,name,note
3,"gamma, with comma","a ""quoted"" note"
4,delta,
\.

COPY item TO STDOUT;

COPY item TO STDOUT WITH (FORMAT csv, HEADER true);

COPY (SELECT id, upper(name) AS name FROM item ORDER BY id DESC) TO STDOUT;

-- A COPY that fails part of the way through.
COPY item FROM STDIN;
5	epsilon	fine
not-a-number	zeta	broken
\.

SELECT count(*) AS items FROM item;

-- Binary format: out through the client into a file, and in again.
\copy item to '/tmp/pgsnare-scenario-items.bin' with (format binary)
CREATE TABLE item_again (LIKE item);
\copy item_again from '/tmp/pgsnare-scenario-items.bin' with (format binary)
SELECT id, name, note FROM item_again ORDER BY id;

-- Binary format, as the bytes the server sends.
COPY (SELECT id, name FROM item ORDER BY id) TO STDOUT WITH (FORMAT binary);
