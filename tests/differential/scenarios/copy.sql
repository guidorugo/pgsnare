-- SPDX-License-Identifier: Apache-2.0
--
-- COPY in both directions, in text and CSV format.

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
