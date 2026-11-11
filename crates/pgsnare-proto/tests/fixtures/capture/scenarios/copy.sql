-- SPDX-License-Identifier: Apache-2.0
--
-- COPY in both directions, in text, CSV and binary form, and a COPY that
-- the server rejects. Every value is synthetic.

COPY (SELECT id, email, note FROM contacts WHERE id <= 3 ORDER BY id) TO STDOUT;
COPY (SELECT id, email, note FROM contacts WHERE id <= 3 ORDER BY id) TO STDOUT (FORMAT csv, HEADER);
COPY (SELECT id, email, note FROM contacts WHERE id <= 3 ORDER BY id) TO STDOUT (FORMAT binary);

CREATE TEMP TABLE scratch (id int PRIMARY KEY, label text);
COPY scratch FROM STDIN;
1	one
2	two
\.
COPY scratch FROM STDIN (FORMAT csv);
3,three
not-a-number,four
\.
SELECT count(*) FROM scratch;
