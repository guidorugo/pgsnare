-- SPDX-License-Identifier: Apache-2.0
--
-- Cursors, and results fetched in pieces.

BEGIN;
DECLARE numbers SCROLL CURSOR FOR SELECT n FROM generate_series(1, 10) AS n;
FETCH 3 FROM numbers;
FETCH BACKWARD 1 FROM numbers;
MOVE FORWARD 5 IN numbers;
FETCH ALL FROM numbers;
CLOSE numbers;
COMMIT;

\set FETCH_COUNT 4
SELECT n FROM generate_series(1, 10) AS n;
\unset FETCH_COUNT
