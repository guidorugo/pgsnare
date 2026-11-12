-- SPDX-License-Identifier: Apache-2.0
--
-- The simple query protocol: one statement, several statements in one
-- message, a wide row and a long result.

SELECT 1 AS one, 'two' AS two, NULL AS nothing;

SELECT generate_series(1, 5) AS n;

SELECT 1 AS first \; SELECT 2 AS second \; SELECT 3 AS third;

SELECT repeat('0123456789', 5000) AS wide;

SELECT n, md5(n::text) AS digest FROM generate_series(1, 2000) AS n;

SELECT '{"a": [1, 2, {"b": null}]}'::jsonb AS document, ARRAY['x', 'y'] AS list, ROW(1, 'r') AS record;
