-- SPDX-License-Identifier: Apache-2.0
--
-- A message of 100 MB in each direction. pgsnare holds a message up to a
-- configured size and passes a larger one on in chunks, so neither of
-- these may be held.

\pset tuples_only on
\pset format unaligned

-- From the server: one row of 100 MB. The client prints its checksum
-- instead of the row.
SELECT repeat('0123456789abcdef', 6553600) \g |md5sum

-- From the client: one statement of 100 MB.
\set large `head -c 104857600 /dev/zero | tr '\0' 'y'`
SELECT length(value) AS received, md5(value) AS digest FROM (SELECT :'large'::text AS value) AS statement;

-- The session is in order afterwards.
SELECT 'still in step' AS state;
