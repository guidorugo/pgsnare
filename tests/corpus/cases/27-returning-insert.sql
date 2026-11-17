-- label: hit
-- describe: INSERT with a RETURNING clause, undone afterwards.

BEGIN;
INSERT INTO bait SELECT v, n FROM bait RETURNING v;
ROLLBACK;
