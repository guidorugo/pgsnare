-- label: hit
-- describe: DELETE with a RETURNING clause, undone afterwards.

BEGIN;
DELETE FROM bait RETURNING v;
ROLLBACK;
