-- label: hit
-- describe: A cursor, fetched in one go.

BEGIN;
DECLARE corpus_cursor CURSOR FOR SELECT v FROM bait;
FETCH ALL FROM corpus_cursor;
COMMIT;
