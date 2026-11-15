-- label: hit
-- describe: A cursor, fetched one row at a time.

BEGIN;
DECLARE corpus_cursor CURSOR FOR SELECT v FROM bait ORDER BY n;
FETCH 1 FROM corpus_cursor;
FETCH 1 FROM corpus_cursor;
FETCH 1 FROM corpus_cursor;
COMMIT;
