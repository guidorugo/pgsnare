-- label: hit
-- describe: The rows copied to a temporary table and read from there.

CREATE TEMPORARY TABLE staged AS SELECT v FROM bait;
SELECT v FROM staged;
