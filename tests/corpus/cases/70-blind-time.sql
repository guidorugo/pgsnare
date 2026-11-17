-- label: gap
-- describe: Blind extraction: the time the answer takes tells one bit of the value.

SELECT CASE WHEN v LIKE 'c%' THEN pg_sleep(0.05) END FROM bait WHERE n = 2;
