-- label: hit
-- describe: All rows as one JSON array.

SELECT json_agg(b) FROM bait AS b;
