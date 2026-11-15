-- label: hit
-- describe: All rows as one JSON object.

SELECT json_object_agg(n, v) FROM bait;
