-- label: hit
-- describe: Each row as a JSON object.

SELECT row_to_json(b) FROM bait AS b;
