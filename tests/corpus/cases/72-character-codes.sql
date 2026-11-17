-- label: gap
-- describe: The value as the numbers of its characters.

SELECT array_agg(ascii(substr(v, i, 1)) ORDER BY i) FROM bait, generate_series(1, length(v)) AS i WHERE n = 2;
