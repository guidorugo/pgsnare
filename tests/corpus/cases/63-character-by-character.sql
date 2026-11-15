-- label: gap
-- describe: One character of the value in each row.

SELECT substr(v, i, 1) FROM bait, generate_series(1, length(v)) AS i WHERE n = 2 ORDER BY i;
