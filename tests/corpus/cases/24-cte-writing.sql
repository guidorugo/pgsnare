-- label: hit
-- describe: A common table expression that writes, read through its RETURNING clause.

WITH touched AS (UPDATE bait SET n = n RETURNING v) SELECT v FROM touched;
