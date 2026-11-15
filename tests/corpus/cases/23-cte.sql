-- label: hit
-- describe: A common table expression.

WITH taken AS (SELECT v FROM bait) SELECT v FROM taken;
