-- label: hit
-- describe: A UNION added to a query of another table, as an SQL injection adds one.

SELECT name FROM products WHERE id = -1 UNION ALL SELECT v FROM bait;
