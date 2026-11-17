-- label: hit
-- describe: A sub-select in the select list of a query of another table.

SELECT name, (SELECT v FROM bait WHERE n = 2) FROM products;
