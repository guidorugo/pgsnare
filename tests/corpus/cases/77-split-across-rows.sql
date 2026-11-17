-- label: gap
-- describe: The two halves of the value in two rows. Messages are never joined.

SELECT left(v, 12) FROM bait WHERE n = 2 UNION ALL SELECT substr(v, 13) FROM bait WHERE n = 2;
