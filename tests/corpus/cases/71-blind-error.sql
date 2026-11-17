-- label: gap
-- describe: Blind extraction: whether the statement fails tells one bit of the value.
-- expect: error

SELECT 1 / (CASE WHEN v LIKE 'c%' THEN 0 ELSE 1 END) FROM bait WHERE n = 2;
