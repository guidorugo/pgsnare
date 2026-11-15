-- label: hit
-- describe: Error-based injection: a cast that fails, and the error message quotes the value.
-- expect: error

SELECT v::integer FROM bait WHERE n = 2;
