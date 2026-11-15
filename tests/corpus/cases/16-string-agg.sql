-- label: hit
-- describe: All values joined into one string.

SELECT string_agg(v, ',') FROM bait;
