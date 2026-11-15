-- label: hit
-- describe: COPY of a query.

COPY (SELECT v FROM bait WHERE n = 2) TO STDOUT;
