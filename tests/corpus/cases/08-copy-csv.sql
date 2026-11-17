-- label: hit
-- describe: COPY in CSV format.

COPY bait TO STDOUT WITH (FORMAT csv, HEADER);
