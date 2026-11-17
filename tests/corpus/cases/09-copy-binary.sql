-- label: hit
-- describe: COPY in binary format. A text column is the same bytes there.

COPY bait TO STDOUT WITH (FORMAT binary);
