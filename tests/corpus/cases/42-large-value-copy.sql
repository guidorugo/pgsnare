-- label: hit
-- describe: The same field of two megabytes, read with COPY.
-- kill-passes: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

COPY bait_large TO STDOUT;
