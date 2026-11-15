-- label: hit
-- describe: Three statements sent ahead of their answers, with one Sync. The simple protocol has no pipeline.
-- modes: extended-text extended-binary
-- pipeline: yes

SELECT 1;
SELECT v FROM bait;
SELECT 2;
