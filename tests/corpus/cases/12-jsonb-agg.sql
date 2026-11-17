-- label: hit
-- describe: All values as one jsonb array.

SELECT jsonb_agg(v) FROM bait;
