-- label: hit
-- describe: A notice with the value as its message.

DO $$ BEGIN RAISE NOTICE '%', (SELECT v FROM bait WHERE n = 2); END $$;
