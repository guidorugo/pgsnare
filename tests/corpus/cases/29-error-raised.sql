-- label: hit
-- describe: An error that code in the database raises with the value as its message.
-- expect: error

DO $$ BEGIN RAISE EXCEPTION '%', (SELECT v FROM bait WHERE n = 2); END $$;
