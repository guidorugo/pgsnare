-- label: hit
-- describe: A warning that carries the value in its detail field.

DO $$ BEGIN RAISE WARNING 'a warning' USING DETAIL = (SELECT v FROM bait WHERE n = 2); END $$;
