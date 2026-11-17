-- label: gap
-- describe: A listed function called from code in a string, which the rules do not read. The statement is a parse failure, and no rule fires.
-- needs: rules
-- rule: functions kill

DO $$ BEGIN PERFORM pg_sleep(0); END $$;
