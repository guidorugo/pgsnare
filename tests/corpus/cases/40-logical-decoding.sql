-- label: hit
-- describe: The changes of a replication slot, read with a function instead of a stream.
-- setup: DO $$ BEGIN FOR i IN 1..100 LOOP EXIT WHEN NOT EXISTS (SELECT FROM pg_replication_slots WHERE slot_name = current_database() || '_slot' AND active); PERFORM pg_sleep(0.1); END LOOP; END $$;

SELECT data FROM pg_logical_slot_peek_changes(current_database() || '_slot', NULL, NULL);
