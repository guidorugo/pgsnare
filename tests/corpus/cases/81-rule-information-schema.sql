-- label: hit
-- describe: The tables of the database, listed from information_schema.
-- needs: rules
-- rule: catalog_enumeration alert

SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';
