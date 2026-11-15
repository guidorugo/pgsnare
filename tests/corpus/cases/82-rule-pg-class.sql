-- label: hit
-- describe: The tables of the database, listed from pg_class without its schema.
-- needs: rules
-- rule: catalog_enumeration alert

SELECT relname FROM pg_class WHERE relkind = 'r';
