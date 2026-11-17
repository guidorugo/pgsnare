-- label: gap
-- describe: A catalogue relation looked up through a function, which names no relation.
-- needs: rules
-- rule: catalog_enumeration alert

SELECT to_regclass('pg_authid') IS NOT NULL;
