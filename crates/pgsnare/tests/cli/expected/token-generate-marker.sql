-- pgsnare token generate: 1 honeytoken of the kind marker.
-- This is an SQL script. The configuration for pgsnare is in the comment
-- at its end.
--
-- 1. Plant the rows. Review this statement, adapt it to your table and
--    run it yourself: pgsnare has connected to nothing. Run it directly
--    against the database, or before pgsnare is given the values: a
--    value that a client sends through pgsnare is a hit as well.
--    Each value is a marker for free text. It is found anywhere in a
--    message, so it can stand inside a sentence of your own.
INSERT INTO "notes" ("note") VALUES
    ('AAAA-AAAA-AAAA-AAAA');

/*
# 2. Tell pgsnare. What stands between the two comment marks is a token
#    file: save it as a file that `token_files` names, or add its entries
#    to the `tokens` of the configuration. Keep it as secret as a password:
#    whoever knows a value can avoid it.
tokens:
  - id: "notes-marker"
    values: ["AAAA-AAAA-AAAA-AAAA"]
    scope: { table: "notes", column: "note" }
*/
