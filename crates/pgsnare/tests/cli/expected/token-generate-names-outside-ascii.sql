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
INSERT INTO U&"caf\00E9".U&"\8868*/ \\ \+01F600" ("a\b") VALUES
    ('BBBB-BBBB-BBBB-BBBB');

/*
# 2. Tell pgsnare. What stands between the two comment marks is a token
#    file: save it as a file that `token_files` names, or add its entries
#    to the `tokens` of the configuration. Keep it as secret as a password:
#    whoever knows a value can avoid it.
tokens:
  - id: "marker-aaaaaa"
    values: ["BBBB-BBBB-BBBB-BBBB"]
    scope: { table: "caf\xE9.\"\u8868\x2A/ \\ \U0001F600\"", column: "a\\b" }
*/
