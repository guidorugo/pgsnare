-- pgsnare token generate: 1 honeytoken of the kind scram-sha-256.
-- This is an SQL script. The configuration for pgsnare is in the comment
-- at its end.
--
-- 1. Plant the rows. Review this statement, adapt it to your table and
--    run it yourself: pgsnare has connected to nothing. Run it directly
--    against the database, or before pgsnare is given the values: a
--    value that a client sends through pgsnare is a hit as well.
--    Each value has the format of a SCRAM-SHA-256 verifier of PostgreSQL
--    and belongs to no password.
INSERT INTO "auth"."roles" ("verifier") VALUES
    ('SCRAM-SHA-256$4096:AQEBAQEBAQEBAQEBAQEBAQ==$AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AQEBAQEBAQEBAQEBAQEBAQICAgICAgICAgICAgICAgI=');

/*
# 2. Tell pgsnare. What stands between the two comment marks is a token
#    file: save it as a file that `token_files` names, or add its entries
#    to the `tokens` of the configuration. Keep it as secret as a password:
#    whoever knows a value can avoid it.
tokens:
  - id: "scram-sha-256-aaaaaa"
    values: ["SCRAM-SHA-256$4096:AQEBAQEBAQEBAQEBAQEBAQ==$AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=:AQEBAQEBAQEBAQEBAQEBAQICAgICAgICAgICAgICAgI="]
    scope: { table: "auth.roles", column: "verifier" }
*/
