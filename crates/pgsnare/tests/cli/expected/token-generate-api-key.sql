-- pgsnare token generate: 3 honeytokens of the kind api-key.
-- This is an SQL script. The configuration for pgsnare is in the comment
-- at its end.
--
-- 1. Plant the rows. Review this statement, adapt it to your table and
--    run it yourself: pgsnare has connected to nothing. Run it directly
--    against the database, or before pgsnare is given the values: a
--    value that a client sends through pgsnare is a hit as well.
--    Each value is 40 random characters and the key of no service.
INSERT INTO "public"."api_keys" ("api_key") VALUES
    ('AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB'),
    ('AgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC'),
    ('AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD');

/*
# 2. Tell pgsnare. What stands between the two comment marks is a token
#    file: save it as a file that `token_files` names, or add its entries
#    to the `tokens` of the configuration. Keep it as secret as a password:
#    whoever knows a value can avoid it.
tokens:
  - id: "api-key-aaaaaa-1"
    values: ["AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"]
    scope: { table: "public.api_keys", column: "api_key" }
  - id: "api-key-aaaaaa-2"
    values: ["AgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC"]
    scope: { table: "public.api_keys", column: "api_key" }
  - id: "api-key-aaaaaa-3"
    values: ["AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD"]
    scope: { table: "public.api_keys", column: "api_key" }
*/
