-- pgsnare token generate: 1 honeytoken of the kind bcrypt.
-- This is an SQL script. The configuration for pgsnare is in the comment
-- at its end.
--
-- 1. Plant the rows. Review this statement, adapt it to your table and
--    run it yourself: pgsnare has connected to nothing. Run it directly
--    against the database, or before pgsnare is given the values: a
--    value that a client sends through pgsnare is a hit as well.
--    Each value has the format of a bcrypt hash and is the hash of
--    nothing: no password belongs to it.
INSERT INTO "public"."users" ("password_hash") VALUES
    ('$2a$12$.OC/.OC/.OC/.OC/.OC/.O.OC/.OC/.OC/.OC/.OC/.OC/.OC/.OC');

/*
# 2. Tell pgsnare. What stands between the two comment marks is a token
#    file: save it as a file that `token_files` names, or add its entries
#    to the `tokens` of the configuration. Keep it as secret as a password:
#    whoever knows a value can avoid it.
tokens:
  - id: "bcrypt-aaaaaa"
    values: ["$2a$12$.OC/.OC/.OC/.OC/.OC/.O.OC/.OC/.OC/.OC/.OC/.OC/.OC/.OC"]
    scope: { table: "public.users", column: "password_hash" }
*/
