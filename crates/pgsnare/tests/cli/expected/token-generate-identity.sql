-- pgsnare token generate: 2 honeytokens of the kind identity.
-- This is an SQL script. The configuration for pgsnare is in the comment
-- at its end.
--
-- 1. Plant the rows. Review this statement, adapt it to your table and
--    run it yourself: pgsnare has connected to nothing. Run it directly
--    against the database, or before pgsnare is given the values: a
--    value that a client sends through pgsnare is a hit as well.
--    Each row is a made-up service account. Its email address is its
--    name at the domain you gave.
INSERT INTO "public"."users" ("name", "email") VALUES
    ('app.billing.bbbbbbbbbbbb', 'app.billing.bbbbbbbbbbbb@mail.example'),
    ('sys.deploy.cccccccccccc', 'sys.deploy.cccccccccccc@mail.example');

/*
# 2. Tell pgsnare. What stands between the two comment marks is a token
#    file: save it as a file that `token_files` names, or add its entries
#    to the `tokens` of the configuration. Keep it as secret as a password:
#    whoever knows a value can avoid it.
#    The value of a token is the account name. The email address
#    contains it and sets off the same token.
tokens:
  - id: "identity-aaaaaa-1"
    values: ["app.billing.bbbbbbbbbbbb"]
    scope: { table: "public.users", column: "name" }
  - id: "identity-aaaaaa-2"
    values: ["sys.deploy.cccccccccccc"]
    scope: { table: "public.users", column: "name" }
*/
