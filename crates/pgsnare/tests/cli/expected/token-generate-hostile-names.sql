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
INSERT INTO "Shop"."Customer ""Logins""; DROP TABLE users; --" ("na""me", "e-mail'); DROP TABLE users; --") VALUES
    ('svc.backup.aaaaaaaaaaaa', 'svc.backup.aaaaaaaaaaaa@mail.example'),
    ('app.billing.bbbbbbbbbbbb', 'app.billing.bbbbbbbbbbbb@mail.example');

/*
# 2. Tell pgsnare. What stands between the two comment marks is a token
#    file: save it as a file that `token_files` names, or add its entries
#    to the `tokens` of the configuration. Keep it as secret as a password:
#    whoever knows a value can avoid it.
#    The value of a token is the account name. The email address
#    contains it and sets off the same token.
tokens:
  - id: "shop-logins-1"
    values: ["svc.backup.aaaaaaaaaaaa"]
    scope: { table: "\"Shop\".\"Customer \"\"Logins\"\"; DROP TABLE users; --\"", column: "na\"me" }
  - id: "shop-logins-2"
    values: ["app.billing.bbbbbbbbbbbb"]
    scope: { table: "\"Shop\".\"Customer \"\"Logins\"\"; DROP TABLE users; --\"", column: "na\"me" }
*/
