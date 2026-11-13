-- pgsnare token generate: 2 honeytokens of the kind card.
-- This is an SQL script. The configuration for pgsnare is in the comment
-- at its end.
--
-- 1. Plant the rows. Review this statement, adapt it to your table and
--    run it yourself: pgsnare has connected to nothing. Run it directly
--    against the database, or before pgsnare is given the values: a
--    value that a client sends through pgsnare is a hit as well.
--    Each number passes the Luhn check and begins with 99, which is
--    outside the ranges of the payment schemes. It is not the number of
--    a card, and a reader who looks at the first digit can tell. Keep it
--    in a text column: a number column is sent in another form in binary
--    results, and the value is missed there.
INSERT INTO "shop"."cards" ("card_number") VALUES
    ('9911111111111112'),
    ('9922222222222222');

/*
# 2. Tell pgsnare. What stands between the two comment marks is a token
#    file: save it as a file that `token_files` names, or add its entries
#    to the `tokens` of the configuration. Keep it as secret as a password:
#    whoever knows a value can avoid it.
tokens:
  - id: "card-aaaaaa-1"
    values: ["9911111111111112"]
    scope: { table: "shop.cards", column: "card_number" }
  - id: "card-aaaaaa-2"
    values: ["9922222222222222"]
    scope: { table: "shop.cards", column: "card_number" }
*/
