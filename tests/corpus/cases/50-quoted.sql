-- label: hit
-- describe: The value quoted as a literal and as a name.

SELECT quote_literal(v), quote_ident(v) FROM bait;
