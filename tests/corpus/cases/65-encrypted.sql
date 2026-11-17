-- label: gap
-- describe: The value encrypted in the database with a key the client chose.

SELECT encrypt(convert_to(v, 'UTF8'), 'corpus-key-00001', 'aes') FROM bait;
