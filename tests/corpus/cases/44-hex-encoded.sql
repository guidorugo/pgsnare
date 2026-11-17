-- label: hit
-- describe: The value encoded in lowercase hexadecimal by the database.

SELECT encode(convert_to(v, 'UTF8'), 'hex') FROM bait;
