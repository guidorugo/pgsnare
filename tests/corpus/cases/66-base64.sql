-- label: gap
-- describe: The value encoded in base64 by the database.

SELECT encode(convert_to(v, 'UTF8'), 'base64') FROM bait;
