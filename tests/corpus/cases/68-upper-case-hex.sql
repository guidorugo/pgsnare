-- label: gap
-- describe: The value encoded in uppercase hexadecimal.

SELECT upper(encode(convert_to(v, 'UTF8'), 'hex')) FROM bait;
