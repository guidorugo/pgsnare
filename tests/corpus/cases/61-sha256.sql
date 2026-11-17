-- label: gap
-- describe: The SHA-256 hash of the value.

SELECT encode(sha256(convert_to(v, 'UTF8')), 'hex') FROM bait;
