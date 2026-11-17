-- label: gap
-- describe: The value with each letter replaced by another (ROT13).

SELECT translate(v, 'abcdefghijklmnopqrstuvwxyz', 'nopqrstuvwxyzabcdefghijklm') FROM bait;
