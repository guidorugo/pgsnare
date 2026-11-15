-- label: gap
-- describe: The value with a blank after each character.

SELECT regexp_replace(v, '(.)', '\1 ', 'g') FROM bait;
