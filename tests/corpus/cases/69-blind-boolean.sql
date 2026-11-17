-- label: gap
-- describe: Blind extraction: one bit of the value in each answer.

SELECT ascii(substr(v, 1, 1)) > 77 FROM bait WHERE n = 2;
