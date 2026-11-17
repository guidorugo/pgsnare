-- label: hit
-- describe: Two statements in one Query message, as a stacked injection sends them. The extended protocol takes one statement in a message.
-- modes: simple

SELECT name FROM products WHERE id = 1 \; SELECT v FROM bait;
