-- label: hit
-- describe: A statement prepared and executed with SQL commands.

PREPARE corpus_statement AS SELECT v FROM bait;
EXECUTE corpus_statement;
