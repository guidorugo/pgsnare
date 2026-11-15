-- label: hit
-- describe: A function that runs a query given as a string and returns XML.

SELECT query_to_xml('SELECT v FROM bait', false, false, '');
