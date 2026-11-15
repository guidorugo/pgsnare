-- label: hit
-- describe: All values as XML elements.

SELECT xmlagg(xmlelement(name item, v)) FROM bait;
