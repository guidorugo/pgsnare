-- label: hit
-- describe: A value that is a UUID, in a column of type uuid. A text result prints it as it is written; a binary result sends its sixteen bytes, which the matcher looks for as well.
-- token: typed

SELECT u FROM bait_typed;
