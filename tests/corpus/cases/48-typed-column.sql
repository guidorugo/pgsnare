-- label: hit
-- describe: A value that is a UUID, in a column of type uuid. A text result prints it as it is written; a binary result sends its sixteen bytes, which is not what the value is written as.
-- token: typed
-- gap-in: extended-binary

SELECT u FROM bait_typed;
