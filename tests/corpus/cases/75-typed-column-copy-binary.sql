-- label: gap
-- describe: A value that is a UUID, in a column of type uuid, read with COPY in binary format, which sends its sixteen bytes whatever the protocol.
-- token: typed

COPY bait_typed TO STDOUT WITH (FORMAT binary);
