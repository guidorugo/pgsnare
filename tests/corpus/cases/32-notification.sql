-- label: hit
-- describe: The value as the payload of a notification the session itself listens for.

LISTEN corpus_channel;
SELECT pg_notify('corpus_channel', v) FROM bait WHERE n = 2;
