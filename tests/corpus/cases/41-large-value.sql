-- label: hit
-- describe: The value at the end of a field of two megabytes. The row is larger than pgsnare holds back, so it is searched while it passes. With kill, what came before the value has reached the client by then (and the beginning of the value too, when it lies across two parts), and the session ends without the error.
-- kill-passes: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

SELECT doc FROM bait_large;
