-- label: hit
-- describe: The value as a setting that the server reports back to the client. No row holds it.

SELECT set_config('application_name', v, false) IS NULL FROM bait WHERE n = 2;
