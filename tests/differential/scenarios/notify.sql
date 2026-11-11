-- SPDX-License-Identifier: Apache-2.0
--
-- LISTEN and NOTIFY: asynchronous messages from the server.

LISTEN pgsnare_channel;

NOTIFY pgsnare_channel, 'first payload';

SELECT 1 AS after_notify;

SELECT pg_notify('pgsnare_channel', 'second payload');

BEGIN;
NOTIFY pgsnare_channel, 'sent at commit';
SELECT 'not delivered yet' AS state;
COMMIT;

UNLISTEN *;

NOTIFY pgsnare_channel, 'nobody listens';

SELECT 2 AS after_unlisten;
