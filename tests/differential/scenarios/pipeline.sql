-- SPDX-License-Identifier: Apache-2.0
--
-- Pipelining: several statements sent before any result is read, with an
-- error in the middle of a pipeline.

\startpipeline
SELECT $1::int AS first \bind 1 \sendpipeline
SELECT $1::int AS second \bind 2 \sendpipeline
SELECT $1::int AS third \bind 3 \sendpipeline
\endpipeline

\startpipeline
SELECT $1::int AS before_error \bind 1 \sendpipeline
SELECT $1::int / 0 AS error \bind 1 \sendpipeline
SELECT $1::int AS skipped \bind 2 \sendpipeline
\syncpipeline
SELECT $1::int AS after_sync \bind 3 \sendpipeline
\endpipeline
