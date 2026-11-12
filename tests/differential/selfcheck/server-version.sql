-- SPDX-License-Identifier: Apache-2.0
--
-- Not a scenario. This output differs between PostgreSQL major versions, so
-- `make itest` uses it to prove that the runner notices a difference.

SHOW server_version_num;
