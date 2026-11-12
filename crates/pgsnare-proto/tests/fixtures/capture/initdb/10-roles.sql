-- SPDX-License-Identifier: Apache-2.0
--
-- Roles, a database and a table for the fixture capture. Every name, value
-- and password here is synthetic and exists only inside a throwaway server.

SET password_encryption = 'scram-sha-256';
CREATE ROLE app_scram LOGIN PASSWORD 'not-a-secret';
CREATE ROLE app_plain LOGIN PASSWORD 'not-a-secret';
CREATE ROLE app_repl LOGIN REPLICATION PASSWORD 'not-a-secret';

-- One role keeps an MD5 hash, so that a login with it uses the MD5 method.
SET password_encryption = 'md5';
CREATE ROLE app_md5 LOGIN PASSWORD 'not-a-secret';

CREATE DATABASE appdb OWNER app_scram;

\connect appdb

CREATE TABLE contacts (
    id    integer PRIMARY KEY,
    email text NOT NULL,
    note  text
);
INSERT INTO contacts (id, email, note) VALUES
    (1, 'alice@example.com', 'first contact'),
    (2, 'bob@example.com', NULL),
    (3, 'carol@example.com', '');
ALTER TABLE contacts OWNER TO app_scram;
GRANT SELECT ON contacts TO app_plain, app_md5, app_repl;
