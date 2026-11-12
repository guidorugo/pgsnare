-- SPDX-License-Identifier: Apache-2.0
--
-- Transactions, savepoints, and recovery after an error.

CREATE TABLE account (id int PRIMARY KEY, balance int NOT NULL CHECK (balance >= 0));
INSERT INTO account VALUES (1, 100), (2, 50);

BEGIN;
UPDATE account SET balance = balance - 30 WHERE id = 1;
SAVEPOINT before_overdraft;
UPDATE account SET balance = balance - 500 WHERE id = 2;
ROLLBACK TO SAVEPOINT before_overdraft;
UPDATE account SET balance = balance + 30 WHERE id = 2;
COMMIT;

SELECT id, balance FROM account ORDER BY id;

BEGIN;
SELECT 1 / 0;
SELECT 'ignored until the transaction ends';
ROLLBACK;

SELECT missing_column FROM missing_table;

INSERT INTO account VALUES (1, 1);

SELECT count(*) AS accounts FROM account;
