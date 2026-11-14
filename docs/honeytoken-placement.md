# Honeytoken placement

A honeytoken works only if legitimate code never reads it. pgsnare finds the value when it leaves the database, whatever query got it out, so the quality of a honeytoken is the quality of its hiding place: somewhere an attacker looks and your own software does not. This guide is advice on choosing places, making values and checking that they work.

## What a good place looks like

A good place is data that someone who has stolen access would be drawn to and that no application of yours selects.

- **A row in a table that does hold such data**, which no query of your applications can return: an extra administrator or backup account in the users table whose `id` or `tenant` no query filters for. Read how each application selects before you plant: a `SELECT *` over the whole table returns the planted row too.
- **A table that looks valuable and is not in any application's model**, such as `users_backup`, `api_credentials_old` or `payment_cards_archive`. An ORM that maps the whole schema, a migration tool that reads every table, or an analytics export that copies everything would touch it; check what runs against the database before you add one.
- **A credential-like column** in a table that exists: a stored password hash, an API key or a card number of a made-up user. `pgsnare token generate` makes bait of these kinds.
- **Free text**, where a marker can sit in a note or comment field that people copy from. A marker is four groups of four characters.

A place is bad when ordinary activity reads it: reporting that selects every row, a nightly export, a replica or backup job, logical replication, `pg_dump` run by an operator, a data-quality check, a developer exploring production with `SELECT *`. Those reads are what the token reports, so every one of them is an alert you have to explain or an exemption you have to maintain.

## Make the values

Use `pgsnare token generate`. It connects to nothing, prints the SQL that plants the values and, in a comment, the token file that tells pgsnare what to look for.

```sh
pgsnare token generate --kind identity --table public.users --domain mail.example --count 3 --id users-backup
pgsnare token generate --kind api-key --table public.service_credentials --column api_key --id svc-api
```

- The kinds are `identity` (a made-up account: a name and an email address at a domain of yours that receives no mail), `bcrypt`, `argon2id`, `scram-sha-256` (a verifier of no password), `api-key`, `card` (begins with `99`, outside the ranges of real card numbers) and `marker`.
- Read the SQL before you run it. Names are quoted for the place they are printed in.
- Every value is random, ASCII and long enough to match; nothing makes values predictable. Do not write values by hand, copy them from an example or reuse one from another installation: values in examples are public, and a value used twice would make two places indistinguishable.
- Use a domain you control for email addresses. The address must not belong to a person or to a mail system that someone reads.
- Give each token an `id` that tells you where it is: `users-backup`, `invoices-archive-card`. The id is what events show; the value is never shown.
- Give the token a `scope` (database, table, column) when you write the token file. It is a hint for the reader of the alert, and is not used for matching.
- Keep the token files secret: whoever reads them knows what not to touch.

## Several tokens, in several places

- A value that is hashed, cut, re-encoded or encrypted inside the database before it leaves does not match. Plant several tokens in several columns and tables, so that an attacker who transforms one still reads another.
- Plant more than one kind. An email address, a password hash and an API key in the same row each stand alone: data from any of them sets the token off.
- Use `case_insensitive: true` for values that clients may change the case of, for email addresses for instance.
- A value must be at least 12 bytes and must not contain, or be contained in, another token's value. The loader refuses a list that breaks this.

## Choose the response

Each token has its own response: `alert` (the default), `kill`, `tarpit`, `fake_data`, a combination, and an escalation after repeated hits.

- Start with `alert` only. Watch for a few weeks which legitimate reads you did not foresee, and fix the place or add an exemption.
- Use `kill` for tokens in places that nothing should ever read. It withholds the message holding the token and ends the session. Rows that came before it in the same result were already sent.
- Use `escalate` to let a first hit alert and a repeated hit kill, where a single stray read is possible.
- `tarpit` and `fake_data` cost the attacker time and pollute what is taken. They have limits: see the README, and set `tarpit.max_sessions` as [Hardening](hardening.md) says.
- Exempt the backup and replication users by user name together with an address range, so that they read tokens without a response. A hit under an exemption is counted, not reported.

## Check that it works

1. `pgsnare config check --config FILE` loads the tokens and reports a problem with any of them.
2. `pgsnare token list --config FILE` shows ids and how many values each token has, never the values.
3. `pgsnare token test --config FILE` reads a value from standard input and names the tokens it matches. A terminal is refused.
4. Plant the token in a **test** database first. Read it through pgsnare with a client and confirm that your receiver gets a `token_hit` with the right `token_id`. [The quickstart](quickstart.md) does this with the Compose example.
5. Run the normal workload of your applications against a copy of production data with the tokens planted and make sure that nothing alerts. Then plant in production.
6. Test again after a change: a new token is read by a client the first time; a token file that was changed is read again about two seconds later; a policy that does not load is refused and logged, and the old one stays.

## Known limits

- **A honeytoken used as a password is not detected.** Login messages (the password a client sends) are not scanned, so an attacker who tries a stolen account's honeytoken password is not seen at that moment. A honeytoken used as a **user name** is detected, because the startup message is scanned, and so is any use of the value in a query. Do not rely on a planted password hash alone; plant it in a column and read it through pgsnare.
- Detection is of the value as it travels. A value that is hashed, cut or re-encoded inside the database is not matched.
- Blind extraction infers data without returning it. A honeytoken is not seen by it.
- Traffic that does not pass through pgsnare is not seen.
- A message larger than `inspection.max_buffered_frame` is scanned as a stream, and bytes before the token inside it can reach the client even under `kill`.

See the [threat model](threat-model.md) for the full list.
