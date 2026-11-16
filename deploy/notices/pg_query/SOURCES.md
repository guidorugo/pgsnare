# Where the licence files of the crate pg_query come from

The published crate pg_query 18.1.0 carries no licence file at any depth:
its manifest lists only the sources of the Rust code and of the C code it
bundles. The files in this directory are copies, byte for byte, of the
licence files of that code, taken from the repositories the code comes
from. Each file is named for the file it copies.

| file | repository | tag | path in the repository | commit the tag points to |
|---|---|---|---|---|
| pg_query.rs-LICENSE | github.com/pganalyze/pg_query.rs | v18.1.0 | LICENSE | 20f3a182dc74ef0406752548bc6fb79fbfb591b1 |
| libpg_query-LICENSE | github.com/pganalyze/libpg_query | 18.1.0 | LICENSE | c1546e7e97edc93fe8474d7a59881e91fbf48cfc |
| postgresql-COPYRIGHT | github.com/postgres/postgres | REL_18_6 | COPYRIGHT | 724edf9bde9d356724ad384a2e196edc3c9f80f7 |

How the tags were pinned:

- The crate was published from the repository pganalyze/pg_query.rs at the
  tag v18.1.0; the tag of the crate's own version.
- The C code of the crate is the submodule libpg_query of that repository.
  At the tag v18.1.0 the submodule points to the commit
  c1546e7e97edc93fe8474d7a59881e91fbf48cfc of pganalyze/libpg_query, and
  the tag 18.1.0 of that repository points to the same commit.
- The makefile of the C code of the crate names the release of PostgreSQL
  it is based on: 18.6. The tag REL_18_6 of postgres/postgres is the
  release tag of that version.

Each file was fetched with the API of the repository it comes from, by the
tag named above, and changed since neither:

    gh api "repos/<owner>/<repo>/contents/<path>?ref=<tag>" --jq .content \
        | base64 -d > <file>
