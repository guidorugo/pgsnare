# Where the licence files of the crate aws-lc-sys come from

The published crate aws-lc-sys 0.47.0 bundles the C code of AWS-LC, and
its licence file names the licence files of the code the bundle carries.
Some of those files are not in the published crate. The files in this
directory are copies, byte for byte, of the ones that are not. Each file
is named for the directory it comes from.

| file | repository | tag | path in the repository | commit the tag points to |
|---|---|---|---|---|
| s2n-bignum-imported-LICENSE | github.com/aws/aws-lc | v5.12.0 | third_party/s2n-bignum/s2n-bignum-imported/LICENSE | cd481c207e38f06aeb5766f4a1cdfce10a4c0af8 |
| jitterentropy-library-LICENSE | github.com/aws/aws-lc | v5.12.0 | third_party/jitterentropy/jitterentropy-library/LICENSE | cd481c207e38f06aeb5766f4a1cdfce10a4c0af8 |
| googletest-LICENSE | github.com/aws/aws-lc | v5.12.0 | third_party/googletest/LICENSE | cd481c207e38f06aeb5766f4a1cdfce10a4c0af8 |
| wycheproof_testvectors-LICENSE | github.com/aws/aws-lc | v5.12.0 | third_party/wycheproof_testvectors/LICENSE | cd481c207e38f06aeb5766f4a1cdfce10a4c0af8 |

The two files under the names s2n-bignum and jitterentropy are the ones
the code the crate compiles carries. The two under the names googletest
and wycheproof are named by the licence file of the crate for code that is
used to test and build, and that the file says is not compiled into the
library; they are kept here so that nothing the file names is left
out.

How the tag was pinned:

- The crate was published from the repository aws/aws-lc-rs, the
  directory aws-lc-sys of it, at the commit
  5d496f88b40f327e28315deecc1a5a1fd1e81e95, which the tag v1.19.0 of that
  repository points to.
- At that tag the submodule aws-lc-sys/aws-lc of the repository points to
  the commit cd481c207e38f06aeb5766f4a1cdfce10a4c0af8 of aws/aws-lc, and
  the tag v5.12.0 of that repository points to the same commit. The
  licence files of the crate are the files of that submodule.

Each file was fetched with the API of the repository it comes from, by the
tag named above, and changed since neither:

    gh api "repos/<owner>/<repo>/contents/<path>?ref=<tag>" --jq .content \
        | base64 -d > <file>
