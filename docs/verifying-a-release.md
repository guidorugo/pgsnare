# Verifying a release

A release of pgsnare is signed, so that you can check, before you run it, that what you downloaded is what the release workflow of this repository built from a tagged commit. This page says what a release holds and how to check it, by hand or with [`deploy/release/verify.sh`](../deploy/release/verify.sh), which does the same and nothing else.

**No release has been published yet.** The steps below have been run in CI on every change against a rehearsal: the release scripts publish to a registry inside the CI runner and sign with a key made for that run, and `verify.sh` then accepts the result and refuses altered copies of it. What a rehearsal cannot show is the signature of a real release, which is tied to the identity of the workflow instead of a key. Until the first release candidate has been published and verified, treat the commands for that as written from the documentation of the tools and not yet run.

## What a release holds

For a version `V`, such as `1.2.3`:

| File | What it is |
|---|---|
| `pgsnare-V-linux-amd64.tar.gz`, `pgsnare-V-linux-arm64.tar.gz` | The static binary for x86_64 and for aarch64, with the licence |
| `pgsnare-V-crates.spdx.json` | SBOM of the binaries: every crate of the lock file the build was held to. That is a little more than a binary links, because the lock file also names crates that only tests use |
| `pgsnare-V-image-amd64.spdx.json`, `pgsnare-V-image-arm64.spdx.json` | SBOM of the image: the packages of its base, and the binary as one file |
| `pgsnare-V-chart.tgz` | The Helm chart, with the image of the release written into its values by digest |
| `pgsnare-V-manifests.yaml` | The chart rendered with example values, for those who do not use Helm. Edit it before applying: see [`deploy/release/manifests-values.yaml`](../deploy/release/manifests-values.yaml) |
| `pgsnare-V-digests.txt` | The image, the image of each architecture and the chart in the registry, each by digest |
| `SHA256SUMS` | The SHA-256 of every file above |
| `SHA256SUMS.sigstore.json` | The signature of `SHA256SUMS` |

In the registry:

| Artefact | Name |
|---|---|
| The image, for both architectures | `ghcr.io/guidorugo/pgsnare` |
| The chart | `ghcr.io/guidorugo/charts/pgsnare` |

The image, the image of each architecture and the chart each carry a signature in the registry. The binary in an archive is the same file as the binary inside the image of that architecture: the release refuses to publish otherwise.

**Use digests, not tags.** A tag such as `:1.2.3` can be moved to another image by whoever controls the registry. A digest cannot. The signature is over the digest, the chart names the image by digest, and `verify.sh` refuses a reference by tag.

## What you need

- `cosign`, version 3. The release is made and rehearsed with the version in [`deploy/tools/tools.txt`](../deploy/tools/tools.txt).
- `sha256sum`.
- For the build provenance, which is optional: the GitHub command line `gh`, logged in.

## With the script

Download every file of the release into an empty directory, then run the script from a checkout of this repository:

```sh
gh release download v1.2.3 --repo guidorugo/pgsnare --dir pgsnare-1.2.3
deploy/release/verify.sh 1.2.3 keyless release pgsnare-1.2.3
```

It checks the signature of `SHA256SUMS`, then every file against it, then the signatures of the image, of the image of each architecture and of the chart that `pgsnare-1.2.3-digests.txt` names. It fails if the directory lacks a file of the release or holds one that is not, and it accepts one signer only: the workflow `.github/workflows/release.yml` of `guidorugo/pgsnare`, run for the tag `v1.2.3`.

To check one image or one chart that you already use, name it by digest:

```sh
deploy/release/verify.sh 1.2.3 keyless image ghcr.io/guidorugo/pgsnare@sha256:<digest>
deploy/release/verify.sh 1.2.3 keyless chart ghcr.io/guidorugo/charts/pgsnare@sha256:<digest>
```

## By hand

The same steps, for version 1.2.3. Set the two values that every step uses:

```sh
identity="https://github.com/guidorugo/pgsnare/.github/workflows/release.yml@refs/tags/v1.2.3"
issuer="https://token.actions.githubusercontent.com"
```

The identity names the repository, the workflow file and the tag. Write the version you expect into it yourself, and do not copy it from the release you are checking: this is what ties a file to its version, so that an older release cannot be passed off as a newer one.

### 1. The signature of the sums

```sh
cosign verify-blob \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  --bundle SHA256SUMS.sigstore.json \
  SHA256SUMS
```

It must print `Verified OK`. Do this first: the next step trusts `SHA256SUMS`.

### 2. The files

```sh
sha256sum --check --strict SHA256SUMS
```

Every file must be `OK`. If you downloaded only some of the files, add `--ignore-missing`, and remember that a file `SHA256SUMS` does not list is covered by no signature.

### 3. The image and the chart

Take the references from `pgsnare-1.2.3-digests.txt`, which step 2 has just checked:

```sh
cat pgsnare-1.2.3-digests.txt
cosign verify \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  ghcr.io/guidorugo/pgsnare@sha256:<digest>
cosign verify \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer "$issuer" \
  ghcr.io/guidorugo/charts/pgsnare@sha256:<digest>
```

Each must end without an error. Then run the image by that digest, and install the chart from the file you verified, `pgsnare-1.2.3-chart.tgz`: it is the same package that the registry holds under the digest of the chart.

### 4. The build provenance (optional)

GitHub records, for every file of the release, for the image and for the chart, which workflow run built it and from which commit. This is a second statement beside the signature, made by GitHub's own attestation service:

```sh
gh attestation verify pgsnare-1.2.3-linux-amd64.tar.gz \
  --repo guidorugo/pgsnare \
  --signer-workflow guidorugo/pgsnare/.github/workflows/release.yml \
  --source-ref refs/tags/v1.2.3 \
  --deny-self-hosted-runners
gh attestation verify oci://ghcr.io/guidorugo/pgsnare@sha256:<digest> \
  --repo guidorugo/pgsnare \
  --signer-workflow guidorugo/pgsnare/.github/workflows/release.yml \
  --source-ref refs/tags/v1.2.3 \
  --deny-self-hosted-runners
```

`deploy/release/verify.sh 1.2.3 keyless provenance pgsnare-1.2.3` does this for every file, the image and the chart.

## What a passed check tells you

- The files, the image and the chart were signed by a run of this repository's release workflow that was started by the tag of that version, and the signature is recorded in a public transparency log.
- Nothing was changed after signing.

It does not tell you that the code is free of faults, or that the tag was pushed by the right person: that rests on the protection of the repository and its tags, which [releasing.md](releasing.md) describes. The SBOMs list what a release was built from, so that you can check it against advisories yourself.

If a check fails, do not use what you downloaded, and report it as [`SECURITY.md`](../SECURITY.md) says.
