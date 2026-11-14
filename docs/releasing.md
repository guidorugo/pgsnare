# Releasing

This is the procedure for the owner of the repository. A release is made by the workflow [`.github/workflows/release.yml`](../.github/workflows/release.yml) and by nothing else: nobody builds or signs one on a machine of their own.

**No release has been made yet.** Everything the workflow does after its build is rehearsed in CI on every change, with a registry inside the runner and a key made for the run (job `release-rehearsal` of the `deploy` workflow). What cannot be rehearsed, and is therefore not verified until the first release candidate: signing with the identity of the workflow, the entry in the public transparency log, the build provenance, pushing to the GitHub Container Registry, and creating the draft of the GitHub release.

## Once, before the first release

1. **Protect the tags.** Add a ruleset for tags that match `v*`: no deletion, no update, and creation restricted to the owner. A release tag is then never moved or removed, and the signature of a release names its tag.
2. **Create the environment `release`** with a required reviewer, and restrict it to tags that match `v*`. The job that can write runs in this environment, so it waits for an approval, and no other workflow can reach it. If the environment does not exist when the first tag is pushed, GitHub creates it without any protection.
3. **Add the jobs of the `deploy` workflow to the required checks** of `main`, `release-rehearsal` and `rules` among them.
4. **Review the threat model**, as the design document asks before a first release.

## What the workflow does

| Job | Token | What it does |
|---|---|---|
| `check` | read | The tag is `v` and a version, equals the version in `Cargo.toml`, and names a commit on `main` |
| `build` | read | Builds the image and the binary on each architecture, from nothing |
| `image-test`, `image-scan` | read | The same tests as on every change, on what was just built |
| `publish` | write, in the environment `release` | Checks what `build` made against the sums it reported, then runs [`deploy/release/publish.sh`](../deploy/release/publish.sh): archives, SBOMs, the image, the chart, the manifests, the sums and the signatures. Then records the build provenance and creates the GitHub release as a draft |
| `verify` | read | Runs [`deploy/release/verify.sh`](../deploy/release/verify.sh) against what was published, as a user would |

The job that can write compiles nothing and builds no image. A version tag is three numbers, and at most a release candidate: `v1.2.3` or `v1.2.3-rc.1`.

## Each release

1. **Raise the version by pull request.** Change `version` under `[workspace.package]` in `Cargo.toml`, and let `Cargo.lock` follow: the release build is held to the lock file and fails if the two disagree. Merge it when all checks pass, the rehearsal among them.
2. **Tag the merged commit and push the tag.** The tag is signed:

   ```sh
   git switch main && git pull --ff-only
   git tag --sign v1.2.3 --message "pgsnare 1.2.3"
   git push origin v1.2.3
   ```

3. **Approve the job `publish`** when the workflow asks for it. Before that point nothing has been published; `check`, `build`, `image-test` and `image-scan` have run.
4. **Wait for `verify`.** Then look at the draft of the release: ten files, and the digests in its text.
5. **The first time only:** make the two packages public, `pgsnare` and `charts/pgsnare`. A new package is private.
6. **Verify it yourself**, from another machine, as [verifying-a-release.md](verifying-a-release.md) says. Downloading the files of a draft needs your login.
7. **Publish the draft.**
8. Afterwards: write the digest of the image into the examples and the quickstart, and update `SECURITY.md`.

Make the first release a release candidate, such as `v0.1.0-rc.1`. It proves the parts that no rehearsal reaches.

## When a release fails

- **Before `publish`:** nothing was published. Fix the cause by pull request. The tag stays, because tags are protected, so the fix is released under the next version.
- **During or after `publish`:** some of the image, the chart and their signatures may be in the registry, and the transparency log may hold entries. Nothing of it is announced: the GitHub release is a draft or does not exist. Do not repair it by hand. Delete the draft if there is one, fix the cause, and release the next version.
- **The same version is never published twice.** `publish.sh` refuses a version whose image or chart is already in the registry, so that a release, once made, is never replaced.

## What is not automated

- Making the packages public, and publishing the draft.
- The versions of the tools in [`deploy/tools/tools.txt`](../deploy/tools/tools.txt): they are updated by hand, and the rehearsal shows whether a new version still works.
- Release notes beyond the digests.
