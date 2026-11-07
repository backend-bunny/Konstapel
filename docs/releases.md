# Releases

Release-please maintains one `chore: release X.Y.Z` pull request from Conventional
Commits on `main`, following talos-nyckelpiga's workflow. The release PR updates
`VERSION`, `CHANGELOG.md`, the melange package version, both Helm charts'
`version` and `appVersion`, and release-please's manifest. Review and merge that PR when a version is ready to ship. Creating or
updating the release PR does not publish a version tag.

The `simple` release strategy keeps Konstapel's application version in `VERSION`;
the Go version in `go.mod` remains the compiler requirement. Local builds and
image builds check that `VERSION` matches `melange.yaml` and both charts
(`charts/konstapel-crds`, `charts/konstapel`; see [Helm charts](charts.md)). The generated C2P
provider manifest and OCI version annotation read `VERSION` as well.

The initial application version is `0.1.0`. The release-please manifest starts at
`0.0.0` because no versioned release exists yet; release-please owns subsequent
manifest changes. Do not manually synchronize that historical baseline with
`VERSION` before the first release PR. The bootstrap commit marks the project's
fresh start, so the initial changelog excludes work from the previous codebase.

## Commit conventions

PR titles must use Conventional Commits because the repository normally squash
merges them. Use `feat:` for features, `fix:` for fixes, and `!` or a
`BREAKING CHANGE:` footer for breaking changes. While the version is below 1.0,
features and breaking changes advance the minor version; fixes advance the
patch version. Build/image changes and dependency changes appear in the
changelog; documentation, CI and housekeeping changes are hidden there.

## Publishing

After the release PR is merged, release-please creates the `vX.Y.Z` tag and
GitHub Release. It calls the reusable publishing workflow directly, which waits
for full main-branch acceptance of the tagged commit, then builds, tests,
publishes the commit and `X.Y.Z` image tags, signs and attests the
image, and verifies its evidence. A final job adds the digest to the GitHub
Release without replacing the generated changelog or user-written notes.

Ordinary pushes to `main` publish commit-tagged images after the `test` workflow
completes successfully. The publisher checks out that run's exact commit, even
if `main` has moved. Automatic, release, and manual publishing all verify that
`checks`, `acceptance`, and every `acceptance-live (<group>)` job declared in
`scripts/acceptance-groups.json` succeeded in the matching main-branch run. Missing,
duplicate, failed, cancelled, or skipped group jobs block publication, even if
the aggregate gate passed. PR runs cannot authorize publication. Release/manual
publishing waits up to 90 minutes for that existing run instead of starting
another acceptance cluster. A release
merge can therefore build the same commit in both workflows; publication is
serialized. Consumers should pin the digest printed in the release notes or
job summary. See the [image guide](images.md) for SBOMs, license notices and
verification commands. The trusted signing identities cover the publishing
workflow and its release-please caller on `main`.

Everything uses `GITHUB_TOKEN`; no personal access token or signing secret is
needed. Since bot-created PRs and tags do not trigger normal GitHub workflow
events, release-please explicitly dispatches the `test` and `image` checks on
the release PR branch, and invokes publishing without depending on a tag-push
event. The repository must allow GitHub Actions to create PRs.

To retry image publication for an existing release, run the `publish` workflow
on `main` with its `tag` input set to `vX.Y.Z`. The workflow verifies the tag's
version, release existence and ancestry before publishing. If acceptance failed,
rerun the failed main-branch `test` workflow first, then retry publication. An old
tag without the current full-acceptance job evidence cannot be published through
this gate. Re-running the
failed jobs in the original release-please workflow also retries the release
notes update. Re-running release-please from scratch after a release already
exists may only update the next release PR.

## Tooling provenance

The release configuration and workflow follow the Apache-2.0 implementation in
[talos-nyckelpiga](https://github.com/backend-bunny/talos-nyckelpiga/tree/3505994c1009ac01f5f0cc526b82468c94e3ab4c),
adapted to Go and Konstapel's existing image publishing pipeline.
