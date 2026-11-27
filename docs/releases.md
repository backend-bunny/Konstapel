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

Policy bundles are released separately, with their own versions and
`bundle/<name>/vX.Y.Z` tags, by a dispatched workflow that does not involve
release-please, `VERSION`, the image or the charts, and published write-once
to `ghcr.io/backend-bunny/bundles/<name>` (one-time package visibility steps
for owners, retries and conflicts included); see
[Release a bundle](policy-bundles.md#release-a-bundle).

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

Publishing uses `GITHUB_TOKEN`; no personal access token or signing secret is
needed, and release-please invokes publishing without depending on a tag-push
event. Release PR updates use the [automation App](#automation-app) token when
it is configured. Otherwise release-please falls back to `GITHUB_TOKEN`, and the
repository must allow GitHub Actions to create PRs.

With the `GITHUB_TOKEN` fallback, GitHub opens the release PR's `pull_request`
runs held at **Approval required** (`action_required`). release-please also
dispatches `test` and `image` on the release branch. Those dispatched runs
report on the PR head commit, but GitHub doesn't count `workflow_dispatch` runs
toward the PR's required `checks` and `acceptance` gates. The release PR
therefore shows no checks and stays blocked until a maintainer approves the
held `test` and `image` runs for the current head commit. Merge only once their
checks pass. Don't substitute main-branch runs or the dispatched runs for them.

To retry image publication for an existing release, run the `publish` workflow
on `main` with its `tag` input set to `vX.Y.Z`. The workflow verifies the tag's
version, release existence and ancestry before publishing. If acceptance failed,
rerun the failed main-branch `test` workflow first, then retry publication. An old
tag without the current full-acceptance job evidence cannot be published through
this gate. Re-running the
failed jobs in the original release-please workflow also retries the release
notes update. Re-running release-please from scratch after a release already
exists may only update the next release PR.

## Automation App

GitHub holds `pull_request` runs for PRs that a workflow creates or updates
with `GITHUB_TOKEN` at approval required. release-please and the image lock
refresh (`lock-refresh`) therefore open their PRs with an installation token from a
repository-owned GitHub App. Runs for the App's same-repository branches start
normally and report the required checks on the PR head commit. Both workflows
use the App only when the `KONSTAPEL_AUTOMATION_APP_CLIENT_ID` repository
variable is set. Without it they keep the `GITHUB_TOKEN` fallback described
above.

To enable it, the repository owner:

1. Creates a GitHub App owned by the repository owner account, with the
   webhook disabled and installation limited to this account.
2. Grants it these repository permissions only: **Contents** read and write,
   **Pull requests** read and write, and **Metadata** read (mandatory). It needs
   no organization or account permissions, no **Workflows** permission and no
   event subscriptions.
3. Installs it on **only** `backend-bunny/Konstapel`.
4. Generates a private key. Stores it as the Actions repository secret
   `KONSTAPEL_AUTOMATION_APP_PRIVATE_KEY`, then deletes the downloaded copy.
5. Sets the App's client ID as the Actions repository variable
   `KONSTAPEL_AUTOMATION_APP_CLIENT_ID`.

The job requests a token limited to `contents: write` and
`pull-requests: write` for this repository, and the token is revoked when the
job ends. The App has no bypass on the `main` ruleset, so its PRs need the same
`checks` and `acceptance` gates as any other. Without the **Workflows**
permission it cannot change files under `.github/workflows`. Runs already held
for an existing release PR still need one approval. Once release-please next
updates the PR with the App token, confirm that its `pull_request` runs start
without approval. To roll back, delete the variable. To rotate the key, generate a new one, replace the secret and
delete the old key in the App settings.

Renovate PRs come from the hosted Renovate GitHub App, so their runs already
start without approval and need no change.

## Chart publication

After the image is published and verified, release-please calls the reusable
`charts` workflow (`.github/workflows/charts.yml`) with the tag and the image
digest. Its three jobs run in order, and any failure stops the publication:

1. **freeze** first checks the release target the same way image publishing
   does, and verifies the image's signature under the image identity. It
   then packages both charts with `charts:package` and attaches
   `konstapel-crds-X.Y.Z.tgz`, `konstapel-X.Y.Z.tgz` and `publication.json`
   to the GitHub Release. A retry downloads those assets and verifies them
   instead of packaging again.
2. **acceptance** requires the full main-branch acceptance for the tagged
   commit (`scripts/ci/require-acceptance.py`), as image publishing does;
   that covers the groups that install no chart. It then runs
   `charts:acceptance` on the downloaded frozen archives with the released
   image pulled by digest: every release-required group (`charts` and
   `availability`, as listed at the tag) on its own disposable cluster. The
   job summary lists each group's result, and sanitized evidence (no
   kubeconfigs, test binaries, rendered chart manifests or node logs) is
   uploaded even on failure. Only a `chart-acceptance.json` in which every
   required test passed for exactly those inputs lets the next job run.
3. **publish**:
   1. pushes the archives write-once (`scripts/charts/publish.py`);
   2. signs each OCI subject and attaches a chart-inputs attestation, which
      records `publication.json` and the acceptance record
      (`scripts/charts/attest.py sign`);
   3. adds GitHub build provenance for each subject;
   4. verifies everything remotely: the signatures (each subject's
      `cosign verify` output must include a `cosign sign` payload for its
      digest, `scripts/image/verify-signature-payload.sh`), the attestation
      predicate (source commit, tag, image digest, archive checksum, and an
      acceptance record that passes the publisher's checks against the
      release-required groups and tests at the source commit), the
      provenance, the image signature, and that pulling each subject by
      digest yields the frozen archive bytes;
   5. attaches `charts-release.json` to the release.

The release-notes job then adds a chart block next to the image block. It
shows both OCI subjects with their digests and archive checksums, and
copyable commands that verify each subject's signature and its payload,
verify the chart-inputs attestation, pull the subject by digest, check the
archive checksum and install that file. Rerunning it replaces only that
block.

Ordinary pushes to `main` publish no charts. Pull requests run the same
`charts`, `monitoring` and `availability` acceptance groups (with an image built from the
pull request), but never sign or write to the chart registry.

**Trust identities.**

| Subject | Signed by (certificate identity) | Issuer |
| --- | --- | --- |
| `ghcr.io/backend-bunny/konstapel@sha256:…` (image) | `https://github.com/backend-bunny/Konstapel/.github/workflows/(publish\|release-please).yml@refs/heads/main` | `https://token.actions.githubusercontent.com` |
| `ghcr.io/backend-bunny/charts/konstapel-crds@sha256:…`, `ghcr.io/backend-bunny/charts/konstapel@sha256:…` | `https://github.com/backend-bunny/Konstapel/.github/workflows/(charts\|release-please).yml@refs/heads/main` | `https://token.actions.githubusercontent.com` |

A valid signature by any other identity doesn't satisfy verification, and
neither does an attestation alone: Cosign v3's `cosign verify` also accepts
the publisher's attestations as signatures, so chart and image verification
require a verified payload of type `https://sigstore.dev/cosign/sign/v1` for
the subject's digest ([images](images.md#verify)). The
chart-inputs attestation (`https://github.com/backend-bunny/Konstapel/chart-inputs/v1`)
must name the released source commit, image digest and archive checksum, and
carry the release acceptance record with a `pass` for every test of every
release-required group at that commit. `attest.py sign` refuses a record the
publisher would refuse, and `attest.py verify` checks it again.
Provenance for the archive file alone isn't accepted: the subject is the OCI
manifest digest.

**Retries and partial publication.** The two registries can't be written
atomically, so each step is safe to repeat. To resume, run the `charts`
workflow on `main` with the release tag:

| Interrupted after | A retry |
| --- | --- |
| freezing (assets attached) | reuses the attached archives and manifest; it never repackages |
| a partial asset upload, with nothing published | discards the incomplete assets and freezes again |
| pushing one chart | finds that version byte-identical and pushes only the other |
| signing or attesting one subject | skips what already verifies under the release identity and adds the rest |
| publishing, with different bytes already at that version | stops: a released version is never replaced |
| publishing, with frozen assets missing | stops with a diagnostic instead of rebuilding a replacement |

A release is complete only when `charts-release.json` is attached and the
notes show the chart block. If acceptance failed, fix the cause, rerun the
failed main-branch `test` workflow if needed, and run `charts` again with
the tag. The frozen inputs and the image stay the same.

**Image and CRD provenance.** The image keeps its own SBOMs, notices,
signature and provenance (see [Images](images.md#verify)). The runtime chart
references the image only by digest. The CRD chart's templates are generated
from `config/crd/bases`, and `publication.json` records their content
identity (`crdContent`), which the acceptance record and the chart-inputs
attestation repeat.

## Tooling provenance

The release configuration and workflow follow the Apache-2.0 implementation in
[talos-nyckelpiga](https://github.com/backend-bunny/talos-nyckelpiga/tree/3505994c1009ac01f5f0cc526b82468c94e3ab4c),
adapted to Go and Konstapel's existing image publishing pipeline.

### Chart signing authentication failures

Helm's registry login and Docker's credential store are separate. The chart
publisher authenticates Helm for chart uploads and uses `docker/login-action`
with the job's package-write token for Cosign and OCI provenance uploads.
A successful Helm push does not prove that signing clients are authenticated.

If publication stops at signing, keep the frozen release assets and existing
OCI subjects. After a workflow authentication fix is merged, dispatch `charts`
on **main** with the existing release tag. Rerunning an old failed workflow
uses its original workflow revision and will not pick up the fix. The new
run reuses the release's frozen inputs, repeats their acceptance, and adds
missing signatures and attestations without replacing the charts. Verify both
subjects and the attached `charts-release.json` before reporting completion.
The original release-please notes job will remain skipped after a separate
chart retry; update the release notes using the verified chart record and the
existing release-note helper, preserving the changelog and user text.
