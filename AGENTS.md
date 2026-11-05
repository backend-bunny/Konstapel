# Repository workflow

- Make changes on a dedicated branch, using a separate worktree when requested.
- Commit changes on that branch and push the branch to `origin`.
- Open a GitHub pull request targeting `main`. Describe the change and relevant
  validation, including checks that were not run.
- Check the PR's required checks and mergeability, resolve any failures, and merge
  the PR through GitHub using a merge method enabled by the repository.
- Update the local `main` checkout to match the merged remote branch. Preserve
  unrelated work and never discard uncommitted changes.
- After work is complete and merged, remove the task's worktrees and local
  branches, delete merged remote branches if still present, and prune stale
  worktree and remote references. Verify the remaining checkout is clean.
- Tear down task-owned test infrastructure, including disposable clusters,
  containers, and background processes, on success or failure. Preserve unrelated
  infrastructure and useful validation evidence; report anything intentionally
  retained or that could not be cleaned up.
- Do not commit directly to `main`, merge a feature branch into local `main`
  before its PR is merged, or push changes directly to `main` unless the user
  explicitly requests an exception to this workflow.

When asked to commit and merge, carry out the full branch, push, PR, and GitHub
merge workflow above. Report the PR URL and merge result.

# Development tooling

- Use the pinned Devbox environment for development and validation. With direnv's
  shell hook active, `.envrc` loads it; otherwise use `devbox run -- <command>` or
  enter `devbox shell`. Do not assume the host's Go, Task, or image tools match CI.
- Keep tool declarations in `devbox.json` and regenerate `devbox.lock` with Devbox
  when changing them. Do not hand-edit generated locks or introduce a second
  host/CI bootstrap installation mechanism for tools already managed here.
  Package/image build environments remain declared in melange/apko recipes.
- Use existing Task workflows as the shared local/CI entry points. Run
  `task --list` to discover them. `task check` is the normal cluster-free
  validation workflow; image changes also need the image build/smoke workflows,
  and policy/runtime/C2P changes need the applicable live acceptance checks.
  Choose checks appropriate to the change; do not launch clusters for a docs-only
  edit. See [development](docs/development.md), [images](docs/images.md), and
  [releases](docs/releases.md) for commands and dependency ownership.

# Taskfile scope

- Treat `Taskfile.yml` as a small public interface for recurring developer and CI
  workflows, not a catalog of scripts. Adding a script does **not** imply adding
  a task. Do not create one-task-per-script wrappers or aliases without a distinct
  workflow purpose.
- Before adding a task, check whether an existing workflow should call the new
  helper or whether a direct command is sufficient. Occasional helpers can run
  through Devbox, for example `devbox run -- sh scripts/check-version.sh`.
  Keep version checks, chart downloads, summary rendering, and similar helpers
  behind the workflows that need them.
- Public tasks should describe outcomes a contributor regularly needs, such as
  building, checking, testing policies, running acceptance, or building an image.
  A namespace does not justify exposing every implementation step. If Task-level
  composition needs a private task, mark it `internal: true`.
- Keep branching, retries, data processing, and substantial orchestration in
  scripts or application code. Taskfile should wire together those pieces, state
  required inputs, and provide useful descriptions. Pass user-controlled inputs
  through quoted arguments or environment variables, not shell interpolation.
- CI should call the same workflows used locally. Avoid duplicating their logic
  in YAML or introducing another general-purpose runner such as a Makefile.
- When changing the public task interface, update the development command table
  and remove redundant aliases. Explain the recurring workflow that warrants any
  new public task in the PR description.
