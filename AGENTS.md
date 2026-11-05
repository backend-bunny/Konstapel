# Repository workflow

- Make changes on a dedicated branch, using a separate worktree when requested.
- Commit changes on that branch and push the branch to `origin`.
- Open a GitHub pull request targeting `main`. Describe the change and relevant
  validation, including checks that were not run.
- Check the PR's required checks and mergeability, resolve any failures, and merge
  the PR through GitHub using a merge method enabled by the repository.
- Update the local `main` checkout to match the merged remote branch. Preserve
  unrelated work and never discard uncommitted changes.
- Do not commit directly to `main`, merge a feature branch into local `main`
  before its PR is merged, or push changes directly to `main` unless the user
  explicitly requests an exception to this workflow.

When asked to commit and merge, carry out the full branch, push, PR, and GitHub
merge workflow above. Report the PR URL and merge result.
