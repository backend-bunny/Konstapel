#!/usr/bin/env bash
# Git metadata only: no dependencies beyond the checkout runner's Bash and Git.
# Only a complete, known prose-only PR diff may skip live acceptance.
set -euo pipefail

decision() {
  printf 'required=%s\nreason=%s\n' "$1" "$2"
}

if [[ ${GITHUB_EVENT_NAME:-} != pull_request ]]; then
  decision true 'Main pushes and manual runs require full acceptance.'
  exit 0
fi

base=${PR_BASE_SHA:-}
head=${PR_HEAD_SHA:-}
if [[ ! $base =~ ^[0-9a-f]{40}$ || ! $head =~ ^[0-9a-f]{40}$ ]]; then
  decision true 'Missing or invalid PR revisions; run acceptance conservatively.'
  exit 0
fi

changed=$(mktemp)
trap 'rm -- "$changed"' EXIT
# Disable rename detection so moving code into a prose path still includes the
# removed code path. NUL separation handles spaces and newlines in filenames.
if ! git diff --no-ext-diff --no-renames --name-only -z "$base...$head" -- > "$changed"; then
  decision true 'Cannot establish the complete PR diff; run acceptance conservatively.'
  exit 0
fi

count=0
while IFS= read -r -d '' path; do
  count=$((count + 1))
  case "$path" in
    README.md|VISION.md|vision.md|ARCHITECTURE.md|AGENTS.md|CHANGELOG.md|LICENSE|NOTICE) ;;
    openspec/*.md|openspec/config.yaml|docs/research/*.md) ;;
    *)
      printf 'Acceptance input changed: %q\n' "$path" >&2
      decision true 'Runtime, integration documentation, tooling, or unknown paths changed.'
      exit 0
      ;;
  esac
done < "$changed"

if [[ $count == 0 ]]; then
  decision true 'Empty diff; run acceptance conservatively.'
else
  decision false 'Only explicitly allowlisted prose and OpenSpec files changed.'
fi
