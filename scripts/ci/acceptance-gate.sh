#!/usr/bin/env bash
set -euo pipefail
printf 'Acceptance: %s\n' "${ACCEPTANCE_REASON:-No valid decision recorded.}"
[[ ${SCOPE_RESULT:-} == success && ${CHECKS_RESULT:-} == success ]]
if [[ ${ACCEPTANCE_REQUIRED:-} == true ]]; then
  # GitHub aggregates the matrix result: any failed/cancelled group fails this
  # gate. The matrix and publishing verifier use acceptance-groups.json.
  [[ ${LIVE_RESULT:-} == success ]]
elif [[ ${ACCEPTANCE_REQUIRED:-} == false && ${GITHUB_EVENT_NAME:-} == pull_request ]]; then
  [[ ${LIVE_RESULT:-} == skipped ]]
  echo 'Full acceptance skipped for an allowlisted prose-only PR.'
else
  echo 'Invalid acceptance decision; refusing to pass.' >&2
  exit 1
fi
