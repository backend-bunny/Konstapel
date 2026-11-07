#!/usr/bin/env bash
# Live targeting acceptance against an existing disposable cluster with Kyverno
# installed. Tests share cluster-scoped resources and run sequentially.
# scripts/acceptance.sh calls this on the cluster it owns.
set -euo pipefail
cd "$(dirname "$0")/.."
kubeconfig=${1:?usage: targeting-live.sh KUBECONFIG CONTEXT OUTPUT}
context=${2:?explicit context required}
out=${3:?output directory required}
mkdir -p "$out"
# The evidence download test runs the pinned test-owned S3 service.
source scripts/runtime.env
KONSTAPEL_S3_IMAGE=$KONSTAPEL_S3_IMAGE KONSTAPEL_WORKLOAD_IMAGE=$KONSTAPEL_WORKLOAD_IMAGE KONSTAPEL_LIVE_KUBECONFIG=$kubeconfig KONSTAPEL_LIVE_CONTEXT=$context KONSTAPEL_LIVE_OUTPUT=$out \
  go test -mod=readonly -tags live -count=1 -p 1 -timeout 25m -run '^(TestLiveDelivery|TestLiveManager|TestLiveEnforcementEpoch|TestLiveAssessmentStatus|TestLiveAssessmentRuns|TestLiveEngineCorrelation|TestLiveTargetingWorkflow|TestLiveTargetingFailures|TestLiveEvidenceDownload|TestLiveRetentionLifecycle|TestLiveIntegratedAssessments|TestLiveHardeningAdmission|TestLiveHardeningUserNamespaces|TestLiveAssessmentFaults|TestLiveDestinationPins|TestLiveOrphanFence)$' -v ./internal/targeting/ ./internal/controller/ \
  2>&1 | tee "$out/targeting-live.log"
