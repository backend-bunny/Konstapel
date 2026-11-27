#!/usr/bin/env bash
# Require a `cosign sign` image signature for exactly IMAGE's digest in the
# output of `cosign verify` (SIGNATURE_JSON). Cosign v3 verifies a publisher's
# attestations as signatures too and lists each verified payload, so an image
# with attestations but no signature passes `cosign verify` alone. Each entry's
# critical.type is the signed statement's predicate type; only a signature
# made by `cosign sign` has https://sigstore.dev/cosign/sign/v1. Run it after
# `cosign verify` with the publisher's identity and issuer (or key) has
# succeeded; it adds to that check and replaces none of it. Attestations are
# verified separately with `cosign verify-attestation`.
#
# Usage: verify-signature-payload.sh SIGNATURE_JSON IMAGE
# IMAGE is the verified reference, repository@sha256:<digest>: the controller
# image, or a Helm chart's OCI subject (scripts/charts/attest.py). The filter
# below is quoted verbatim in docs/images.md ("Verify"), scripts/image/summary.py
# and scripts/charts/release-notes.py; scripts/ci/test_image_signature_payload.py
# fails if they drift apart.
set -euo pipefail
usage='usage: verify-signature-payload.sh SIGNATURE_JSON IMAGE'
signature=${1:?$usage}
IMAGE=${2:?$usage}
[[ $# == 2 ]] || { echo "$usage" >&2; exit 2; }
[[ $IMAGE =~ ^[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]] || { echo "$IMAGE is not a digest reference (repository@sha256:...)" >&2; exit 1; }
filter='type == "array" and any(.[]; .critical.type == "https://sigstore.dev/cosign/sign/v1" and .critical.image."docker-manifest-digest" == $digest)'
if ! jq -e --arg digest "${IMAGE#*@}" "$filter" "$signature" > /dev/null; then
  echo "$signature: no cosign image signature for ${IMAGE#*@} (only attestations or another subject were verified)" >&2
  exit 1
fi
echo "Verified cosign image signature payload for $IMAGE"
