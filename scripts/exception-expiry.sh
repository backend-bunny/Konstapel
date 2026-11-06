#!/usr/bin/env bash
# Reproduce native policies.kyverno.io/v1 PolicyException expiry on the pinned
# Kyverno runtime (add-self-service-policy-exceptions task 1.2).
#
# The probe owns one disposable cluster. Konstapel is never installed, so the
# controller is "stopped" for the whole run, and no policy is edited after the
# exception is created. Admission runs with two replicas so that requests are
# spread across independently cached engines. Every request, its timestamp and
# outcome, plus the image pins, are retained in OUTPUT.
#
# Usage: scripts/exception-expiry.sh ABSOLUTE_OUTPUT_DIRECTORY
# Exit status is 0 when the observation was recorded completely, whatever the
# expiry outcome; result.json states whether cached grants outlived expiry.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
out=${1:?usage: scripts/exception-expiry.sh ABSOLUTE_OUTPUT_DIRECTORY}
out=$(realpath -m "$out")
[[ ! -e $out ]] || { echo 'Output must be a fresh directory' >&2; exit 1; }
mkdir -p "$out"
export KONSTAPEL_CLUSTER_NAME=${KONSTAPEL_CLUSTER_NAME:-konstapel-assessment-exc}
kubeconfig=$out/kubeconfig
context=kind-$KONSTAPEL_CLUSTER_NAME
k=(kubectl --request-timeout=20s --kubeconfig "$kubeconfig" --context "$context")
lifetime=${KONSTAPEL_EXCEPTION_LIFETIME:-120}
ns=exc-probe
exns=policy-exceptions
created=false
cleanup() {
  code=$?
  if [[ $created == true ]]; then
    "${k[@]}" logs -n kyverno -l app.kubernetes.io/component=admission-controller --prefix --tail=-1 > "$out/admission-logs.txt" 2>&1 || true
    scripts/environment.sh delete "$kubeconfig" "$out/environment" > "$out/teardown.log" 2>&1 || { [[ $code != 0 ]] || code=1; }
  fi
  rm -f "$kubeconfig"
  exit "$code"
}
trap cleanup EXIT

if kind get clusters 2>/dev/null | rg -Fxq "$KONSTAPEL_CLUSTER_NAME"; then
  echo "Disposable cluster $KONSTAPEL_CLUSTER_NAME already exists; inspect and remove it explicitly first" >&2; exit 1
fi
created=true
scripts/environment.sh create "$kubeconfig" "$out/environment" > "$out/environment.log" 2>&1

# Two admission replicas: each compiles and caches policies independently.
"${k[@]}" scale deployment -n kyverno kyverno-admission-controller --replicas=2
"${k[@]}" rollout status deployment -n kyverno kyverno-admission-controller --timeout=180s
"${k[@]}" get pods -n kyverno -o json | jq '[.items[] | {name:.metadata.name,uid:.metadata.uid,containers:[.status.containerStatuses[]?|{image,imageID}]}]' > "$out/engine-pods-initial.json"
"${k[@]}" get crd policyexceptions.policies.kyverno.io -o json > "$out/policyexception-crd.json"
"${k[@]}" get --raw /apis/policies.kyverno.io > "$out/policies-group.json"

# Enforcing copy of the vendored policy under a probe-owned name.
sed -e 's/^  name: disallow-privileged-containers$/  name: exc-probe-disallow-privileged/' -e 's/^     - Audit$/     - Deny/' \
  content/upstream/kyverno/disallow-privileged-containers/disallow-privileged-containers.yaml > "$out/policy.yaml"
rg -q 'name: exc-probe-disallow-privileged' "$out/policy.yaml" && rg -q -- '- Deny' "$out/policy.yaml" || { echo 'Policy overlay failed' >&2; exit 1; }
"${k[@]}" apply -f "$out/policy.yaml"
"${k[@]}" wait validatingpolicies.policies.kyverno.io/exc-probe-disallow-privileged --timeout=120s \
  --for=jsonpath='{.status.conditionStatus.conditions[?(@.type=="WebhookConfigured")].status}'=True
"${k[@]}" create namespace "$ns"
# The chart enables exceptions only in this namespace but does not create it.
"${k[@]}" create namespace "$exns" --dry-run=client -o yaml | "${k[@]}" apply -f -
cat > "$out/pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: privileged
  namespace: $ns
  labels: {app: excepted}
spec:
  containers:
  - name: main
    image: $KONSTAPEL_WORKLOAD_IMAGE
    securityContext: {privileged: true}
EOF

requests=$out/requests.jsonl
: > "$requests"
# One server-side dry-run admission request; records phase, time and outcome.
probe() {
  local phase=$1 started finished outcome message
  started=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
  if message=$("${k[@]}" create --dry-run=server -f "$out/pod.yaml" 2>&1); then outcome=admitted; else
    if [[ $message == *exc-probe-disallow-privileged* || $message == *denied* ]]; then outcome=denied; else outcome=error; fi
  fi
  finished=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
  jq -cn --arg phase "$phase" --arg started "$started" --arg finished "$finished" --arg outcome "$outcome" --arg message "$message" \
    '{phase:$phase,started:$started,finished:$finished,outcome:$outcome,message:$message}' >> "$requests"
  printf '%s\n' "$outcome"
}
# Repeat a probe COUNT times, INTERVAL seconds apart.
probes() { local phase=$1 count=$2 interval=$3; for _ in $(seq "$count"); do probe "$phase" > /dev/null; sleep "$interval"; done; }
# Probe until N consecutive results equal WANT, within TIMEOUT seconds.
until_stable() {
  local phase=$1 want=$2 n=$3 timeout=$4 streak=0 deadline
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if [[ $(probe "$phase") == "$want" ]]; then streak=$((streak + 1)); else streak=0; fi
    (( streak >= n )) && return 0
    sleep 1
  done
  return 1
}

# Phase 1: enforcement without an exception.
until_stable before-exception denied 10 120 || { echo 'Policy never enforced' >&2; exit 1; }

# Control: an exception created already expired must never grant.
past=$(date -u -d '-60 seconds' +%Y-%m-%dT%H:%M:%SZ)
exception() {
  local name=$1 expires=$2
  cat <<EOF
apiVersion: policies.kyverno.io/v1
kind: PolicyException
metadata:
  name: $name
  namespace: $exns
spec:
  expiresAt: "$expires"
  policyRefs:
  - name: exc-probe-disallow-privileged
    kind: ValidatingPolicy
  matchConditions:
  - name: probe-namespace
    expression: "object.metadata.namespace == '$ns'"
  - name: probe-workload
    expression: "has(object.metadata.labels) && 'app' in object.metadata.labels && object.metadata.labels['app'] == 'excepted'"
EOF
}
exception exc-probe-expired "$past" > "$out/exception-expired.yaml"
"${k[@]}" apply -f "$out/exception-expired.yaml"
sleep 10
probes created-expired 10 1

# Phase 2: a short-lived exception becomes effective on every replica.
"${k[@]}" delete -f "$out/exception-expired.yaml"
expires=$(date -u -d "+$lifetime seconds" +%Y-%m-%dT%H:%M:%SZ)
exception exc-probe-short "$expires" > "$out/exception.yaml"
"${k[@]}" apply -f "$out/exception.yaml"
"${k[@]}" get policyexceptions.policies.kyverno.io -n "$exns" exc-probe-short -o json > "$out/exception-stored.json"
until_stable active admitted 20 60 || { echo 'Exception never became effective' >&2; exit 1; }

# Phase 3: no events after expiry; Konstapel absent and policies untouched.
expiry_epoch=$(date -u -d "$expires" +%s)
while (( $(date -u +%s) < expiry_epoch + 15 )); do sleep 2; done
probes after-expiry 30 1
sleep 60
probes after-expiry-75s 20 1
"${k[@]}" get policyexceptions.policies.kyverno.io -n "$exns" -o json > "$out/exceptions-after-expiry.json"
"${k[@]}" get pods -n kyverno -o json | jq '[.items[] | {name:.metadata.name,uid:.metadata.uid,restarts:[.status.containerStatuses[]?.restartCount]}]' > "$out/engine-pods-after-expiry.json"

# Phase 4: engine restart recompiles policies from current exceptions.
"${k[@]}" rollout restart deployment -n kyverno kyverno-admission-controller
"${k[@]}" rollout status deployment -n kyverno kyverno-admission-controller --timeout=180s
sleep 10
probes after-restart 20 1

jq -s --arg expires "$expires" --arg kyverno "$(jq -r '[.[].containers[].image] | map(select(test("kyverno"))) | unique' "$out/engine-pods-initial.json")" \
  --arg chart "$KONSTAPEL_KYVERNO_CHART_VERSION" --arg node "$KONSTAPEL_NODE_IMAGE" --argjson lifetime "$lifetime" '
  (group_by(.phase) | map({key:.[0].phase, value:(group_by(.outcome) | map({key:.[0].outcome, value:length}) | from_entries)}) | from_entries) as $phases
  | {
      kyvernoChart:$chart, nodeImage:$node, kyvernoImages:($kyverno|fromjson), admissionReplicas:2,
      exceptionLifetimeSeconds:$lifetime, expiresAt:$expires, konstapelRunning:false, policyEditedAfterException:false,
      phases:$phases,
      firstAdmittedAfterExpiry:([.[] | select((.phase|startswith("after-expiry")) and .outcome=="admitted")][0].started),
      lastAdmittedAfterExpiry:([.[] | select((.phase|startswith("after-expiry")) and .outcome=="admitted")][-1].started),
      cachedGrantOutlivedExpiry:([.[] | select((.phase|startswith("after-expiry")) and .outcome=="admitted")] | length > 0),
      restartRestoredEnforcement:([.[] | select(.phase=="after-restart")] | all(.outcome=="denied")),
      expiredAtCreationNeverGranted:([.[] | select(.phase=="created-expired")] | all(.outcome=="denied"))
    }' "$requests" > "$out/result.json"
cat "$out/result.json"
