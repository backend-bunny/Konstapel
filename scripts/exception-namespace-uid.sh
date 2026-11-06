#!/usr/bin/env bash
# Probe whether native policies.kyverno.io/v1 PolicyException match conditions
# can bind a grant to a namespace instance (name and UID) on the pinned Kyverno
# runtime (add-self-service-policy-exceptions design §4 / task 1.4).
#
# The probe owns one disposable cluster. It tries three exceptions against a
# Deny copy of the vendored policy, each in its own namespace:
#   upper - namespaceObject.metadata.UID == <uid>  (the field the Kubernetes
#           CEL Namespace type declares)
#   lower - namespaceObject.metadata.uid == <uid>  (the Namespace JSON field)
#   name  - namespaceObject.metadata.name only (control)
# and records whether each is accepted, then checks admission (server dry-run)
# and background evaluation (PolicyReport results).
#
# Usage: scripts/exception-namespace-uid.sh ABSOLUTE_OUTPUT_DIRECTORY
# Run it under `flock /tmp/konstapel-live-cluster.lock` on a shared host.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
out=${1:?usage: scripts/exception-namespace-uid.sh ABSOLUTE_OUTPUT_DIRECTORY}
out=$(realpath -m "$out")
[[ ! -e $out ]] || { echo 'Output must be a fresh directory' >&2; exit 1; }
mkdir -p "$out"
export KONSTAPEL_CLUSTER_NAME=${KONSTAPEL_CLUSTER_NAME:-konstapel-assessment-exc-uid}
kubeconfig=$out/kubeconfig
k=(kubectl --request-timeout=20s --kubeconfig "$kubeconfig" --context "kind-$KONSTAPEL_CLUSTER_NAME")
created=false
cleanup() {
  code=$?
  if [[ $created == true ]]; then
    "${k[@]}" logs -n kyverno -l app.kubernetes.io/component=admission-controller --tail=-1 > "$out/admission-logs.txt" 2>&1 || true
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

sed -e 's/^  name: disallow-privileged-containers$/  name: uid-probe-priv/' -e 's/^     - Audit$/     - Deny/' \
  content/upstream/kyverno/disallow-privileged-containers/disallow-privileged-containers.yaml > "$out/policy.yaml"
"${k[@]}" apply -f "$out/policy.yaml" > /dev/null
"${k[@]}" wait validatingpolicies.policies.kyverno.io/uid-probe-priv --timeout=120s \
  --for=jsonpath='{.status.conditionStatus.conditions[?(@.type=="WebhookConfigured")].status}'=True > /dev/null
"${k[@]}" create namespace policy-exceptions --dry-run=client -o yaml | "${k[@]}" apply -f - > /dev/null

pod() {
  cat <<EOF
apiVersion: v1
kind: Pod
metadata: {name: privileged, namespace: $1, labels: {app: debug}}
spec: {containers: [{name: main, image: $KONSTAPEL_WORKLOAD_IMAGE, command: [sleep, "3600"], securityContext: {privileged: true}}]}
EOF
}
declare -A expression accepted
for variant in upper lower name; do
  ns=uid-probe-$variant
  "${k[@]}" create namespace "$ns" > /dev/null
  uid=$("${k[@]}" get namespace "$ns" -o jsonpath='{.metadata.uid}')
  case $variant in
    upper) expression[$variant]="namespaceObject != null && namespaceObject.metadata.name == '$ns' && namespaceObject.metadata.UID == '$uid'" ;;
    lower) expression[$variant]="namespaceObject != null && namespaceObject.metadata.name == '$ns' && namespaceObject.metadata.uid == '$uid'" ;;
    name) expression[$variant]="namespaceObject != null && namespaceObject.metadata.name == '$ns'" ;;
  esac
  jq -n --arg name "uid-probe-$variant" --arg expr "${expression[$variant]}" '{
    apiVersion: "policies.kyverno.io/v1", kind: "PolicyException",
    metadata: {name: $name, namespace: "policy-exceptions"},
    spec: {policyRefs: [{name: "uid-probe-priv", kind: "ValidatingPolicy"}], reportResult: "skip",
           matchConditions: [{name: "namespace", expression: $expr}]}}' > "$out/exception-$variant.json"
  if msg=$("${k[@]}" apply -f "$out/exception-$variant.json" 2>&1); then accepted[$variant]=true; else accepted[$variant]=false; fi
  printf '%s\n' "$msg" > "$out/exception-$variant.apply.log"
done
sleep 15

results=$out/results.jsonl
: > "$results"
for variant in upper lower name; do
  ns=uid-probe-$variant
  if msg=$(pod "$ns" | "${k[@]}" create --dry-run=server -f - 2>&1); then admission=admitted; else admission=denied; fi
  jq -cn --arg variant "$variant" --arg expression "${expression[$variant]}" --argjson accepted "${accepted[$variant]}" \
    --arg admission "$admission" --arg message "$msg" \
    '{variant:$variant, expression:$expression, exceptionAccepted:$accepted, admission:$admission, admissionMessage:$message}' >> "$results"
done

# Background: admit the pods under Audit, then read the background results.
"${k[@]}" patch validatingpolicies.policies.kyverno.io uid-probe-priv --type merge -p '{"spec":{"validationActions":["Audit"]}}' > /dev/null
sleep 10
for variant in upper lower name; do pod "uid-probe-$variant" | "${k[@]}" apply -f - > /dev/null; done
deadline=$((SECONDS + 180))
while (( SECONDS < deadline )); do
  done_count=0
  for variant in upper lower name; do
    n=$("${k[@]}" get policyreports -n "uid-probe-$variant" -o json | jq '[.items[].results[]? | select(.policy=="uid-probe-priv")] | length')
    (( n > 0 )) && done_count=$((done_count + 1))
  done
  (( done_count == 3 )) && break
  sleep 10
done
for variant in upper lower name; do
  "${k[@]}" get policyreports -n "uid-probe-$variant" -o json \
    | jq -c '[.items[].results[]? | select(.policy=="uid-probe-priv") | {result, properties}]' > "$out/background-$variant.json"
done

jq -s --slurpfile up "$out/background-upper.json" --slurpfile lo "$out/background-lower.json" --slurpfile nm "$out/background-name.json" \
  --arg chart "$KONSTAPEL_KYVERNO_CHART_VERSION" --arg node "$KONSTAPEL_NODE_IMAGE" '
  {kyvernoChart: $chart, nodeImage: $node,
   variants: (map({key: .variant, value: (. + {background: ({upper: $up[0], lower: $lo[0], name: $nm[0]}[.variant])})}) | from_entries)}
  | . + {namespaceUIDMatchSupported: ((.variants.upper.admission == "admitted" and (.variants.upper.background | any(.result == "skip")))
                                      or (.variants.lower.exceptionAccepted and .variants.lower.admission == "admitted"))}' \
  "$results" > "$out/result.json"
cat "$out/result.json"
