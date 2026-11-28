#!/usr/bin/env bash
# Verify which Kyverno-side grants the delivered official policies need on the
# pinned Kyverno chart (improve-kyverno-readiness-diagnostics task 2.1).
#
# The probe owns one disposable cluster created by scripts/environment.sh,
# which installs the upstream ephemeral-container fixture. It then removes and
# re-adds grants scenario by scenario and records, for every scenario:
#   - the effective access of the admission and reports controller service
#     accounts (kubectl auth can-i), after RBAC aggregation settles;
#   - RBACPermissionsGranted/WebhookConfigured on every delivered policy in
#     Audit and in Deny mode, before and after a no-op policy touch (whether
#     Kyverno re-evaluates an RBAC change on its own);
#   - Deny admission of pods/ephemeralcontainers updates and Pod creation
#     (server dry-run);
#   - Audit admission of a real pods/ephemeralcontainers update, the
#     admission EphemeralReports written for it and the aggregated
#     PolicyReport results for the Pod;
#   - Forbidden errors logged by the admission and reports controllers.
# A final probe repairs a missing grant without touching any policy and
# measures whether, and after how long, Kyverno reports ready on its own.
# Policies are the bundle's delivered content rendered like
# internal/targeting/render.go: mode, background enabled, namespace selector.
# Konstapel's own RBAC is never touched.
#
# Usage: scripts/kyverno-permission-matrix.sh ABSOLUTE_OUTPUT_DIRECTORY
# Run it under `flock /tmp/konstapel-live-cluster.lock` on a shared host.
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/runtime.env
out=${1:?usage: scripts/kyverno-permission-matrix.sh ABSOLUTE_OUTPUT_DIRECTORY}
out=$(realpath -m "$out")
[[ ! -e $out ]] || { echo 'Output must be a fresh directory' >&2; exit 1; }
mkdir -p "$out/scenarios"
export KONSTAPEL_CLUSTER_NAME=${KONSTAPEL_CLUSTER_NAME:-konstapel-assessment-kyvperm}
kubeconfig=$out/kubeconfig
k=(kubectl --request-timeout=20s --kubeconfig "$kubeconfig" --context "kind-$KONSTAPEL_CLUSTER_NAME")
fixture=content/upstream/kyverno/disallow-privileged-containers/.chainsaw-test/ephemeral-rbac.yaml
created=false
watch_pid=
stop_watch() {
  if [[ -n $watch_pid ]] && kill -0 "$watch_pid" 2> /dev/null; then kill "$watch_pid"; wait "$watch_pid" 2> /dev/null || true; fi
  watch_pid=
}
cleanup() {
  code=$?
  stop_watch
  if [[ $created == true ]]; then
    for c in admission-controller reports-controller; do
      "${k[@]}" logs -n kyverno -l "app.kubernetes.io/component=$c" --tail=-1 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$out/$c-logs.txt" || true
    done
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
# The environment's Helm manifest is not needed as evidence; keep its digest.
sha256sum "$out/environment/helm-manifest.yaml" | cut -d' ' -f1 > "$out/environment/helm-manifest.sha256"
rm -f "$out/environment/helm-manifest.yaml"

# Every policy an official bundle delivers (bundles/*/definition.json and the
# released definitions kept under bundles/*/released/);
# TestPermissionMatrixCoversDeliveredPolicies fails when this set changes.
policies=(content/upstream/kyverno/disallow-privileged-containers/disallow-privileged-containers.yaml
  content/linux-hardening/variants/disallow-privilege-escalation.yaml content/linux-hardening/variants/disallow-capabilities-strict.yaml
  content/linux-hardening/variants/require-run-as-nonroot.yaml content/linux-hardening/variants/restrict-seccomp-strict.yaml
  content/linux-hardening/variants/require-drop-all-capabilities.yaml content/linux-hardening/variants/restrict-added-capabilities.yaml
  content/linux-hardening/variants/restrict-pod-seccomp-profile.yaml content/linux-hardening/variants/require-container-seccomp-profile.yaml)
names=()
for mode in Audit Deny; do
  ns=kpm-${mode,,}
  "${k[@]}" create namespace "$ns" > /dev/null
  for f in "${policies[@]}"; do
    "${k[@]}" create --dry-run=client -o json -f "$f" | jq --arg mode "$mode" --arg ns "$ns" '
      .metadata.name = "kpm-\($mode | ascii_downcase)-\(.metadata.name)"
      | .spec.validationActions = [$mode]
      | .spec.evaluation.background.enabled = true
      | .spec.matchConstraints.namespaceSelector = {matchLabels: {"kubernetes.io/metadata.name": $ns}}' > "$out/policy.json"
    names+=("$(jq -r .metadata.name "$out/policy.json")")
    "${k[@]}" apply -f "$out/policy.json" > /dev/null
  done
done
rm -f "$out/policy.json"
jq -n '$ARGS.positional' --args "${names[@]}" > "$out/policies.json"
for n in "${names[@]}"; do
  "${k[@]}" wait "validatingpolicies.policies.kyverno.io/$n" --timeout=120s \
    --for=jsonpath='{.status.conditionStatus.conditions[?(@.type=="WebhookConfigured")].status}'=True > /dev/null
done

compliant='{"runAsNonRoot":true,"runAsUser":1000,"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"seccompProfile":{"type":"RuntimeDefault"}}'
pod_json() { # NAMESPACE NAME [PRIVILEGED]
  jq -n --arg ns "$1" --arg name "$2" --arg image "$KONSTAPEL_WORKLOAD_IMAGE" --argjson sc "$compliant" --arg priv "${3:-}" '
    {apiVersion: "v1", kind: "Pod", metadata: {name: $name, namespace: $ns},
     spec: {terminationGracePeriodSeconds: 1,
            containers: [{name: "main", image: $image, command: ["sleep", "3600"],
                          securityContext: (if $priv == "" then $sc else {privileged: true} end)}]}}'
}
with_ephemeral() { # NAMESPACE POD NAME compliant|privileged -> pod JSON with an added ephemeral container
  local sc=$compliant; [[ $4 == privileged ]] && sc='{"privileged":true}'
  "${k[@]}" get pod -n "$1" "$2" -o json | jq --arg name "$3" --arg image "$KONSTAPEL_WORKLOAD_IMAGE" --argjson sc "$sc" '
    .spec.ephemeralContainers = ((.spec.ephemeralContainers // []) + [{name: $name, image: $image, command: ["sleep", "3600"], securityContext: $sc}])'
}
outcome() { # COMMAND... -> {"result":"admitted|denied","message":...}
  local msg
  if msg=$("$@" 2>&1); then jq -cn '{result: "admitted"}'
  else jq -cn --arg m "${msg:0:600}" '{result: "denied", message: $m}'; fi
}
access() { # -> can-i matrix for both controller service accounts
  local sa verb res j='{}'
  for sa in admission reports; do
    for verb in get list watch update patch; do
      res=$("${k[@]}" auth can-i "$verb" pods --subresource=ephemeralcontainers --as="system:serviceaccount:kyverno:kyverno-$sa-controller" 2>/dev/null || true)
      j=$(jq -c --arg sa "$sa" --arg v "pods/ephemeralcontainers:$verb" --arg r "$res" '.[$sa][$v] = ($r == "yes")' <<< "$j")
    done
    for verb in get list watch; do
      res=$("${k[@]}" auth can-i "$verb" pods --as="system:serviceaccount:kyverno:kyverno-$sa-controller" 2>/dev/null || true)
      j=$(jq -c --arg sa "$sa" --arg v "pods:$verb" --arg r "$res" '.[$sa][$v] = ($r == "yes")' <<< "$j")
    done
  done
  printf '%s\n' "$j"
}
conditions() {
  "${k[@]}" get validatingpolicies.policies.kyverno.io -o json | jq -c '[.items[] | select(.metadata.name | startswith("kpm-"))
    | {policy: .metadata.name, ready: .status.conditionStatus.ready,
       conditions: [.status.conditionStatus.conditions[]? | select(.type == "RBACPermissionsGranted" or .type == "WebhookConfigured")
                    | {type, status, reason, message}] | sort_by(.type)}] | sort_by(.policy)'
}
kpm_role() { # COMPONENT VERBS...
  local component=$1; shift
  jq -n --arg c "$component" '$ARGS.positional as $v | {apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRole",
    metadata: {name: "kpm:\($c):ephemeralcontainers", labels: {"rbac.kyverno.io/aggregate-to-\($c)": "true", "kpm.konstapel.dev/probe": "true"}},
    rules: [{apiGroups: [""], resources: ["pods/ephemeralcontainers"], verbs: $v}]}' --args "$@" | "${k[@]}" apply -f - > /dev/null
}
saved_bindings=$out/saved-bindings
mkdir -p "$saved_bindings"
remove_view() { # COMPONENT: delete the chart's <component>:view binding (restored by restore_view)
  local b=kyverno:$1:view
  "${k[@]}" get clusterrolebinding "$b" -o json | jq 'del(.metadata.resourceVersion, .metadata.uid, .metadata.creationTimestamp, .metadata.managedFields)' > "$saved_bindings/$1.json"
  "${k[@]}" delete clusterrolebinding "$b" > /dev/null
}
restore_view() {
  local f
  for f in "$saved_bindings"/*.json; do [[ -e $f ]] || continue; "${k[@]}" apply -f "$f" > /dev/null; rm -f "$f"; done
}
set_grants() { # ADMISSION_VERBS REPORTS_VERBS ("fixture" uses the upstream fixture file); "-" means no role
  restore_view
  "${k[@]}" delete --ignore-not-found -f "$fixture" > /dev/null
  "${k[@]}" delete clusterrole --ignore-not-found -l kpm.konstapel.dev/probe=true > /dev/null
  if [[ $1 == fixture ]]; then "${k[@]}" apply -f "$fixture" > /dev/null; return; fi
  # shellcheck disable=SC2086 # verb lists are word-split on purpose
  [[ $1 == - ]] || kpm_role admission-controller $1
  # shellcheck disable=SC2086
  [[ $2 == - ]] || kpm_role reports-controller $2
}
expected_access() { # ADMISSION_VERBS REPORTS_VERBS VIEWLESS -> same shape as access()
  jq -cn --arg a "$1" --arg r "$2" --arg viewless "$3" '
    def verbs($s): if $s == "fixture" then null elif $s == "-" then [] else ($s | split(" ")) end;
    def acc($sa; $s; $fix):
      (verbs($s) // $fix) as $v
      | ([("get","list","watch","update","patch") | {key: "pods/ephemeralcontainers:\(.)", value: (. as $x | $v | index($x) != null)}]
         + [("get","list","watch") | {key: "pods:\(.)", value: ($viewless != $sa)}]) | from_entries;
    {admission: acc("admission"; $a; ["get","list","watch","update"]), reports: acc("reports"; $r; ["get","list","watch"])}'
}

audit_pod_seq=0
scenario() { # NAME ADMISSION_VERBS REPORTS_VERBS [VIEWLESS_COMPONENT]
  local name=$1 adm=$2 rep=$3 viewless=${4:-} dir=$out/scenarios/$1 since want got deadline
  mkdir -p "$dir"
  echo "scenario $name" >&2
  since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  set_grants "$adm" "$rep"
  case $viewless in admission) remove_view admission-controller ;; reports) remove_view reports-controller ;; esac
  want=$(expected_access "$adm" "$rep" "$viewless")
  deadline=$((SECONDS + 60))
  until got=$(access); [[ $(jq -S . <<< "$got") == $(jq -S . <<< "$want") ]]; do
    (( SECONDS < deadline )) || { echo "RBAC for $name did not settle: $got" >&2; break; }
    sleep 2
  done
  printf '%s\n' "$got" > "$dir/access.json"
  # Give Kyverno a full minute to notice the change on its own, then touch.
  sleep 60
  conditions > "$dir/conditions-unprompted.json"
  for n in "${names[@]}"; do
    "${k[@]}" annotate --overwrite "validatingpolicies.policies.kyverno.io/$n" "kpm.konstapel.dev/touch=$name" > /dev/null
  done
  sleep 20
  conditions > "$dir/conditions.json"

  # Deny: server dry-run, nothing persists.
  local u=/api/v1/namespaces/kpm-deny/pods/kpm-deny-base/ephemeralcontainers?dryRun=All
  with_ephemeral kpm-deny kpm-deny-base "dbg-$name" privileged > "$dir/deny-privileged.json"
  with_ephemeral kpm-deny kpm-deny-base "dbg-$name" compliant > "$dir/deny-compliant.json"
  pod_json kpm-deny "priv-$name" privileged > "$dir/deny-pod.json"
  jq -n --argjson p "$(outcome "${k[@]}" replace --raw "$u" -f "$dir/deny-privileged.json")" \
    --argjson c "$(outcome "${k[@]}" replace --raw "$u" -f "$dir/deny-compliant.json")" \
    --argjson pod "$(outcome "${k[@]}" create --dry-run=server -f - < "$dir/deny-pod.json")" \
    '{ephemeralPrivileged: $p, ephemeralCompliant: $c, podCreatePrivileged: $pod}' > "$dir/deny.json"
  rm -f "$dir"/deny-*.json

  # Audit: a real update on a fresh compliant Pod, then its PolicyReport results.
  audit_pod_seq=$((audit_pod_seq + 1))
  local pod=kpm-audit-$audit_pod_seq
  pod_json kpm-audit "$pod" | "${k[@]}" apply -f - > /dev/null
  "${k[@]}" wait -n kpm-audit "pod/$pod" --for=condition=Ready --timeout=120s > /dev/null
  with_ephemeral kpm-audit "$pod" "dbg-$name" privileged > "$dir/audit-update.json"
  # Watch EphemeralReports during the update: the aggregated PolicyReport keeps
  # one result per policy, so admission-review results are only visible here.
  "${k[@]/--request-timeout=20s/--request-timeout=0}" get ephemeralreports.reports.kyverno.io -n kpm-audit -w -o json \
    --output-watch-events > "$dir/ephemeral-watch.json" 2> /dev/null &
  watch_pid=$!
  sleep 2
  local update
  update=$(outcome "${k[@]}" replace --raw "/api/v1/namespaces/kpm-audit/pods/$pod/ephemeralcontainers" -f "$dir/audit-update.json")
  rm -f "$dir/audit-update.json"
  local results='[]'
  deadline=$((SECONDS + 150))
  while (( SECONDS < deadline )); do
    results=$("${k[@]}" get policyreports -n kpm-audit -o json | jq -c --arg pod "$pod" '[.items[]
      | select(any(.scope?, .metadata.ownerReferences[]?; .name? == $pod))
      | .results[]? | select(.policy | startswith("kpm-audit-")) | {policy, result, process: .properties.process}] | unique')
    jq -e 'any(.[]; .policy == "kpm-audit-disallow-privileged-containers" and .result == "fail")' <<< "$results" > /dev/null && break
    sleep 10
  done
  stop_watch
  local admission_results
  admission_results=$(jq -cs --arg pod "$pod" '[.[] | .object // empty
    | select(.spec.owner.name? == $pod or .metadata.annotations["audit.kyverno.io/resource.name"]? == $pod)
    | .metadata.labels["audit.kyverno.io/source"] as $source
    | .spec.results[]? | select(.policy | startswith("kpm-audit-"))
    | {source: $source, policy, result, process: .properties.process}] | unique' "$dir/ephemeral-watch.json")
  rm -f "$dir/ephemeral-watch.json"
  jq -n --arg pod "$pod" --argjson update "$update" --argjson results "$results" --argjson eph "$admission_results" \
    '{pod: $pod, ephemeralUpdate: ($update | if .result == "admitted" then del(.message) else . end),
      ephemeralReportResults: $eph, policyReportResults: $results}' > "$dir/audit.json"

  local c
  for c in admission-controller reports-controller; do
    "${k[@]}" logs -n kyverno -l "app.kubernetes.io/component=$c" --since-time="$since" --tail=-1 2>/dev/null \
      | sed 's/\x1b\[[0-9;]*m//g' | rg -i 'forbidden' | cut -c1-500 > "$dir/$c-forbidden.log" || true
  done
  jq -n --arg name "$name" --arg adm "$adm" --arg rep "$rep" --arg viewless "$viewless" \
    --slurpfile access "$dir/access.json" --slurpfile unprompted "$dir/conditions-unprompted.json" --slurpfile cond "$dir/conditions.json" \
    --slurpfile deny "$dir/deny.json" --slurpfile audit "$dir/audit.json" \
    --arg admForbidden "$(wc -l < "$dir/admission-controller-forbidden.log")" --arg repForbidden "$(wc -l < "$dir/reports-controller-forbidden.log")" '
    {scenario: $name, grants: {admission: $adm, reports: $rep, viewBindingRemoved: (if $viewless == "" then null else $viewless end)},
     access: $access[0],
     unpromptedRefresh: ($unprompted[0] == $cond[0]),
     readiness: ($cond[0] | map({policy, ready, rbac: (.conditions[] | select(.type == "RBACPermissionsGranted") | {status, message}),
                                 webhook: (.conditions[] | select(.type == "WebhookConfigured") | .status)})),
     deny: $deny[0], audit: $audit[0],
     forbiddenLogLines: {admission: ($admForbidden | tonumber), reports: ($repForbidden | tonumber)}}' > "$dir/result.json"
}

# Repair without touching: does Kyverno pick up a grant on its own (informer
# resync, 15m by default) and how long does that take?
resync_probe() {
  local dir=$out/scenarios/resync-repair start elapsed=null n rbac
  mkdir -p "$dir"
  echo "scenario resync-repair" >&2
  set_grants - -
  for n in "${names[@]}"; do
    "${k[@]}" annotate --overwrite "validatingpolicies.policies.kyverno.io/$n" kpm.konstapel.dev/touch=resync-removed > /dev/null
  done
  sleep 20
  conditions > "$dir/conditions-before.json"
  set_grants - "get list watch"
  start=$SECONDS
  while (( SECONDS - start < 1200 )); do
    rbac=$(conditions | jq -c '[.[].conditions[] | select(.type == "RBACPermissionsGranted") | .status] | unique')
    if [[ $rbac == '["True"]' ]]; then elapsed=$((SECONDS - start)); break; fi
    sleep 15
  done
  conditions > "$dir/conditions-after.json"
  jq -n --argjson elapsed "$elapsed" --slurpfile before "$dir/conditions-before.json" --slurpfile after "$dir/conditions-after.json" '
    {scenario: "resync-repair", grants: {admission: "-", reports: "get list watch"}, pollLimitSeconds: 1200,
     before: ([$before[0][].conditions[] | select(.type == "RBACPermissionsGranted") | .status] | unique),
     after: ([$after[0][].conditions[] | select(.type == "RBACPermissionsGranted") | .status] | unique),
     unpromptedRecoverySeconds: $elapsed}' > "$dir/result.json"
}

# Base Pod for Deny probes, created while every grant is present.
pod_json kpm-deny kpm-deny-base | "${k[@]}" apply -f - > /dev/null
"${k[@]}" wait -n kpm-deny pod/kpm-deny-base --for=condition=Ready --timeout=120s > /dev/null

scenario upstream-fixture fixture fixture
scenario none - -
scenario reports-read-only - "get list watch"
scenario reports-without-get - "list watch"
scenario reports-without-list - "get watch"
scenario reports-without-watch - "get list"
scenario admission-only "get list watch update" -
scenario reports-read-admission-no-view - "get list watch" admission
scenario fixture-reports-no-view fixture fixture reports
restore_view
resync_probe

jq -s --arg chart "$KONSTAPEL_KYVERNO_CHART_VERSION" --arg node "$KONSTAPEL_NODE_IMAGE" \
  --slurpfile policies "$out/policies.json" --slurpfile resync "$out/scenarios/resync-repair/result.json" \
  '{kyvernoChart: $chart, nodeImage: $node, policies: $policies[0], scenarios: ., resync: $resync[0]}' \
  "$out"/scenarios/{upstream-fixture,none,reports-read-only,reports-without-get,reports-without-list,reports-without-watch,admission-only,reports-read-admission-no-view,fixture-reports-no-view}/result.json \
  > "$out/result.json"
jq -c '.scenarios[] | {scenario, unpromptedRefresh, rbac: ([.readiness[].rbac.status] | unique), deny: .deny.ephemeralPrivileged.result,
  audit: .audit.ephemeralUpdate.result, admissionReports: ([.audit.ephemeralReportResults[] | "\(.result)/\(.process)"] | unique), reports: ([.audit.policyReportResults[] | "\(.result)/\(.process)"] | unique), forbiddenLogLines}' "$out/result.json"
jq -c .resync "$out/result.json"
