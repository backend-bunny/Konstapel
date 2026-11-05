#!/usr/bin/env bash
# Verify assessment request/run access control on a disposable cluster:
# CRD validation, RBAC, and the admission policies in config/admission.
# Usage: scripts/check-assessment-access.sh KUBECONFIG OUTPUT_DIR
# The cluster must be disposable; this script creates namespaces, roles, and
# cluster-scoped objects and does not remove the cluster.
set -euo pipefail

kubeconfig=${1:?usage: $0 KUBECONFIG OUTPUT_DIR}
out=${2:?usage: $0 KUBECONFIG OUTPUT_DIR}
root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$out"
log=$out/assessment-access.log
: >"$log"

k() { kubectl --kubeconfig "$kubeconfig" "$@"; }
team_a=system:serviceaccount:team-a:dev
team_b=system:serviceaccount:team-b:dev
platform=platform-operator
controller=system:serviceaccount:konstapel-system:konstapel-controller
failures=0

expect() { # expect ok|deny DESCRIPTION -- kubectl args...
	local want=$1 desc=$2
	shift 3
	if k "$@" >>"$log" 2>&1; then got=ok; else got=deny; fi
	if [ "$got" = "$want" ]; then
		printf 'PASS %s\n' "$desc" | tee -a "$log"
	else
		printf 'FAIL %s (want %s, got %s)\n' "$desc" "$want" "$got" | tee -a "$log"
		failures=$((failures + 1))
	fi
}

k apply --server-side -f "$root/config/crd/bases" >>"$log"
k wait --for=condition=Established crd --all --timeout=60s >>"$log"
k apply --server-side -f "$root/config/rbac" -f "$root/config/admission" >>"$log"
for ns in team-a team-b konstapel-system; do k create namespace "$ns" --dry-run=client -o yaml | k apply -f - >>"$log"; done
k -n team-a create rolebinding requester --clusterrole=konstapel-assessment-requester --serviceaccount=team-a:dev --dry-run=client -o yaml | k apply -f - >>"$log"
k -n team-b create rolebinding requester --clusterrole=konstapel-assessment-requester --serviceaccount=team-b:dev --dry-run=client -o yaml | k apply -f - >>"$log"
k create clusterrolebinding platform-operator --clusterrole=konstapel-assessment-operator --user="$platform" --dry-run=client -o yaml | k apply -f - >>"$log"
k create clusterrolebinding konstapel-controller-assessments --clusterrole=konstapel-controller-assessments --serviceaccount=konstapel-system:konstapel-controller --dry-run=client -o yaml | k apply -f - >>"$log"
# Admission policies become effective asynchronously; wait until one denies.
for _ in $(seq 60); do
	if ! k create --as="$platform" --dry-run=server -f - >/dev/null 2>&1 <<'EOF'
apiVersion: compliance.erenius.io/v1alpha1
kind: AssessmentRun
metadata: {generateName: probe-}
spec: {bindingRef: {name: baseline-audit}, scope: Binding, trigger: {type: Request}}
EOF
	then break; fi
	sleep 1
done

request() { # NAMESPACE NAME [REQUESTER]
	printf 'apiVersion: compliance.erenius.io/v1alpha1\nkind: AssessmentRequest\nmetadata: {name: %s, namespace: %s}\nspec:\n  bindingRef: {name: baseline-audit}\n' "$2" "$1"
	[ -z "${3:-}" ] || printf '  requester: {username: %s}\n' "$3"
}
run() { # NAME SCOPE [TRIGGER]
	printf 'apiVersion: compliance.erenius.io/v1alpha1\nkind: AssessmentRun\nmetadata: {name: %s}\nspec:\n  bindingRef: {name: baseline-audit}\n  scope: %s\n' "$1" "$2"
	if [ "$2" = Namespace ]; then
		printf '  request: {namespace: team-a, name: nightly, uid: %s}\n  trigger: {type: Request}\n' "$(k -n team-a get assessmentrequest nightly -o jsonpath='{.metadata.uid}')"
	elif [ -n "${3:-}" ]; then
		printf '  trigger: {type: %s, scheduledTime: "2026-11-05T00:00:00Z"}\n' "$3"
	fi
}

expect ok "team-a creates a request in its namespace" -- create --as="$team_a" -f <(request team-a nightly)
requester=$(k -n team-a get assessmentrequest nightly -o jsonpath='{.spec.requester.username}')
if [ "$requester" = "$team_a" ]; then echo "PASS requester recorded from authenticated user" | tee -a "$log"; else echo "FAIL requester is '$requester'" | tee -a "$log"; failures=$((failures + 1)); fi
expect ok "forged requester is overwritten, not trusted" -- create --as="$team_a" -f <(request team-a forged "$platform")
forged=$(k -n team-a get assessmentrequest forged -o jsonpath='{.spec.requester.username}')
if [ "$forged" = "$team_a" ]; then echo "PASS forged requester replaced by '$forged'" | tee -a "$log"; else echo "FAIL forged requester stored as '$forged'" | tee -a "$log"; failures=$((failures + 1)); fi
expect deny "team-a cannot create a request in team-b" -- create --as="$team_a" -f <(request team-b intrude)
expect ok "team-b creates its own request" -- create --as="$team_b" -f <(request team-b nightly)
expect deny "team-a cannot read team-b's request" -- -n team-b get assessmentrequest nightly --as="$team_a"
expect deny "team-a cannot list requests cluster-wide" -- get assessmentrequests -A --as="$team_a"
expect deny "team-a cannot change its request spec" -- -n team-a patch assessmentrequest nightly --as="$team_a" --type=merge -p '{"spec":{"bindingRef":{"name":"other"}}}'
expect deny "spec is immutable even for an administrator" -- -n team-a patch assessmentrequest nightly --type=merge -p '{"spec":{"bindingRef":{"name":"other"}}}'
expect deny "team-a cannot write request status" -- -n team-a patch assessmentrequest nightly --as="$team_a" --subresource=status --type=merge -p '{"status":{"phase":"Completed"}}'
expect deny "team-a cannot create a full-binding run" -- create --as="$team_a" -f <(run team-run Binding)
expect deny "team-a cannot list runs" -- get assessmentruns --as="$team_a"
expect ok "platform creates a Binding-scope Manual run" -- create --as="$platform" -f <(run platform-run Binding)
expect deny "platform cannot create a Namespace-scope run" -- create --as="$platform" -f <(run platform-ns Namespace)
expect deny "platform cannot forge a Scheduled trigger" -- create --as="$platform" -f <(run platform-sched Binding Scheduled)
expect deny "platform cannot write run status" -- patch assessmentrun platform-run --as="$platform" --subresource=status --type=merge -p '{"status":{"phase":"Completed"}}'
expect deny "CRD rejects a Binding run carrying a request" -- create --as="$controller" -f <(run bad-run Binding | sed 's/scope: Binding/scope: Binding\n  request: {namespace: team-a, name: nightly, uid: x}/')
expect ok "controller creates a Namespace-scope run" -- create --as="$controller" -f <(run controller-ns Namespace)
expect ok "controller creates a Scheduled run" -- create --as="$controller" -f <(run controller-sched Binding Scheduled)
expect ok "controller writes run status" -- patch assessmentrun controller-ns --as="$controller" --subresource=status --type=merge -p '{"status":{"phase":"Collecting"}}'
expect ok "controller writes request status" -- -n team-a patch assessmentrequest nightly --as="$controller" --subresource=status --type=merge -p '{"status":{"phase":"Running"}}'
expect deny "run spec is immutable for the controller" -- patch assessmentrun controller-ns --as="$controller" --type=merge -p '{"spec":{"bindingRef":{"name":"other"}}}'
expect ok "team-a still reads its own request and status" -- -n team-a get assessmentrequest nightly --as="$team_a"

k get assessmentrequests -A -o yaml >"$out/assessmentrequests.yaml"
k get assessmentruns -o yaml >"$out/assessmentruns.yaml"
k version -o json >"$out/kubernetes-version.json"
echo "failures: $failures" | tee -a "$log"
[ "$failures" -eq 0 ]
