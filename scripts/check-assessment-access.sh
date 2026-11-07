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
	local attempt result
	for attempt in 1 2 3 4 5 6; do
		if result=$(k "$@" 2>&1); then got=ok; else got=deny; fi
		printf '%s\n' "$result" >>"$log"
		# Discovery can briefly report a just-established CRD as unavailable.
		[[ $got == deny && $result == *ServiceUnavailable* ]] || break
		sleep 2
	done
	if [ "$got" = "$want" ]; then
		printf 'PASS %s\n' "$desc" | tee -a "$log"
	else
		printf 'FAIL %s (want %s, got %s)\n' "$desc" "$want" "$got" | tee -a "$log"
		failures=$((failures + 1))
	fi
}

k apply --server-side -f "$root/config/crd/bases" >>"$log"
k wait --for=condition=Established crd --all --timeout=60s >>"$log"
for ns in team-a team-b konstapel-system; do k create namespace "$ns" --dry-run=client -o yaml | k apply -f - >>"$log"; done
k apply --server-side -f "$root/config/rbac" -f "$root/config/admission" >>"$log"
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

# The requester policies (config/admission/assessment-requester.yaml) also
# become effective asynchronously: wait until a dry-run request is mutated.
for _ in $(seq 60); do
	[ "$(k create --as="$team_a" --dry-run=server -o jsonpath='{.spec.requester.username}' -f <(request team-a probe) 2>/dev/null)" = "$team_a" ] && break
	sleep 1
done
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

# The published workflow examples (docs/integration/assessment-workflows.md)
# work as the documented identity and no other.
examples=$root/testdata/assessments/examples/valid
expect ok "workflow: team-a submits the published request example" -- create --as="$team_a" -f "$examples/request-team-a.yaml"
expect deny "workflow: team-b cannot submit team-a's request example" -- create --as="$team_b" --dry-run=server -f "$examples/request-team-a.yaml"
expect ok "workflow: platform submits the published run example" -- create --as="$platform" -f "$examples/run-platform-binding.yaml"
expect deny "workflow: team-a cannot submit the run example" -- create --as="$team_a" --dry-run=server -f "$examples/run-platform-binding.yaml"
expect deny "workflow: team-a cannot apply the binding example" -- apply --as="$team_a" --dry-run=server -f "$examples/binding-assessment.yaml"
expect ok "workflow: team-a may download its own requests" -- auth can-i get assessmentrequests/download -n team-a --as="$team_a"
expect deny "workflow: team-a may not download team-b requests" -- auth can-i get assessmentrequests/download -n team-b --as="$team_a"
expect deny "workflow: team-a may not download runs" -- auth can-i get assessmentruns/download --as="$team_a"
expect ok "workflow: platform may download runs" -- auth can-i get assessmentruns/download --as="$platform"

# EvidenceDestinations are platform-managed: location immutable, access rotatable,
# credentials only in the controller namespace, invisible to application teams.
admin=platform-admin
k create clusterrolebinding platform-admin --clusterrole=konstapel-compliance-admin --user="$admin" --dry-run=client -o yaml | k apply -f - >>"$log"
destination() { # ENDPOINT BUCKET PREFIX SECRET [SECRET_NAMESPACE]
	printf 'apiVersion: compliance.erenius.io/v1alpha1\nkind: EvidenceDestination\nmetadata: {name: primary}\nspec:\n  s3:\n    endpoint: %s\n    bucket: %s\n    region: eu-north-1\n    prefix: %s\n    credentialSecret: {name: %s%s}\n' \
		"$1" "$2" "$3" "$4" "${5:+, namespace: $5}"
}
expect ok "destination: platform admin creates a destination" -- create --as="$admin" -f <(destination https://s3.example.internal evidence clusters/prod konstapel-s3)
expect deny "destination: team-a cannot create a destination" -- create --as="$team_a" --dry-run=server -f <(destination https://s3.team.example evidence team konstapel-s3 | sed 's/name: primary/name: team-owned/')
expect deny "destination: assessment operator cannot create a destination" -- create --as="$platform" --dry-run=server -f <(destination https://s3.example.internal evidence other konstapel-s3 | sed 's/name: primary/name: operator-owned/')
expect deny "destination: team-a cannot read destinations" -- get evidencedestination primary --as="$team_a"
expect deny "destination: team-a cannot read controller-namespace Secrets" -- -n konstapel-system get secrets --as="$team_a"
expect deny "destination: team-a cannot write destination status" -- patch evidencedestination primary --as="$team_a" --subresource=status --type=merge -p '{"status":{"outstandingRuns":0}}'
expect deny "destination: admin cannot write destination status" -- patch evidencedestination primary --as="$admin" --subresource=status --type=merge -p '{"status":{"outstandingRuns":0}}'
expect deny "destination: endpoint is immutable" -- patch evidencedestination primary --as="$admin" --type=merge -p '{"spec":{"s3":{"endpoint":"https://moved.example.internal"}}}'
expect deny "destination: bucket is immutable" -- patch evidencedestination primary --as="$admin" --type=merge -p '{"spec":{"s3":{"bucket":"moved"}}}'
expect deny "destination: prefix is immutable" -- patch evidencedestination primary --as="$admin" --type=merge -p '{"spec":{"s3":{"prefix":"moved"}}}'
expect ok "destination: credentials rotate" -- patch evidencedestination primary --as="$admin" --type=merge -p '{"spec":{"s3":{"credentialSecret":{"name":"konstapel-s3-rotated"}}}}'
expect ok "destination: CA trust rotates" -- patch evidencedestination primary --as="$admin" --type=merge -p '{"spec":{"s3":{"caTrust":{"name":"s3-ca"}}}}'
expect deny "destination: cross-namespace credentials are rejected" -- create --as="$admin" --dry-run=server -f <(destination https://s3.example.internal evidence x konstapel-s3 team-a | sed 's/name: primary/name: crossns/')
# Orphan intent: the actor is the authenticated requester, never forged, and an
# accepted handoff (status.orphanIntent, written by the controller) is frozen.
expect ok "orphan: admin requests Orphan with a reason" -- patch evidencedestination primary --as="$admin" --type=merge -p '{"spec":{"deletionPolicy":"Orphan","orphan":{"reason":"bucket handed to archive team"}}}'
actor=$(k get evidencedestination primary -o jsonpath='{.spec.orphan.actor}')
if [ "$actor" = "$admin" ]; then echo "PASS orphan: actor recorded from the authenticated requester" | tee -a "$log"; else echo "FAIL orphan: actor is '$actor'" | tee -a "$log"; failures=$((failures + 1)); fi
expect deny "orphan: a forged actor is rejected" -- patch evidencedestination primary --as="$admin" --type=merge -p '{"spec":{"orphan":{"actor":"someone-else"}}}'
expect ok "orphan: a forged actor with a new reason is overwritten" -- patch evidencedestination primary --as="$admin" --type=merge -p '{"spec":{"orphan":{"reason":"updated reason","actor":"someone-else"}}}'
actor=$(k get evidencedestination primary -o jsonpath='{.spec.orphan.actor}')
if [ "$actor" = "$admin" ]; then echo "PASS orphan: forged actor replaced by the requester" | tee -a "$log"; else echo "FAIL orphan: forged actor stored as '$actor'" | tee -a "$log"; failures=$((failures + 1)); fi
expect deny "orphan: Orphan without a reason is rejected" -- create --as="$admin" --dry-run=server -f <(destination https://s3.example.internal evidence noreason konstapel-s3 | sed 's/name: primary/name: noreason/; s/^spec:/spec:\n  deletionPolicy: Orphan/')
# Simulate the controller accepting the handoff (status is controller-only).
k patch evidencedestination primary --subresource=status --type=merge -p "{\"status\":{\"orphanIntent\":{\"reason\":\"updated reason\",\"actor\":\"$admin\",\"acceptedAt\":\"2026-11-07T00:00:00Z\"}}}" >>"$log"
expect deny "orphan: an accepted handoff cannot revert to Retire" -- patch evidencedestination primary --as="$admin" --type=merge -p '{"spec":{"deletionPolicy":"Retire","orphan":null}}'
expect deny "orphan: an accepted handoff's reason is frozen" -- patch evidencedestination primary --as="$admin" --type=merge -p '{"spec":{"orphan":{"reason":"rewritten"}}}'
expect ok "orphan: credentials still rotate after acceptance" -- patch evidencedestination primary --as="$admin" --type=merge -p '{"spec":{"s3":{"credentialSecret":{"name":"konstapel-s3-later"}}}}'
k get evidencedestination primary -o yaml >"$out/evidencedestination.yaml"

# The controller identity is configuration, not policy text.
custom=system:serviceaccount:konstapel-system:custom-controller
k create clusterrolebinding custom-controller-assessments --clusterrole=konstapel-controller-assessments --serviceaccount=konstapel-system:custom-controller --dry-run=client -o yaml | k apply -f - >>"$log"
k -n konstapel-system patch configmap konstapel-assessment-admission --type=merge -p '{"data":{"controllerServiceAccountName":"custom-controller"}}' >>"$log"
wait_for() { # DESCRIPTION -- kubectl args...; retry while admission caches the parameter change
	local desc=$1; shift 2
	for _ in $(seq 30); do k "$@" >>"$log" 2>&1 && return 0; sleep 2; done
	return 1
}
if wait_for "custom controller allowed" -- create --as="$custom" --dry-run=server -f <(run probe-custom Binding Scheduled); then echo "PASS reconfigured controller identity is honored" | tee -a "$log"; else echo "FAIL reconfigured controller identity is not honored" | tee -a "$log"; failures=$((failures + 1)); fi
expect deny "previous controller identity loses controller rights" -- create --as="$controller" --dry-run=server -f <(run probe-old Binding Scheduled)
k -n konstapel-system delete configmap konstapel-assessment-admission >>"$log"
for _ in $(seq 30); do k create --as="$platform" --dry-run=server -f <(run probe-missing Binding) >>"$log" 2>&1 || break; sleep 2; done
expect deny "missing controller configuration fails closed" -- create --as="$custom" --dry-run=server -f <(run probe-missing Binding Scheduled)
expect deny "missing configuration denies platform runs too" -- create --as="$platform" --dry-run=server -f <(run probe-missing Binding)
k apply --server-side -f "$root/config/admission/assessment-run-scope.yaml" >>"$log"

k get assessmentrequests -A -o yaml >"$out/assessmentrequests.yaml"
k get assessmentruns -o yaml >"$out/assessmentruns.yaml"
k version -o json >"$out/kubernetes-version.json"
echo "failures: $failures" | tee -a "$log"
[ "$failures" -eq 0 ]
