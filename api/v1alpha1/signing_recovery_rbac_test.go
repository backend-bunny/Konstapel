package v1alpha1_test

import (
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

// add-evidence-signing-recovery 1.3: requesting recovery and auditing
// requests are dedicated, non-aggregated platform ClusterRoles. No namespace
// role, konstapel-compliance-admin, or any other shipped role can create or
// read requests; neither recovery role can change a request, write any
// status, read Secrets, or change destinations; and only the controller
// writes request status. Checked statically against every shipped Role and
// ClusterRole (aggregation labels: TestComplianceRolesAreNotAggregatedIntoNamespaceRoles);
// TestLiveEvidenceSigningRequestAPI checks the same matrix against a real
// API server.

const (
	signingRecoverer      = "konstapel-evidence-signing-recoverer"
	signingRecoveryReader = "konstapel-evidence-signing-recovery-reader"
)

var signingRecoveryMatrix = map[string][]grant{
	signingRecoverer: {{"get", "evidencesigningrequests"}, {"list", "evidencesigningrequests"}, {"watch", "evidencesigningrequests"},
		{"create", "evidencesigningrequests"}, {"get", "evidencesigningrequests/status"}},
	signingRecoveryReader: {{"get", "evidencesigningrequests"}, {"list", "evidencesigningrequests"}, {"watch", "evidencesigningrequests"},
		{"get", "evidencesigningrequests/status"}, {"list", "evidencesigningrequests/status"}, {"watch", "evidencesigningrequests/status"}},
	controllerRole: {{"get", "evidencesigningrequests"}, {"list", "evidencesigningrequests"}, {"watch", "evidencesigningrequests"},
		{"get", "evidencesigningrequests/status"}, {"update", "evidencesigningrequests/status"}, {"patch", "evidencesigningrequests/status"}},
}

func TestSigningRecoveryAuthorityMatrix(t *testing.T) {
	found := map[string]bool{}
	for _, r := range loadRoles(t) {
		want, listed := signingRecoveryMatrix[r.name]
		if listed && r.kind == "ClusterRole" {
			found[r.name] = true
			if r.name != controllerRole && r.labels["app.kubernetes.io/part-of"] != "konstapel" {
				t.Errorf("%s lacks the part-of label", r.name)
			}
		}
		if listed && r.kind != "ClusterRole" && r.name != controllerRole {
			t.Errorf("%s must be a ClusterRole (bound cluster-wide to platform subjects)", r.name)
		}
		for _, res := range []string{"evidencesigningrequests", "evidencesigningrequests/status", "evidencesigningrequests/finalizers"} {
			for _, verb := range allVerbs {
				expected := listed && r.kind == "ClusterRole" && slices.Contains(want, grant{verb, res})
				if got := grants(r.rules, verb, res); got != expected {
					t.Errorf("%s %s (%s): %s %s = %v, want %v", r.kind, r.name, r.file, verb, res, got, expected)
				}
			}
		}
	}
	for name := range signingRecoveryMatrix {
		if !found[name] {
			t.Errorf("ClusterRole %s not shipped", name)
		}
	}
}

// The recovery roles carry nothing else: binding one never grants run status
// writes, signing Secret access, destination changes, or any other resource.
func TestSigningRecoveryRolesGrantOnlyRequests(t *testing.T) {
	for _, r := range loadRoles(t) {
		if r.name != signingRecoverer && r.name != signingRecoveryReader {
			continue
		}
		for _, rule := range r.rules {
			if !slices.Equal(rule.APIGroups, []string{"compliance.erenius.io"}) || len(rule.ResourceNames) > 0 || len(rule.NonResourceURLs) > 0 {
				t.Errorf("%s rule %v reaches beyond the request records", r.name, rule)
			}
			for _, res := range rule.Resources {
				if res != "evidencesigningrequests" && res != "evidencesigningrequests/status" {
					t.Errorf("%s grants %s", r.name, res)
				}
			}
			if slices.Contains(rule.Verbs, "*") || slices.Contains(rule.Resources, "*") {
				t.Errorf("%s uses a wildcard", r.name)
			}
		}
		for _, res := range []string{"assessmentruns/status", "assessmentruns", "evidencedestinations", "evidencedestinations/status"} {
			for _, verb := range []string{"create", "update", "patch", "delete"} {
				if grants(r.rules, verb, res) {
					t.Errorf("%s may %s %s", r.name, verb, res)
				}
			}
		}
		for _, verb := range allVerbs {
			if grantsCore(r.rules, verb, "secrets") {
				t.Errorf("%s may %s secrets", r.name, verb)
			}
		}
	}
}

func grantsCore(rules []rbacv1.PolicyRule, verb, resource string) bool {
	for _, r := range rules {
		if matches(r.APIGroups, "") && matches(r.Resources, resource) && matches(r.Verbs, verb) {
			return true
		}
	}
	return false
}
