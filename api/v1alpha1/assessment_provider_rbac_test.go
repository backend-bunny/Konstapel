package v1alpha1_test

import (
	"slices"
	"strings"
	"testing"
)

// add-external-assessment-providers 2.1: registering external providers is
// a dedicated, non-aggregated platform grant. Only
// konstapel-assessment-provider-admin writes registrations, the viewer only
// reads them, and the controller reads them and alone writes their status.
// No namespace role, konstapel-compliance-admin, or any other shipped role
// touches them, and neither provider role reads Secrets or ConfigMaps or
// reaches any other resource. Checked statically against every shipped Role
// and ClusterRole (aggregation labels:
// TestComplianceRolesAreNotAggregatedIntoNamespaceRoles);
// TestLiveAssessmentProviderAPI checks the same matrix against a real API
// server, and TestLiveHelmLateKyverno against the installed chart.

const (
	providerAdmin  = "konstapel-assessment-provider-admin"
	providerViewer = "konstapel-assessment-provider-viewer"
)

var providerMatrix = map[string][]grant{
	providerAdmin: {{"get", "assessmentproviders"}, {"list", "assessmentproviders"}, {"watch", "assessmentproviders"},
		{"create", "assessmentproviders"}, {"update", "assessmentproviders"}, {"patch", "assessmentproviders"}, {"delete", "assessmentproviders"},
		{"get", "assessmentproviders/status"}},
	providerViewer: {{"get", "assessmentproviders"}, {"list", "assessmentproviders"}, {"watch", "assessmentproviders"},
		{"get", "assessmentproviders/status"}, {"list", "assessmentproviders/status"}, {"watch", "assessmentproviders/status"}},
	controllerRole: {{"get", "assessmentproviders"}, {"list", "assessmentproviders"}, {"watch", "assessmentproviders"},
		{"get", "assessmentproviders/status"}, {"update", "assessmentproviders/status"}, {"patch", "assessmentproviders/status"}},
}

func TestAssessmentProviderAuthorityMatrix(t *testing.T) {
	found := map[string]bool{}
	for _, r := range loadRoles(t) {
		want, listed := providerMatrix[r.name]
		if listed && r.kind == "ClusterRole" {
			found[r.name] = true
			if r.name != controllerRole && r.labels["app.kubernetes.io/part-of"] != "konstapel" {
				t.Errorf("%s lacks the part-of label", r.name)
			}
		}
		if listed && r.kind != "ClusterRole" && r.name != controllerRole {
			t.Errorf("%s must be a ClusterRole (bound cluster-wide to platform subjects)", r.name)
		}
		for _, res := range []string{"assessmentproviders", "assessmentproviders/status", "assessmentproviders/finalizers"} {
			for _, verb := range allVerbs {
				expected := listed && r.kind == "ClusterRole" && slices.Contains(want, grant{verb, res})
				if got := grants(r.rules, verb, res); got != expected {
					t.Errorf("%s %s (%s): %s %s = %v, want %v", r.kind, r.name, r.file, verb, res, got, expected)
				}
			}
		}
	}
	for name := range providerMatrix {
		if !found[name] {
			t.Errorf("ClusterRole %s not shipped", name)
		}
	}
}

// The provider roles carry nothing else: binding one never grants Secret or
// ConfigMap reads (a registration's trust lives in the controller
// namespace), any other Konstapel resource, or a wildcard.
func TestAssessmentProviderRolesGrantOnlyRegistrations(t *testing.T) {
	for _, r := range loadRoles(t) {
		if r.name != providerAdmin && r.name != providerViewer {
			continue
		}
		if len(r.labels) != 1 {
			t.Errorf("%s carries labels %v; only app.kubernetes.io/part-of is expected", r.name, r.labels)
		}
		for _, rule := range r.rules {
			if !slices.Equal(rule.APIGroups, []string{"compliance.erenius.io"}) || len(rule.ResourceNames) > 0 || len(rule.NonResourceURLs) > 0 {
				t.Errorf("%s rule %v reaches beyond registrations", r.name, rule)
			}
			for _, res := range rule.Resources {
				if res != "assessmentproviders" && res != "assessmentproviders/status" {
					t.Errorf("%s grants %s", r.name, res)
				}
			}
			if slices.Contains(rule.Verbs, "*") || slices.Contains(rule.Resources, "*") {
				t.Errorf("%s uses a wildcard", r.name)
			}
		}
		for _, verb := range allVerbs {
			for _, res := range []string{"secrets", "configmaps", "services", "serviceaccounts", "pods"} {
				if grantsCore(r.rules, verb, res) {
					t.Errorf("%s may %s %s", r.name, verb, res)
				}
			}
		}
	}
}

// Namespace-scoped roles (bound with RoleBindings by namespace teams) and
// the existing central roles never reach registrations, so a caller with
// only namespace assessment rights cannot create or change one. The
// cluster-scoped kind is also never reachable through a RoleBinding.
func TestNamespaceRolesCannotRegisterProviders(t *testing.T) {
	for _, r := range loadRoles(t) {
		if _, listed := providerMatrix[r.name]; listed {
			continue
		}
		if !strings.HasPrefix(r.name, "konstapel-") {
			t.Errorf("unexpected role %s", r.name)
		}
		for _, verb := range allVerbs {
			for _, res := range []string{"assessmentproviders", "assessmentproviders/status"} {
				if grants(r.rules, verb, res) {
					t.Errorf("%s %s (%s) may %s %s", r.kind, r.name, r.file, verb, res)
				}
			}
		}
	}
}
