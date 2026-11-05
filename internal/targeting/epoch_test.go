package targeting

import (
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func revisions(t *testing.T, b v1alpha1.ComplianceBinding) (contrib []string, eligibility []string) {
	t.Helper()
	r := Resolve(Input{Cluster: "kube-system:abc", Bundles: []Bundle{testBundle()},
		Profiles: []v1alpha1.ComplianceProfile{profile("pr", selfService("p1", time.Hour))},
		Bindings: []v1alpha1.ComplianceBinding{b}, Namespaces: []Namespace{ns("a")}})
	if len(r.Bindings) != 1 || len(r.Bindings[0].Contributions) != 1 || len(r.Eligibility) != 1 {
		t.Fatalf("unexpected result %+v", r)
	}
	for _, c := range r.Bindings[0].Contributions {
		contrib = append(contrib, c.Revision)
	}
	for _, c := range r.Eligibility[0].Contributors {
		eligibility = append(eligibility, c.Revision)
	}
	return contrib, eligibility
}

// An epoch'd binding whose generation advanced for a reporting-only edit keeps
// its contribution and exception-eligibility revisions; an epoch change
// rotates them.
func TestEnforcementEpochDecouplesReportingEdits(t *testing.T) {
	b := binding("b", "pr", v1alpha1.ModeDeny, v1alpha1.NamespaceSelector{})
	b.Generation, b.Spec.EnforcementEpoch = 3, 2
	before, beforeElig := revisions(t, b)

	reporting := b
	reporting.Generation = 4
	reporting.Spec.Assessment = &v1alpha1.BindingAssessment{Interval: "1h", Retention: "24h"}
	after, afterElig := revisions(t, reporting)
	if before[0] != after[0] || beforeElig[0] != afterElig[0] {
		t.Fatal("reporting-only edit rotated the enforcement revision")
	}

	enforcement := reporting
	enforcement.Generation, enforcement.Spec.EnforcementEpoch = 5, 3
	rotated, rotatedElig := revisions(t, enforcement)
	if rotated[0] == before[0] || rotatedElig[0] == beforeElig[0] {
		t.Fatal("epoch change kept the enforcement revision")
	}
}

// A binding written before the epoch policy existed uses its generation, so
// initializing the epoch from that generation keeps its revision.
func TestEpochMigrationKeepsRevision(t *testing.T) {
	legacy := binding("b", "pr", v1alpha1.ModeAudit, v1alpha1.NamespaceSelector{})
	legacy.Generation = 7
	before, _ := revisions(t, legacy)

	migrated := legacy
	migrated.Generation, migrated.Spec.EnforcementEpoch = 8, 7 // reporting-only first write after upgrade
	after, _ := revisions(t, migrated)
	if before[0] != after[0] {
		t.Fatal("epoch initialization rotated an unchanged binding")
	}
	if BindingEpoch(&legacy) != 7 || BindingEpoch(&migrated) != 7 {
		t.Fatal("BindingEpoch must fall back to generation only when no epoch is set")
	}
}
