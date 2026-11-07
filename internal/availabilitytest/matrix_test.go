// Package availabilitytest checks the controller-availability lifecycle
// matrix against the specification (add-controller-high-availability 1.1).
package availabilitytest

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"testing"
)

type entry struct {
	Requirement, Boundary, Expected, Owner, Status, Evidence string
}

// Every availability requirement maps to a boundary, an expected result, an
// owning change, and a status, and nothing in the matrix is stale.
func TestLifecycleMatrixCoversEveryRequirement(t *testing.T) {
	spec, err := os.ReadFile("../../openspec/changes/add-controller-high-availability/specs/controller-availability/spec.md")
	if err != nil {
		t.Skipf("change archived or moved: %v", err)
	}
	var want []string
	for _, m := range regexp.MustCompile(`(?m)^### Requirement: (.+)$`).FindAllSubmatch(spec, -1) {
		want = append(want, string(m[1]))
	}
	raw, err := os.ReadFile("../../testdata/availability/lifecycle-matrix.json")
	if err != nil {
		t.Fatal(err)
	}
	var matrix struct{ Requirements []entry }
	if err := json.Unmarshal(raw, &matrix); err != nil {
		t.Fatal(err)
	}
	var got []string
	owners := []string{"add-controller-high-availability", "add-helm-oci-distribution", "add-continuous-assessments", "add-s3-evidence-publishing", "add-self-service-policy-exceptions", "add-compliance-targeting-api", "add-policy-bundle-distribution", "add-prometheus-observability"}
	for _, e := range matrix.Requirements {
		got = append(got, e.Requirement)
		if e.Boundary == "" || e.Expected == "" || e.Evidence == "" || !slices.Contains(owners, e.Owner) || (e.Status != "verified" && e.Status != "pending") {
			t.Errorf("incomplete matrix entry: %+v", e)
		}
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("matrix requirements %v\nspec requirements %v", got, want)
	}
}
