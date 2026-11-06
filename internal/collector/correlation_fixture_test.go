package collector

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// TestSavedEngineCorrelationEvidence replays the PolicyReports recorded by
// TestLiveEngineCorrelation (docs/integration/engine-correlation.json) for
// the pinned Kyverno release, without a cluster. The reports carry no
// resource version or state digest, so a result is attributable to the
// updated state only through the continuity boundary: the pre-update report
// is rejected for the new state and the first post-update evaluation counts.
func TestSavedEngineCorrelationEvidence(t *testing.T) {
	var ev struct {
		WorkloadUpdate struct {
			At time.Time `json:"at"`
		} `json:"workloadUpdate"`
		Reports []struct {
			Scope   assessment.Object `json:"scope"`
			Results []any             `json:"results"`
			PodHash string            `json:"podStateSha256"`
		} `json:"reports"`
	}
	if err := assessment.Read(filepath.Join(repo(t), "docs/integration/engine-correlation.json"), &ev); err != nil {
		t.Fatal(err)
	}
	if len(ev.Reports) < 2 {
		t.Fatal("evidence needs a pre-update and a post-update report")
	}
	for _, r := range ev.Reports {
		for _, k := range []string{"resourceVersion", "generation"} {
			if _, ok := r.Scope[k]; ok {
				t.Fatalf("evidence shows engine-provided %s; update the documented correlation", k)
			}
		}
	}
	uid := assessment.Str(ev.Reports[0].Scope["uid"])
	ns := assessment.Str(ev.Reports[0].Scope["namespace"])
	policy := assessment.Str(assessment.Map(ev.Reports[0].Results[0])["policy"])
	updated := ev.WorkloadUpdate.At
	if uid == "" || policy == "" || updated.IsZero() {
		t.Fatalf("evidence lacks identity: uid %q policy %q update %v", uid, policy, updated)
	}

	c := freshCapture(t)
	// Re-key the fixture's first expected observation to the recorded pod and
	// engine policy, with the post-update state frozen.
	e := c.Expected[0]
	w := e.Workload
	w.UID, w.Namespace, w.StateSHA256 = uid, ns, ev.Reports[len(ev.Reports)-1].PodHash
	c.Workloads = []Workload{w}
	for i := range c.Checks {
		if c.Checks[i].EnginePolicy == e.Check.EnginePolicy {
			c.Checks[i].EnginePolicy = policy
		}
	}
	c.Subjects = c.Subjects[:1]
	c.Subjects[0].EnginePolicy, c.Subjects[0].Namespace, c.Subjects[0].NamespaceUID = policy, ns, "uid-shop-dev"
	c.Workloads[0].NamespaceUID = "uid-shop-dev"
	c.Checks = c.Checks[:1]
	c.Checks[0].EnginePolicy = policy
	inv, err := BuildInventory(c.Subjects, c.Checks, c.Workloads, c.MappingSHA256)
	if err != nil || len(inv) != 1 {
		t.Fatalf("%v %d", err, len(inv))
	}
	c.Expected = inv
	c.Window = CaptureWindow{Started: updated, Closed: updated.Add(time.Minute)}
	boundary := []Boundary{{WorkloadUID: uid, StateSHA256: w.StateSHA256, Since: updated}}
	asReport := func(i int) assessment.Object {
		return assessment.Object{"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport",
			"metadata": assessment.Object{"uid": "recorded-report"}, "scope": ev.Reports[i].Scope, "results": ev.Reports[i].Results}
	}

	c.Reports = []assessment.Object{asReport(0)}
	if got := evaluate(t, c, boundary, 2*time.Hour); got.Evidence.Completeness != publication.Incomplete || got.Evidence.Rejected != 1 {
		t.Fatalf("pre-update result counted for the updated state: %+v", got.Evidence)
	}
	c.Reports = []assessment.Object{asReport(1)}
	got := evaluate(t, c, boundary, 2*time.Hour)
	if got.Evidence.Completeness != publication.Complete || got.Outcomes.Fail != 1 || !got.Observations[0].Evaluated.After(updated) {
		t.Fatalf("first post-update evaluation not attributable: %+v", got.Evidence)
	}
}
