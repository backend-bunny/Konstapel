package controller

import (
	"context"
	"io"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/coverage"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

// Failure and degraded-input paths across report generation
// (add-control-coverage-reporting 5.2): whatever goes wrong, coverage never
// becomes a successful, complete report, and findings stay attributable.

func startedCoverageRun(t *testing.T) (*runEnv, string) {
	t.Helper()
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	return e, name
}

func packageOf(t *testing.T, e *runEnv, r *v1alpha1.AssessmentRun) string {
	t.Helper()
	rc, _, err := e.pub.Open(context.Background(), e.ref(r))
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	archive, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return unpackFake(t, archive)
}

// Missing evidence: a run closed at its timeout without the expected
// report still publishes coverage, but it says the evidence is incomplete,
// carries the owner's counts verbatim, attributes no outcome, and offers no
// automation state that could read as satisfied.
func TestMissingEvidenceCoverageIsIncomplete(t *testing.T) {
	e, name := startedCoverageRun(t)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted {
		t.Fatalf("phase %s", r.Status.Phase)
	}
	rep, d := packagedCoverage(t, packageOf(t, e, r))
	te := rep.TechnicalEvidence
	if te.State != coverage.EvidenceResolved || te.Evidence == nil || te.Evidence.Completeness != publication.Incomplete ||
		te.Evidence.Missing != 1 || *te.Evidence != d.Evidence || te.Outcomes == nil || *te.Outcomes != d.Outcomes {
		t.Fatalf("technical evidence %+v %+v; descriptor %+v", te.Evidence, te.Outcomes, d.Evidence)
	}
	if o := d.Outcomes; o.Pass+o.Fail+o.Error != 0 {
		t.Fatalf("an unreported check has outcomes: %+v", o)
	}
	for _, c := range rep.Controls {
		if ev := c.Evidence; ev != nil && ev.Outcomes != nil && ev.Outcomes.Pass+ev.Outcomes.Fail != 0 {
			t.Fatalf("control %s counts an outcome nobody reported: %+v", c.ID, ev)
		}
	}
	sum := r.Status.Summary.Coverage
	if sum == nil || sum.Automation.None+sum.Automation.Unselected+sum.Automation.Partial+sum.Automation.Unknown != sum.Controls {
		t.Fatalf("summary %+v", sum)
	}
	e.assess("audit-prod")
	if cur := e.current("audit-prod"); cur.Evidence.Completeness == "Complete" {
		t.Fatalf("current evidence %+v", cur.Evidence)
	}
}

// Publication failures: until a package is committed the run has no
// coverage; a failed publication leaves no summary, and the binding's
// current coverage reports no report rather than a complete one.
func TestPublicationFailureLeavesNoCoverage(t *testing.T) {
	for _, op := range []fake.Op{fake.OpStage, fake.OpPublish} {
		t.Run(string(op), func(t *testing.T) {
			e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
			for range 100 {
				e.pub.Fail(op, publication.ErrUnavailable)
			}
			e.deliver("audit-prod")
			e.assess("audit-prod")
			name := e.schedule("audit-prod").ActiveRun.Name
			e.step(name)
			e.report("prod", "pod-1", e.enginePolicy(), "fail", a0.Add(time.Minute))
			e.now = a0.Add(90 * time.Second)
			e.step(name)
			noReport := func(when string) {
				t.Helper()
				e.assess("audit-prod")
				cur := e.current("audit-prod")
				if cur.Coverage == nil || cur.Coverage.State != v1alpha1.CoverageNoReport || cur.Coverage.Summary != nil || cur.Coverage.Run != nil {
					t.Fatalf("%s: current coverage %s", when, asJSON(cur.Coverage))
				}
			}
			if r := e.run(name); r.Status.Phase != v1alpha1.RunPublishing {
				t.Fatalf("outage: %+v", r.Status)
			}
			noReport("publishing")
			e.now = a0.Add(11 * time.Minute)
			e.step(name)
			r := e.run(name)
			if r.Status.Phase != v1alpha1.RunFailed || e.pub.Commits() != 0 {
				t.Fatalf("outage: %+v commits %d", r.Status.Phase, e.pub.Commits())
			}
			if r.Status.Summary != nil && r.Status.Summary.Coverage != nil && r.Status.Summary.Coverage.TechnicalEvidence == coverage.EvidenceResolved &&
				r.Status.Publication != nil && r.Status.Publication.Phase == v1alpha1.PublicationPhase(publication.PhaseCommitted) {
				t.Fatalf("failed publication reads as committed coverage: %+v", r.Status)
			}
			noReport("failed")
		})
	}
}

// Input changes during a run: the profile edited after the run started
// does not rewrite the report, which keeps the selection frozen at start;
// the binding's current coverage then reports ScopeChanged.
func TestProfileEditedDuringRunKeepsFrozenSelection(t *testing.T) {
	e, run, dir := publishedPackage(t, func(e *runEnv, _ *v1alpha1.AssessmentRun) {
		p := &v1alpha1.ComplianceProfile{}
		if err := e.c.Get(context.Background(), client.ObjectKey{Name: "baseline"}, p); err != nil {
			t.Fatal(err)
		}
		p.Spec.Policies = append(p.Spec.Policies, v1alpha1.ProfilePolicy{Name: "added-after-start"})
		if err := e.c.Update(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	})
	rep, _ := packagedCoverage(t, dir)
	if len(rep.Inputs.Selection.Policies) != 1 || rep.Inputs.Selection.Policies[0].Name != pol || !rep.Inventory.Resolved {
		t.Fatalf("selection %+v", rep.Inputs.Selection)
	}
	// The finding stays attributed to the run's own observation.
	if o := rep.TechnicalEvidence.Outcomes; o == nil || o.Fail != 1 || rep.TechnicalEvidence.Evidence.Completeness != publication.Complete {
		t.Fatalf("technical evidence %+v %+v", rep.TechnicalEvidence.Evidence, o)
	}
	e.assess("audit-prod")
	c := e.current("audit-prod").Coverage
	if c.State != v1alpha1.CoverageScopeChanged || c.Run.UID != string(run.UID) {
		t.Fatalf("current coverage %s", asJSON(c))
	}
}

// Unavailable package: once the package can no longer be downloaded the
// retained summary is never current coverage.
func TestCurrentCoverageNeverCurrentWithoutAvailablePackage(t *testing.T) {
	e, run, _ := publishedPackage(t, nil)
	for _, av := range []publication.Availability{publication.AvailabilityUnavailable, publication.AvailabilityExpired, publication.AvailabilityUnknown} {
		r := e.run(run.Name)
		r.Status.Publication.Availability = v1alpha1.Availability(av)
		if err := e.c.Status().Update(context.Background(), r); err != nil {
			t.Fatal(err)
		}
		e.assess("audit-prod")
		c := e.current("audit-prod").Coverage
		if c.State != v1alpha1.CoverageExpired || c.Run == nil || c.Run.UID != string(run.UID) || c.Summary == nil {
			t.Fatalf("%s: current coverage %s", av, asJSON(c))
		}
	}
}
