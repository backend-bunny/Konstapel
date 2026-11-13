package controller

import (
	"context"
	"os"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/observability"
	"github.com/backend-bunny/Konstapel/internal/publication"
	pubfake "github.com/backend-bunny/Konstapel/internal/publication/fake"
)

func (e *runEnv) binding(name string) *v1alpha1.ComplianceBinding {
	e.t.Helper()
	b := &v1alpha1.ComplianceBinding{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, b); err != nil {
		e.t.Fatal(err)
	}
	return b
}

// assessmentMetrics projects the assessment owner's recorded state at now.
func assessmentMetrics(t *testing.T, e *runEnv, now time.Time) map[string]float64 {
	t.Helper()
	hub, term := leadingHub(t, func() time.Time { return now }, observability.DomainAssessment)
	if err := publishAssessment(e.c, hub)(context.Background(), term, now); err != nil {
		t.Fatal(err)
	}
	return metricsOf(t, hub)
}

func ts(t time.Time) float64 { return float64(t.Unix()) }

// The owner records the source evaluation time of the oldest attributable
// observation on current evidence and on the closed run, where it survives
// publication. Absent evidence records none.
func TestOwnerRecordsOldestSourceEvaluation(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	if cur := e.binding("audit-prod").Status.Assessment.Current; cur == nil || cur.OldestEvaluation != nil {
		t.Fatalf("no attributable evidence, oldest %+v", cur)
	}
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	evaluated := a0.Add(time.Minute)
	e.report("prod", "pod-1", e.enginePolicy(), "fail", evaluated)
	e.now = a0.Add(90 * time.Second)
	e.assess("audit-prod")
	cur := e.binding("audit-prod").Status.Assessment.Current
	if cur.OldestEvaluation == nil || !cur.OldestEvaluation.Time.Equal(evaluated) {
		t.Fatalf("current oldest evaluation %v, want the report's %v", cur.OldestEvaluation, evaluated)
	}
	if cur.EvaluatedAt.Time.Equal(evaluated) {
		t.Fatal("fixture cannot tell evaluation from collection time")
	}
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Summary.OldestEvaluation == nil || !r.Status.Summary.OldestEvaluation.Time.Equal(evaluated) {
		t.Fatalf("closed run oldest evaluation %+v (phase %s)", r.Status.Summary.OldestEvaluation, r.Status.Phase)
	}

	// The assessment projection exposes the owner's times.
	m := assessmentMetrics(t, e, e.now)
	want := map[string]float64{
		`konstapel_binding_oldest_evaluation_timestamp_seconds{binding="audit-prod",view="current"}`:       ts(evaluated),
		`konstapel_binding_oldest_evaluation_timestamp_seconds{binding="audit-prod",view="latest_closed"}`: ts(evaluated),
		`konstapel_binding_last_closed_timestamp_seconds{binding="audit-prod"}`:                            ts(r.Status.Window.Closed.Time),
		`konstapel_binding_snapshot_collection_started_timestamp_seconds{binding="audit-prod"}`:            ts(r.Status.Window.Started.Time),
		`konstapel_binding_current_evidence_expiry_timestamp_seconds{binding="audit-prod"}`:                ts(cur.NextExpiry.Time),
		`konstapel_binding_assessment_checks{binding="audit-prod",state="fail",view="current"}`:            1,
		`konstapel_binding_assessment_checks{binding="audit-prod",state="fail",view="latest_closed"}`:      1,
		`konstapel_binding_max_evidence_age_seconds{binding="audit-prod"}`:                                 7200,
		`konstapel_binding_collection_timeout_seconds{binding="audit-prod"}`:                               300,
		`konstapel_binding_assessment_interval_seconds{binding="audit-prod"}`:                              86400,
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %v, want %v", k, m[k], v)
		}
	}
	// At its source-time expiry the current view is unknown; the closed run
	// keeps its own times.
	m = assessmentMetrics(t, e, cur.NextExpiry.Time)
	if m[`konstapel_binding_assessment_status{binding="audit-prod",status="unknown",view="current"}`] != 1 ||
		m[`konstapel_binding_assessment_status{binding="audit-prod",status="known",view="latest_closed"}`] != 1 {
		t.Errorf("at expiry: %v", m)
	}
}

// The initial scheduled run is due from when it was planned until it closes
// with an assessment export; then the next tick is due.
func TestScheduledObligationsAreRecorded(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	s := e.schedule("audit-prod")
	if s.OutstandingSince == nil || !s.OutstandingSince.Time.Equal(a0) {
		t.Fatalf("initial obligation %v", s.OutstandingSince)
	}
	due := `konstapel_binding_scheduled_due_timestamp_seconds{binding="audit-prod"}`
	if m := assessmentMetrics(t, e, a0.Add(time.Hour)); m[due] != ts(a0) {
		t.Errorf("initial run overdue: due %v, want %v", m[due], ts(a0))
	}
	name := s.ActiveRun.Name
	e.step(name)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name) // closes incomplete and publishes
	if r := e.run(name); r.Status.Phase != v1alpha1.RunCompleted || r.Status.Summary.Evidence.Completeness != "Incomplete" {
		t.Fatalf("run %+v", r.Status)
	}
	e.assess("audit-prod")
	if s = e.schedule("audit-prod"); s.OutstandingSince != nil || s.ActiveRun != nil {
		t.Fatalf("an incomplete assessment did not meet its obligation: %+v", s)
	}
	if m := assessmentMetrics(t, e, e.now); m[due] != ts(a0.Add(24*time.Hour)) {
		t.Errorf("next due %v", m[due])
	}
}

// A lost capture does not meet its scheduled obligation.
func TestLostCaptureLeavesObligationOutstanding(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	if err := os.RemoveAll(e.rr.staging(e.run(name))); err != nil {
		t.Fatal(err)
	}
	e.now = a0.Add(time.Minute)
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunFailed || r.Status.Summary.Export != "CaptureLost" {
		t.Fatalf("run %+v", r.Status)
	}
	e.assess("audit-prod")
	if s := e.schedule("audit-prod"); s.ActiveRun != nil || s.OutstandingSince == nil || !s.OutstandingSince.Time.Equal(a0) {
		t.Fatalf("lost capture met the obligation: %+v", s)
	}
}

// A run that exported an assessment met its collection obligation even if
// publication later failed; publication health is reported separately.
func TestPublicationFailureAfterExportMeetsObligation(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	for range 100 {
		e.pub.Fail(pubfake.OpStage, publication.ErrUnavailable)
	}
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	e.now = a0.Add(11 * time.Minute)
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunFailed || r.Status.Summary.Export != "Assessment" {
		t.Fatalf("run %+v", r.Status)
	}
	e.assess("audit-prod")
	if s := e.schedule("audit-prod"); s.OutstandingSince != nil {
		t.Fatalf("an exported assessment left its obligation outstanding: %+v", s)
	}
}

// Only finished scheduled runs that exported an assessment meet anything.
func TestScheduledMet(t *testing.T) {
	at := metav1.NewTime(a0)
	run := func(trigger v1alpha1.TriggerType, phase v1alpha1.RunPhase, export v1alpha1.ExportState) *v1alpha1.AssessmentRun {
		r := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "r", UID: "uid-r"}}
		// Every trigger carries a time here, so only the trigger type can
		// tell a scheduled run apart (admission rejects it on others).
		r.Spec.Trigger = &v1alpha1.RunTrigger{Type: trigger, ScheduledTime: &at}
		r.Status.Phase = phase
		if export != "" {
			r.Status.Summary = &v1alpha1.AssessmentSummary{Export: export}
		}
		return r
	}
	for _, c := range []struct {
		name string
		run  *v1alpha1.AssessmentRun
		met  bool
	}{
		{"completed assessment", run(v1alpha1.TriggerScheduled, v1alpha1.RunCompleted, "Assessment"), true},
		{"publication failed after export", run(v1alpha1.TriggerScheduled, v1alpha1.RunFailed, "Assessment"), true},
		{"diagnostic", run(v1alpha1.TriggerScheduled, v1alpha1.RunCompleted, "Diagnostic"), false},
		{"capture lost", run(v1alpha1.TriggerScheduled, v1alpha1.RunFailed, "CaptureLost"), false},
		{"failed before closing", run(v1alpha1.TriggerScheduled, v1alpha1.RunFailed, ""), false},
		{"still publishing", run(v1alpha1.TriggerScheduled, v1alpha1.RunPublishing, "Assessment"), false},
		{"manual", run(v1alpha1.TriggerManual, v1alpha1.RunCompleted, "Assessment"), false},
		{"namespace request", run(v1alpha1.TriggerRequest, v1alpha1.RunCompleted, "Assessment"), false},
	} {
		if got := !scheduledMet(c.run).IsZero(); got != c.met {
			t.Errorf("%s: met=%v, want %v", c.name, got, c.met)
		}
	}
}
