package controller

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/publication/fake"
)

type runEnv struct {
	*assessEnv
	pub *fake.Publisher
	rr  *AssessmentRunReconciler
}

func newRunEnv(t *testing.T, objs ...*v1alpha1.ComplianceBinding) *runEnv {
	base := []client.Object{nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol), privilegedPod("prod", "web", "pod-1")}
	for _, b := range objs {
		base = append(base, b)
	}
	e := newAssessEnv(t, base...)
	pub := fake.New(func() time.Time { return e.now })
	root, _ := filepath.Abs("../..")
	rt := AssessmentRuntime{Publisher: pub, StagingDir: t.TempDir(), ContentRoot: root, Poll: 10 * time.Second, PublishTimeout: 5 * time.Minute, Workers: 2}
	e.ar.Runtime = rt
	return &runEnv{assessEnv: e, pub: pub, rr: &AssessmentRunReconciler{Client: e.c, Assess: e.ar, Runtime: rt, Now: func() time.Time { return e.now }}}
}

func (e *runEnv) step(name string) ctrl.Result {
	e.t.Helper()
	res, err := e.rr.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}})
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

func (e *runEnv) run(name string) *v1alpha1.AssessmentRun {
	e.t.Helper()
	r := &v1alpha1.AssessmentRun{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, r); err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *runEnv) schedule(binding string) *v1alpha1.AssessmentSchedule {
	e.t.Helper()
	b := &v1alpha1.ComplianceBinding{}
	_ = e.c.Get(context.Background(), client.ObjectKey{Name: binding}, b)
	if b.Status.Assessment == nil || b.Status.Assessment.Schedule == nil {
		e.t.Fatalf("no schedule on %s", binding)
	}
	return b.Status.Assessment.Schedule
}

func (e *runEnv) runs() []v1alpha1.AssessmentRun {
	var l v1alpha1.AssessmentRunList
	_ = e.c.List(context.Background(), &l)
	return l.Items
}

func shortTimeout(b *v1alpha1.ComplianceBinding) *v1alpha1.ComplianceBinding {
	b.Spec.Assessment = &v1alpha1.BindingAssessment{CollectionTimeout: "5m"}
	return b
}

func TestScheduledRunLifecycle(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	s := e.schedule("audit-prod")
	if s.ActiveRun == nil || len(e.runs()) != 1 {
		t.Fatalf("initial scheduled run not created: %+v", s)
	}
	name := s.ActiveRun.Name
	if r := e.run(name); r.Spec.Trigger == nil || r.Spec.Trigger.Type != v1alpha1.TriggerScheduled || r.Labels[LabelRunBinding] != "uid-audit-prod" {
		t.Fatalf("run %+v", r.Spec)
	}
	// Planning again is idempotent: same run, no duplicate.
	e.assess("audit-prod")
	if len(e.runs()) != 1 {
		t.Fatal("re-planning duplicated the run")
	}

	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCollecting || r.Status.Binding == nil || r.Status.Scope == nil || r.Status.Scope.NamespaceCount != 1 {
		t.Fatalf("start: %+v", r.Status)
	}
	if _, err := os.Stat(filepath.Join(e.rr.staging(r), "capture.json")); err != nil {
		t.Fatal("capture not staged:", err)
	}
	// Not yet complete: keeps collecting.
	e.now = a0.Add(30 * time.Second)
	if res := e.step(name); res.RequeueAfter != 10*time.Second || e.run(name).Status.Phase != v1alpha1.RunCollecting {
		t.Fatalf("closed before evidence or timeout: %+v", e.run(name).Status.Phase)
	}
	// An evaluation after observation completes the evidence: closes early.
	e.report("prod", "pod-1", e.enginePolicy(), "fail", a0.Add(time.Minute))
	e.now = a0.Add(90 * time.Second)
	e.step(name)
	r = e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Publication == nil || r.Status.Publication.Phase != "Committed" ||
		r.Status.Summary.Evidence.Completeness != "Complete" || r.Status.Summary.Outcomes.Fail != 1 || r.Status.Window.Closed == nil {
		t.Fatalf("completed run %+v", r.Status)
	}
	if r.Status.Publication.Retention == nil || r.Status.Publication.Retention.Duration != "2160h0m0s" {
		t.Fatalf("retention %+v", r.Status.Publication.Retention)
	}
	if _, err := os.Stat(e.rr.staging(r)); !os.IsNotExist(err) {
		t.Fatal("staging not cleaned after publication")
	}
	// The slot frees; the next run is due a full interval after the anchor.
	e.assess("audit-prod")
	if s = e.schedule("audit-prod"); s.ActiveRun != nil || !s.NextDue.Equal(&metav1.Time{Time: a0.Add(24 * time.Hour)}) {
		t.Fatalf("slot not released or wrong next due: %+v", s)
	}
	e.now = a0.Add(24*time.Hour + time.Minute)
	e.assess("audit-prod")
	if s = e.schedule("audit-prod"); s.ActiveRun == nil || s.ActiveRun.Name == name || len(e.runs()) != 2 {
		t.Fatalf("next scheduled run not created: %+v", s)
	}
}

func TestRunClosesIncompleteAtTimeoutAndStillPublishes(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Summary == nil || r.Status.Summary.Evidence.Completeness != "Incomplete" || r.Status.Summary.Evidence.Missing != 1 {
		t.Fatalf("%+v %+v", r.Status, r.Status.Conditions)
	}
	if c := meta.FindStatusCondition(r.Status.Conditions, v1alpha1.ConditionEvidenceComplete); c == nil || c.Status != metav1.ConditionFalse {
		t.Fatalf("EvidenceComplete %+v", c)
	}
	if e.pub.Commits() != 1 {
		t.Fatal("incomplete snapshot was not published")
	}
}

func TestPublisherOutageFailsAndReleasesSlot(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	for range 100 {
		e.pub.Fail(fake.OpStage, publication.ErrUnavailable)
	}
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunPublishing || r.Status.Summary == nil {
		t.Fatalf("outage must keep retrying with evidence recorded: %+v", r.Status)
	}
	e.now = a0.Add(11 * time.Minute)
	e.step(name)
	r := e.run(name)
	c := meta.FindStatusCondition(r.Status.Conditions, v1alpha1.ConditionPublished)
	if r.Status.Phase != v1alpha1.RunFailed || c == nil || c.Reason != v1alpha1.ReasonPublicationFailed || r.Status.Summary.Evidence.Expected != 1 {
		t.Fatalf("outage: %+v %+v", r.Status.Phase, c)
	}
	e.assess("audit-prod")
	if s := e.schedule("audit-prod"); s.ActiveRun != nil {
		t.Fatal("failed publication did not release the binding's slot")
	}
}

func TestLostCaptureIsExplicit(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	if err := os.RemoveAll(e.rr.staging(e.run(name))); err != nil { // controller restart without durable staging
		t.Fatal(err)
	}
	e.now = a0.Add(time.Minute)
	e.step(name)
	r := e.run(name)
	c := meta.FindStatusCondition(r.Status.Conditions, v1alpha1.ConditionPublished)
	if r.Status.Phase != v1alpha1.RunFailed || c == nil || c.Reason != v1alpha1.ReasonCaptureLost || r.Status.Summary == nil || r.Status.Summary.Export != "CaptureLost" {
		t.Fatalf("%+v %+v", r.Status, c)
	}
	if e.pub.Commits() != 0 {
		t.Fatal("a lost capture was replaced by newer observations")
	}
}

func TestSchedulingDisabledWithoutPublisher(t *testing.T) {
	e := newAssessEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol),
		epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	cur := e.current("audit-prod")
	if !strings.Contains(strings.Join(cur.Limitations, ";"), "scheduled snapshots are disabled: no evidence publisher is configured") {
		t.Fatalf("missing publisher not surfaced: %v", cur.Limitations)
	}
	var l v1alpha1.AssessmentRunList
	_ = e.c.List(context.Background(), &l)
	if len(l.Items) != 0 {
		t.Fatal("runs created without a publisher")
	}
}

func TestManualRunWaitsForScheduledFirst(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	manual := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "manual-1", UID: "manual-uid"},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: "audit-prod"}, Scope: v1alpha1.RunScopeBinding}}
	if err := e.c.Create(context.Background(), manual); err != nil {
		t.Fatal(err)
	}
	e.assess("audit-prod")
	scheduled := e.schedule("audit-prod").ActiveRun.Name
	if scheduled == "manual-1" {
		t.Fatal("manual run admitted before the initial scheduled run")
	}
	e.step("manual-1")
	if e.run("manual-1").Status.Phase != v1alpha1.RunPending {
		t.Fatal("unadmitted manual run must wait as Pending")
	}
	e.step(scheduled)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(scheduled)
	e.assess("audit-prod")
	if s := e.schedule("audit-prod"); s.ActiveRun == nil || s.ActiveRun.Name != "manual-1" {
		t.Fatalf("manual run not admitted after the slot freed: %+v", s.ActiveRun)
	}
	if !e.schedule("audit-prod").LastScheduled.Equal(&metav1.Time{Time: a0}) {
		t.Fatal("manual run moved the schedule")
	}
	e.step("manual-1")
	if e.run("manual-1").Status.Phase != v1alpha1.RunCollecting {
		t.Fatal("admitted manual run did not start")
	}
}

// A namespace run the binding's schedule did not admit (for example, one
// created by someone other than the planner) never executes; it waits.
func TestUnadmittedNamespaceRunWaits(t *testing.T) {
	e := newRunEnv(t, epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"}))
	r := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: "ns-run"}, Spec: v1alpha1.AssessmentRunSpec{
		BindingRef: v1alpha1.BindingReference{Name: "audit-prod"}, Scope: v1alpha1.RunScopeNamespace,
		Request: &v1alpha1.RequestReference{Namespace: "prod", Name: "r", UID: "u"}, Trigger: &v1alpha1.RunTrigger{Type: v1alpha1.TriggerRequest}}}
	if err := e.c.Create(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	e.step("ns-run")
	if got := e.run("ns-run"); got.Status.Phase != v1alpha1.RunPending || got.Status.Scope != nil {
		t.Fatalf("%+v", got.Status)
	}
}

// laggingCache hides AssessmentRuns from Get, like an informer cache that
// has not yet observed a run created moments ago.
type laggingCache struct{ client.Client }

func (c laggingCache) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*v1alpha1.AssessmentRun); ok {
		return apierrors.NewNotFound(v1alpha1.GroupVersion.WithResource("assessmentruns").GroupResource(), key.Name)
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

// A cache that has not yet seen the active run must not free the binding's
// slot: the planner reads runs through the uncached reader.
func TestCacheLagDoesNotReleaseActiveRun(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	e.ar.Reader = e.c
	e.ar.Client = laggingCache{e.c}
	e.assess("audit-prod")
	active := e.schedule("audit-prod").ActiveRun
	if active == nil {
		t.Fatal("no run admitted")
	}
	e.now = a0.Add(time.Minute)
	e.assess("audit-prod")
	if s := e.schedule("audit-prod"); s.ActiveRun == nil || s.ActiveRun.Name != active.Name || len(e.runs()) != 1 {
		t.Fatalf("cache lag released the active run: %+v", s.ActiveRun)
	}
}

// A plan computed from a stale binding must not overwrite a newer schedule:
// the status apply is conditioned on the binding's resourceVersion.
func TestStaleBindingCannotOverwriteSchedule(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	stale := &v1alpha1.ComplianceBinding{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: "audit-prod"}, stale); err != nil {
		t.Fatal(err)
	}
	e.assess("audit-prod") // admits the initial run and persists the schedule
	active := e.schedule("audit-prod").ActiveRun
	if active == nil {
		t.Fatal("no run admitted")
	}
	err := e.ar.apply(context.Background(), stale, &v1alpha1.BindingAssessmentStatus{Schedule: &v1alpha1.AssessmentSchedule{Anchor: metav1.NewTime(a0), Interval: "24h"}})
	if !apierrors.IsConflict(err) {
		t.Fatalf("stale apply must conflict, got %v", err)
	}
	if s := e.schedule("audit-prod"); s.ActiveRun == nil || s.ActiveRun.Name != active.Name {
		t.Fatalf("stale plan overwrote the schedule: %+v", s)
	}
}

// A plan from a stale binding (its schedule not yet visible) must not create
// a run: the run name is derived from the anchor, so a stale anchor would
// create a duplicate scheduled run before the status apply could conflict.
func TestStaleBindingCreatesNoDuplicateRun(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	stale := &v1alpha1.ComplianceBinding{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: "audit-prod"}, stale); err != nil {
		t.Fatal(err)
	}
	e.assess("audit-prod") // creates the initial run and persists the anchor
	if len(e.runs()) != 1 {
		t.Fatalf("setup: %d runs", len(e.runs()))
	}
	e.now = e.now.Add(time.Second)
	first := e.runs()[0].Name
	// The first-schedule lookup adopts a run it can see; hide it so the
	// stale plan reaches the run creation and its resourceVersion guard.
	e.ar.Reader = hideRuns{Client: e.c, hide: first}
	if _, _, _, _, err := e.ar.plan(context.Background(), stale, e.now); !apierrors.IsConflict(err) {
		t.Fatalf("stale plan must conflict before creating anything, got %v", err)
	}
	if n := len(e.runs()); n != 1 {
		t.Fatalf("stale plan created a duplicate run: %d runs", n)
	}
	// Seeing the run, the stale plan adopts it instead of creating another.
	e.ar.Reader = e.c
	sched, _, _, _, err := e.ar.plan(context.Background(), stale, e.now)
	if err != nil || sched == nil || sched.ActiveRun == nil || sched.ActiveRun.Name != first {
		t.Fatalf("stale plan with the run visible: %v %+v", err, sched)
	}
	if n := len(e.runs()); n != 1 {
		t.Fatalf("stale plan created a duplicate run: %d runs", n)
	}
}

// A plan that created the first scheduled run but whose status write then
// lost to another writer must not leave that run behind: the replan, a second
// later, adopts it instead of deriving a new anchor and a duplicate run.
func TestLostFirstScheduleWriteAdoptsTheCreatedRun(t *testing.T) {
	e, created := lostFirstSchedule(t)
	e.now = e.now.Add(time.Second)
	e.assess("audit-prod")
	e.wantAdopted(created, 1)
}

// The adoption survives a replan more than one interval later (scheduling
// was disabled meanwhile): the created run is admitted, not replaced by a
// run for the latest due time.
func TestLostFirstScheduleWriteAdoptedAfterAnInterval(t *testing.T) {
	e, created := lostFirstSchedule(t)
	e.now = e.now.Add(25 * time.Hour)
	e.assess("audit-prod")
	e.wantAdopted(created, 1)
}

// The run informer can lag behind the binding's: a replan whose cached run
// list does not yet contain the created run still adopts it, because the
// first-schedule lookup reads uncached.
func TestLostFirstScheduleWriteAdoptedDespiteRunCacheLag(t *testing.T) {
	e, created := lostFirstSchedule(t)
	e.ar.Reader = e.c
	e.ar.Client = hideRuns{Client: e.c, hide: created.Name}
	e.now = e.now.Add(time.Second)
	e.assess("audit-prod")
	e.wantAdopted(created, 1)
}

// Only an unfinished scheduled run of the same binding (by UID) is adopted,
// the earliest when there are several; other bindings' runs, a same-named
// binding's runs, finished runs and manual runs never anchor the schedule.
func TestFirstScheduleAdoptsOnlyOwnUnfinishedScheduledRuns(t *testing.T) {
	ignored := []struct {
		name, binding, uid string
		trigger            v1alpha1.TriggerType
		phase              v1alpha1.RunPhase
	}{
		{"other-binding", "other", "", v1alpha1.TriggerScheduled, ""},
		{"replaced-binding", "audit-prod", "uid-old", v1alpha1.TriggerScheduled, v1alpha1.RunPending},
		{"completed", "audit-prod", "", v1alpha1.TriggerScheduled, v1alpha1.RunCompleted},
		{"failed", "audit-prod", "", v1alpha1.TriggerScheduled, v1alpha1.RunFailed},
		{"manual", "audit-prod", "", v1alpha1.TriggerManual, v1alpha1.RunPending},
		{"request", "audit-prod", "", v1alpha1.TriggerRequest, v1alpha1.RunPending},
	}
	for _, c := range ignored {
		t.Run(c.name, func(t *testing.T) {
			e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
			e.deliver("audit-prod")
			uid := c.uid
			if uid == "" {
				uid = string(e.bindingUID("audit-prod"))
			}
			e.scheduledRun(c.name, c.binding, uid, c.trigger, e.now.Add(-time.Hour), c.phase)
			e.assess("audit-prod")
			if s := e.schedule("audit-prod"); !s.Anchor.Time.Equal(e.now) || s.ActiveRun == nil || s.ActiveRun.Name == c.name {
				t.Fatalf("schedule %+v adopted %s", s, c.name)
			}
		})
	}
	t.Run("earliest", func(t *testing.T) {
		e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
		e.deliver("audit-prod")
		uid := string(e.bindingUID("audit-prod"))
		later := e.scheduledRun("later", "audit-prod", uid, v1alpha1.TriggerScheduled, e.now.Add(-time.Minute), "")
		earlier := e.scheduledRun("earlier", "audit-prod", uid, v1alpha1.TriggerScheduled, e.now.Add(-time.Hour), v1alpha1.RunPending)
		e.assess("audit-prod")
		e.wantAdopted(earlier, 2)
		if r := e.run(later.Name); r.Status.Phase != "" {
			t.Fatalf("the later run changed: %s", r.Status.Phase)
		}
	})
}

// lostFirstSchedule plans the binding's first run without persisting the
// schedule, as when the status write loses to another writer.
func lostFirstSchedule(t *testing.T) (*runEnv, *v1alpha1.AssessmentRun) {
	t.Helper()
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	e.deliver("audit-prod")
	b := &v1alpha1.ComplianceBinding{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: "audit-prod"}, b); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := e.ar.plan(context.Background(), b, e.now); err != nil {
		t.Fatal(err)
	}
	created := e.runs()
	if len(created) != 1 {
		t.Fatalf("setup: %d runs", len(created))
	}
	return e, &created[0]
}

// wantAdopted checks that the binding has n runs and that its schedule
// admits run, anchored at its scheduled time.
func (e *runEnv) wantAdopted(run *v1alpha1.AssessmentRun, n int) {
	e.t.Helper()
	if got := e.runs(); len(got) != n {
		e.t.Fatalf("replan created a duplicate scheduled run: %d runs", len(got))
	}
	s := e.schedule("audit-prod")
	if s.ActiveRun == nil || s.ActiveRun.Name != run.Name || !s.Anchor.Time.Equal(run.Spec.Trigger.ScheduledTime.Time) {
		e.t.Fatalf("schedule %+v does not adopt %s", s, run.Name)
	}
}

func (e *runEnv) bindingUID(name string) types.UID {
	e.t.Helper()
	b := &v1alpha1.ComplianceBinding{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, b); err != nil {
		e.t.Fatal(err)
	}
	return b.UID
}

func (e *runEnv) scheduledRun(name, binding, uid string, trigger v1alpha1.TriggerType, at time.Time, phase v1alpha1.RunPhase) *v1alpha1.AssessmentRun {
	e.t.Helper()
	when := metav1.NewTime(at)
	r := &v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{LabelRunBinding: uid}},
		Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: binding}, Scope: v1alpha1.RunScopeBinding,
			Trigger: &v1alpha1.RunTrigger{Type: trigger}}}
	if trigger == v1alpha1.TriggerScheduled {
		r.Spec.Trigger.ScheduledTime = &when
	}
	if err := e.c.Create(context.Background(), r); err != nil {
		e.t.Fatal(err)
	}
	if phase != "" {
		r.Status.Phase = phase
		if err := e.c.Status().Update(context.Background(), r); err != nil {
			e.t.Fatal(err)
		}
	}
	return r
}

// hideRuns is a client whose run lists lag behind: they omit one run.
type hideRuns struct {
	client.Client
	hide string
}

func (h hideRuns) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if err := h.Client.List(ctx, list, opts...); err != nil {
		return err
	}
	if runs, ok := list.(*v1alpha1.AssessmentRunList); ok {
		runs.Items = slices.DeleteFunc(runs.Items, func(r v1alpha1.AssessmentRun) bool { return r.Name == h.hide })
	}
	return nil
}
