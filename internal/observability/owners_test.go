package observability

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
)

func bindingObj(name string, gen int64, conds ...metav1.Condition) v1alpha1.ComplianceBinding {
	b := v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID("uid-" + name), Generation: gen, CreationTimestamp: metav1.NewTime(t0.Add(-time.Hour))}}
	b.Status.Conditions = conds
	return b
}

func cond(t string, s metav1.ConditionStatus, gen int64) metav1.Condition {
	return metav1.Condition{Type: t, Status: s, ObservedGeneration: gen, Reason: "R"}
}

// Conditions and target counts describe the binding only when observed for
// its current generation; otherwise they are unknown, never last-known.
func TestBindingTargetingFromStatus(t *testing.T) {
	two := int32(2)
	cur := bindingObj("cur", 3, cond(v1alpha1.ConditionResolved, metav1.ConditionTrue, 3), cond(v1alpha1.ConditionEngineReady, metav1.ConditionFalse, 3))
	cur.Status.ObservedGeneration, cur.Status.TargetCount = 3, &two
	got := BindingTargetingFrom(&cur)
	if got.Resolved != StatusTrue || got.EngineReady != StatusFalse || got.TargetNamespaces == nil || *got.TargetNamespaces != 2 ||
		got.Binding != (BindingRef{Name: "cur", UID: "uid-cur"}) || !got.Created.Equal(t0.Add(-time.Hour)) {
		t.Errorf("current status: %+v", got)
	}

	stale := bindingObj("stale", 4, cond(v1alpha1.ConditionResolved, metav1.ConditionTrue, 3), cond(v1alpha1.ConditionEngineReady, metav1.ConditionTrue, 4))
	stale.Status.ObservedGeneration, stale.Status.TargetCount = 3, &two
	got = BindingTargetingFrom(&stale)
	if got.Resolved != StatusUnknown || got.EngineReady != StatusTrue || got.TargetNamespaces != nil {
		t.Errorf("stale generation: %+v", got)
	}

	zero := int32(0)
	empty := bindingObj("empty", 1, cond(v1alpha1.ConditionResolved, metav1.ConditionUnknown, 1))
	empty.Status.ObservedGeneration, empty.Status.TargetCount = 1, &zero
	got = BindingTargetingFrom(&empty)
	if got.Resolved != StatusUnknown || got.EngineReady != StatusUnknown || got.TargetNamespaces == nil || *got.TargetNamespaces != 0 {
		t.Errorf("unknown/missing conditions, zero targets: %+v", got)
	}
	s := TargetingFrom([]v1alpha1.ComplianceBinding{cur, stale, empty}, map[Capability]Status{CapabilityAssessment: StatusFalse})
	if len(s.Bindings) != 3 || s.validate() != nil {
		t.Errorf("snapshot: %+v %v", s, s.validate())
	}
}

func pubRun(name string, phase v1alpha1.RunPhase, edit func(*v1alpha1.AssessmentRun)) v1alpha1.AssessmentRun {
	r := v1alpha1.AssessmentRun{ObjectMeta: metav1.ObjectMeta{Name: name}}
	r.Status.Phase = phase
	if edit != nil {
		edit(&r)
	}
	return r
}

func committed(expires time.Time, cleanup string) func(*v1alpha1.AssessmentRun) {
	return func(r *v1alpha1.AssessmentRun) {
		e := metav1.NewTime(expires)
		r.Status.Publication = &v1alpha1.PublicationStatus{Phase: "Committed", ExpiresAt: &e, Cleanup: v1alpha1.PublicationCleanup{State: v1alpha1.CleanupState(cleanup)}}
	}
}

// The backlog comes from retained run records: actionable publication
// failures are separate from pending work and from historical failures,
// and cleanup counts only unconfirmed deletions.
func TestStorageFromRuns(t *testing.T) {
	retrying := func(r *v1alpha1.AssessmentRun) {
		r.Status.Conditions = []metav1.Condition{{Type: v1alpha1.ConditionPublished, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonPublicationRetrying}}
	}
	historical := func(r *v1alpha1.AssessmentRun) {
		r.Status.Conditions = []metav1.Condition{{Type: v1alpha1.ConditionPublished, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonPublicationFailed}}
	}
	runs := []v1alpha1.AssessmentRun{
		pubRun("collecting", v1alpha1.RunCollecting, nil),
		pubRun("publishing", v1alpha1.RunPublishing, nil),
		pubRun("retrying", v1alpha1.RunPublishing, retrying),
		pubRun("signing-pending", v1alpha1.RunPublishing, func(r *v1alpha1.AssessmentRun) {
			r.Status.Conditions = []metav1.Condition{{Type: v1alpha1.ConditionPublished, Status: metav1.ConditionFalse, Reason: v1alpha1.ReasonSigningPending}}
		}),
		pubRun("failed-for-good", v1alpha1.RunFailed, historical),
		pubRun("retained", v1alpha1.RunCompleted, committed(t0.Add(time.Hour), "NotDue")),
		pubRun("expired", v1alpha1.RunCompleted, committed(t0.Add(-2*time.Hour), "NotDue")),
		pubRun("deletion-failed", v1alpha1.RunCompleted, committed(t0.Add(-time.Hour), "DeletionFailed")),
		pubRun("blocked", v1alpha1.RunCompleted, committed(t0.Add(-3*time.Hour), "RetentionBlocked")),
		pubRun("deleted", v1alpha1.RunCompleted, committed(t0.Add(-4*time.Hour), "Deleted")),
		pubRun("orphaned", v1alpha1.RunCompleted, committed(t0.Add(-5*time.Hour), "Orphaned")),
	}
	got := StorageFrom(runs, t0)
	want := StorageSnapshot{PublicationPending: 1, PublicationFailed: 2, CleanupPending: 2, CleanupBlocked: 1, OldestCleanupExpiry: ptr(t0.Add(-3 * time.Hour))}
	if got.PublicationPending != want.PublicationPending || got.PublicationFailed != want.PublicationFailed || got.CleanupPending != want.CleanupPending ||
		got.CleanupBlocked != want.CleanupBlocked || got.OldestCleanupExpiry == nil || !got.OldestCleanupExpiry.Equal(*want.OldestCleanupExpiry) {
		t.Errorf("backlog = %+v, want %+v", got, want)
	}
	if err := got.validate(); err != nil {
		t.Error(err)
	}
	// Expiry is evaluated at the projection time.
	if s := StorageFrom(runs[5:6], t0.Add(time.Hour)); s.CleanupPending != 1 {
		t.Errorf("expiry at the projection time: %+v", s)
	}
	if s := StorageFrom(nil, t0); s != (StorageSnapshot{}) {
		t.Errorf("no records: %+v", s)
	}
}

type refresherWorld struct {
	hub   *Hub
	clk   *clocktesting.FakeClock
	mu    sync.Mutex
	calls int
	fail  error
	terms []Term
}

func (w *refresherWorld) publish(_ context.Context, term Term, now time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	w.terms = append(w.terms, term)
	if w.fail != nil {
		return w.fail
	}
	return w.hub.PublishStorage(term, now, StorageSnapshot{})
}

func (w *refresherWorld) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.calls
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// The Refresher waits for synchronization and the leadership term,
// publishes on triggers and at its interval, withdraws when owner state
// cannot be read, and stops with its context.
func TestRefresher(t *testing.T) {
	clk := clocktesting.NewFakeClock(t0)
	hub, err := NewHub(Options{Enabled: []Domain{DomainEvidenceStorage}, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	w := &refresherWorld{hub: hub, clk: clk}
	trigger, notify := Notifier()
	synced := make(chan bool)
	r := &Refresher{Name: "test", Hub: hub, Domain: DomainEvidenceStorage, Clock: clk, Publish: w.publish, Trigger: trigger,
		Synced: func(context.Context) bool { return <-synced }}
	if !r.NeedLeaderElection() {
		t.Fatal("refresher must run on the leader only")
	}
	// Leading but not synchronized: nothing is published.
	term := hub.Acquire()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- r.Start(ctx) }()
	time.Sleep(20 * time.Millisecond)
	if w.count() != 0 {
		t.Fatal("published before synchronization")
	}
	select {
	case synced <- true:
	case <-time.After(5 * time.Second):
		t.Fatal("the refresher never waited for synchronization")
	}
	waitFor(t, "first publication", func() bool { return w.count() == 1 })
	ready := func() bool { return scrape(t, hub)[`konstapel_observation_ready{domain="evidence_storage"}`] == 1 }
	if !ready() {
		t.Fatal("published projection is not ready")
	}

	notify()
	waitFor(t, "triggered publication", func() bool { return w.count() == 2 })
	waitFor(t, "interval timer", clk.HasWaiters)
	clk.Step(DefaultRefreshInterval)
	waitFor(t, "interval publication", func() bool { return w.count() == 3 })

	w.mu.Lock()
	w.fail = errors.New("cache not synchronized")
	w.mu.Unlock()
	notify()
	waitFor(t, "withdrawal", func() bool { return w.count() == 4 && !ready() })
	if _, ok := scrape(t, hub)[`konstapel_observation_updated_timestamp_seconds{domain="evidence_storage"}`]; ok {
		t.Error("withdrawn projection keeps its production time")
	}
	w.mu.Lock()
	w.fail = nil
	for _, got := range w.terms {
		if got != term {
			t.Errorf("published for term %d, want %d", got, term)
		}
	}
	w.mu.Unlock()
	notify()
	waitFor(t, "recovery", func() bool { return w.count() == 5 && ready() })

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// Not leading: it retries without publishing, and publishes once the
	// term starts.
	idle, _ := NewHub(Options{Enabled: []Domain{DomainEvidenceStorage}, Clock: clk})
	w2 := &refresherWorld{hub: idle, clk: clk}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error)
	go func() {
		done2 <- (&Refresher{Hub: idle, Domain: DomainEvidenceStorage, Clock: clk, Publish: w2.publish}).Start(ctx2)
	}()
	waitFor(t, "retry timer", clk.HasWaiters)
	if w2.count() != 0 {
		t.Fatal("published without a leadership term")
	}
	idle.Acquire()
	clk.Step(time.Second)
	waitFor(t, "publication after acquisition", func() bool { return w2.count() == 1 })
	cancel2()
	<-done2

	// Not synchronized: it never publishes.
	r2 := &Refresher{Hub: hub, Domain: DomainEvidenceStorage, Clock: clk, Publish: w.publish, Synced: func(context.Context) bool { return false }}
	if err := r2.Start(context.Background()); err != nil || w.count() != 5 {
		t.Errorf("unsynchronized refresher published: %v", err)
	}
}
