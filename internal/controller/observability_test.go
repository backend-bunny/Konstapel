package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clocktesting "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/bundle/stack"
	"github.com/backend-bunny/Konstapel/internal/capability"
	"github.com/backend-bunny/Konstapel/internal/observability"
	"github.com/backend-bunny/Konstapel/internal/publication"
	pubfake "github.com/backend-bunny/Konstapel/internal/publication/fake"
)

// metricsOf scrapes hub and returns each series as `name{l="v",...}`.
func metricsOf(t *testing.T, hub *observability.Hub) map[string]float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(hub)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, f := range families {
		for _, m := range f.Metric {
			var ls []string
			for _, l := range m.Label {
				ls = append(ls, fmt.Sprintf("%s=%q", l.GetName(), l.GetValue()))
			}
			key := f.GetName() + "{" + strings.Join(ls, ",") + "}"
			switch {
			case m.Gauge != nil:
				out[key] = m.Gauge.GetValue()
			case m.Counter != nil:
				out[key] = m.Counter.GetValue()
			}
		}
	}
	return out
}

func leadingHub(t *testing.T, now func() time.Time, domains ...observability.Domain) (*observability.Hub, observability.Term) {
	t.Helper()
	clk := clocktesting.NewFakePassiveClock(now())
	hub, err := observability.NewHub(observability.Options{Enabled: domains, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	return hub, hub.Acquire()
}

type countingChecker struct {
	results map[capability.Name]capability.Result
	calls   atomic.Int64
}

func (c *countingChecker) Check(_ context.Context, n capability.Name) capability.Result {
	c.calls.Add(1)
	return c.results[n]
}

type countingReader struct {
	client.Reader
	lists atomic.Int64
}

func (r *countingReader) List(ctx context.Context, l client.ObjectList, opts ...client.ListOption) error {
	r.lists.Add(1)
	return r.Reader.List(ctx, l, opts...)
}

// Assessment reporting can be unavailable while policy delivery works:
// both are visible, and the binding's EngineReady is unaffected. Stale
// generations are unknown. Scraping causes no owner reads.
func TestTargetingProjection(t *testing.T) {
	ready := &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "ready", UID: "uid-ready", Generation: 2}}
	two := int32(2)
	ready.Status = v1alpha1.ComplianceBindingStatus{ObservedGeneration: 2, TargetCount: &two, Conditions: []metav1.Condition{
		{Type: v1alpha1.ConditionResolved, Status: metav1.ConditionTrue, ObservedGeneration: 2, Reason: "Resolved"},
		{Type: v1alpha1.ConditionEngineReady, Status: metav1.ConditionTrue, ObservedGeneration: 2, Reason: "EngineReady"}}}
	edited := ready.DeepCopy()
	edited.Name, edited.UID, edited.Generation = "edited", "uid-edited", 3
	c := &countingReader{Reader: fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(ready, edited).WithStatusSubresource(ready, edited).Build()}
	caps := &countingChecker{results: map[capability.Name]capability.Result{
		capability.Delivery:   {Name: capability.Delivery, Reason: capability.Available},
		capability.Assessment: {Name: capability.Assessment, Reason: capability.AccessDenied, Message: "reports: forbidden for system:serviceaccount:konstapel:secret-sa"},
	}}
	hub, term := leadingHub(t, func() time.Time { return a0 }, observability.DomainTargeting)
	if err := publishTargeting(c, hub, caps)(context.Background(), term, a0); err != nil {
		t.Fatal(err)
	}
	reads, checks := c.lists.Load(), caps.calls.Load()
	var got map[string]float64
	for range 20 {
		got = metricsOf(t, hub)
	}
	if c.lists.Load() != reads || caps.calls.Load() != checks {
		t.Error("scraping read owner state")
	}
	want := map[string]float64{
		`konstapel_capability_condition{capability="policy_delivery",status="true"}`:             1,
		`konstapel_capability_condition{capability="assessment",status="false"}`:                 1,
		`konstapel_binding_condition{binding="ready",condition="EngineReady",status="true"}`:     1,
		`konstapel_binding_condition{binding="edited",condition="Resolved",status="unknown"}`:    1,
		`konstapel_binding_condition{binding="edited",condition="EngineReady",status="unknown"}`: 1,
		`konstapel_binding_target_namespaces{binding="ready"}`:                                   2,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if _, ok := got[`konstapel_binding_target_namespaces{binding="edited"}`]; ok {
		t.Error("a target count observed for an older generation is exposed")
	}
	if _, ok := got[`konstapel_capability_condition{capability="exceptions",status="unknown"}`]; ok {
		t.Error("an unobserved capability is reported")
	}

	// A dependency that cannot be asked is unknown, not false.
	for r, want := range map[capability.Reason]observability.Status{capability.Available: "true", capability.Unavailable: "unknown",
		capability.AccessDenied: "false", capability.APINotServed: "false", capability.ResourceMissing: "false", capability.UnsupportedResource: "false"} {
		if got := capabilityStatus(capability.Result{Reason: r}); got != want {
			t.Errorf("%s -> %s, want %s", r, got, want)
		}
	}
}

func storageMetrics(t *testing.T, e *runEnv) map[string]float64 {
	t.Helper()
	hub, term := leadingHub(t, func() time.Time { return e.now }, observability.DomainEvidenceStorage)
	if err := publishStorage(e.c, hub)(context.Background(), term, e.now); err != nil {
		t.Fatal(err)
	}
	return metricsOf(t, hub)
}

func backlog(m map[string]float64) [4]float64 {
	return [4]float64{m["konstapel_publication_pending{}"], m["konstapel_publication_failed{}"], m["konstapel_cleanup_pending{}"], m["konstapel_cleanup_blocked{}"]}
}

type recordedOps struct{ ok, failed atomic.Int64 }

func (o *recordedOps) observe(err error, _ time.Duration) {
	if err != nil {
		o.failed.Add(1)
	} else {
		o.ok.Add(1)
	}
}

// Incomplete evidence that publishes successfully is a successful attempt
// and no backlog; the incomplete assessment stays visible on the run.
func TestIncompletePublicationSucceeds(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	var pub recordedOps
	e.rr.Observe = RunObserver{Publication: pub.observe}
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	if r := e.run(name); r.Status.Summary.Evidence.Completeness != "Incomplete" || r.Status.Publication.Phase != "Committed" {
		t.Fatalf("run %+v", r.Status)
	}
	if pub.ok.Load() != 1 || pub.failed.Load() != 0 {
		t.Errorf("attempts ok=%d failed=%d", pub.ok.Load(), pub.failed.Load())
	}
	if b := backlog(storageMetrics(t, e)); b != [4]float64{} {
		t.Errorf("backlog %v after a successful publication", b)
	}
}

// A failing publication is actionable while it is retried; each retry is
// an attempt. After the publish timeout it is a historical failure.
func TestPublicationFailureIsActionableWhileRetried(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", map[string]v1alpha1.LabelValue{"environment": "production"})))
	var pub recordedOps
	e.rr.Observe = RunObserver{Publication: pub.observe}
	for range 100 {
		e.pub.Fail(pubfake.OpStage, publication.ErrUnavailable)
	}
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	if b := backlog(storageMetrics(t, e)); b != [4]float64{0, 1, 0, 0} {
		t.Fatalf("retried failure: backlog %v", b)
	}
	e.now = a0.Add(6 * time.Minute)
	e.step(name)
	if pub.failed.Load() != 2 || pub.ok.Load() != 0 {
		t.Errorf("attempts ok=%d failed=%d, want two failed attempts", pub.ok.Load(), pub.failed.Load())
	}
	e.now = a0.Add(11 * time.Minute)
	e.step(name)
	if r := e.run(name); r.Status.Phase != v1alpha1.RunFailed {
		t.Fatalf("phase %s", r.Status.Phase)
	}
	if b := backlog(storageMetrics(t, e)); b != [4]float64{} {
		t.Errorf("historical failure counted as backlog: %v", b)
	}
}

// Blocked cleanup stays visible after its binding is deleted, survives a
// controller restart (rebuilt from records, counters reset), and clears
// only once storage confirms deletion.
func TestBlockedCleanupOutlivesBindingAndRestart(t *testing.T) {
	e, name := completedRun(t, "10m")
	var cleanup recordedOps
	e.rr.Observe = RunObserver{Cleanup: cleanup.observe}
	ctx := context.Background()
	_ = e.c.Delete(ctx, &v1alpha1.ComplianceBinding{ObjectMeta: metav1.ObjectMeta{Name: "audit-prod"}})
	expires := e.run(name).Status.Publication.ExpiresAt.Time
	if b := backlog(storageMetrics(t, e)); b != [4]float64{} {
		t.Fatalf("backlog before expiry: %v", b)
	}
	e.now = expires.Add(time.Second)
	if b := backlog(storageMetrics(t, e)); b != [4]float64{0, 0, 1, 0} {
		t.Fatalf("expired, not yet deleted: %v", b)
	}
	e.pub.Fail(pubfake.OpDelete, publication.ErrRetentionBlocked)
	e.step(name)
	m := storageMetrics(t, e)
	if b := backlog(m); b != [4]float64{0, 0, 0, 1} || m["konstapel_cleanup_oldest_expiry_timestamp_seconds{}"] != float64(expires.Unix()) {
		t.Fatalf("blocked cleanup: %v oldest %v", b, m["konstapel_cleanup_oldest_expiry_timestamp_seconds{}"])
	}
	if cleanup.failed.Load() != 1 {
		t.Errorf("blocked deletion attempts: %d", cleanup.failed.Load())
	}

	// A restarted controller rebuilds the gauges from the records.
	e.restart()
	var after recordedOps
	e.rr.Observe = RunObserver{Cleanup: after.observe}
	if b := backlog(storageMetrics(t, e)); b != [4]float64{0, 0, 0, 1} {
		t.Fatalf("after restart: %v", b)
	}
	e.now = e.now.Add(time.Minute)
	e.step(name)
	if after.ok.Load() != 1 || after.failed.Load() != 0 {
		t.Errorf("confirmed deletion attempts ok=%d failed=%d", after.ok.Load(), after.failed.Load())
	}
	if b := backlog(storageMetrics(t, e)); b != [4]float64{} {
		t.Errorf("backlog after confirmed deletion: %v", b)
	}
}

// Bundle resolution is ready only while the sources Watcher's latest Sync
// read its configuration within the bound.
func TestBundleProjection(t *testing.T) {
	now := a0
	var at time.Time
	var ok bool
	hub, term := leadingHub(t, func() time.Time { return now }, observability.DomainBundleResolution)
	publish := publishBundles(func() (time.Time, bool) { return at, ok }, time.Minute, hub)
	if err := publish(context.Background(), term, now); err == nil {
		t.Error("published before the first Sync")
	}
	at, ok = now.Add(-time.Minute), true
	if err := publish(context.Background(), term, now); err != nil {
		t.Errorf("synced at the bound: %v", err)
	}
	if metricsOf(t, hub)[`konstapel_observation_ready{domain="bundle_resolution"}`] != 1 {
		t.Error("synchronized bundle resolution is not ready")
	}
	ok = false
	if err := publish(context.Background(), term, now.Add(time.Second)); err == nil {
		t.Error("published after a failed Sync")
	}
	at, ok = now.Add(-time.Minute-time.Second), true
	if err := publish(context.Background(), term, now); err == nil {
		t.Error("published a Sync older than the bound")
	}
	if got := bundleSyncBound(stack.Options{}); got != 2*stack.DefaultRefreshInterval+10*time.Second {
		t.Errorf("default bound %s", got)
	}
	if got := bundleSyncBound(stack.Options{RefreshInterval: 5 * time.Minute}); got != 10*time.Minute+10*time.Second {
		t.Errorf("bound %s", got)
	}
}

// Attempt observation maps outcomes onto the bounded result labels.
func TestObserveOperation(t *testing.T) {
	hub, _ := leadingHub(t, func() time.Time { return a0 })
	f := observeOperation(hub, observability.OperationBundleResolution)
	f(nil, time.Second)
	f(errors.New("registry.example.test/org/bundle: unauthorized for user reader"), time.Second)
	f(errors.New("again"), time.Second)
	m := metricsOf(t, hub)
	if m[`konstapel_operation_attempts_total{operation="bundle_resolution",result="success"}`] != 1 ||
		m[`konstapel_operation_attempts_total{operation="bundle_resolution",result="failure"}`] != 2 {
		t.Errorf("attempts %v", m)
	}
	for k := range m {
		if strings.Contains(k, "registry.example.test") || strings.Contains(k, "reader") {
			t.Errorf("error detail leaked into %s", k)
		}
	}
}
