package controller

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/provider"
)

// Collection bounds in the assessment controller (add-assessment-provider-
// contract 2.3): the host bounds the Kyverno collection, a canceled
// reconcile records nothing, and a stopped collection is explicitly
// incomplete.

// The deadline is the binding's collection timeout; the other bounds are
// the host defaults. Within those defaults the existing collections are
// unchanged (the characterization tests in assessment_collection_test.go).
func TestCollectionLimitsComeFromTheBinding(t *testing.T) {
	r := &AssessmentReconciler{}
	for timeout, want := range map[string]time.Duration{"": 5 * time.Minute, "7m": 7 * time.Minute, "bogus": 5 * time.Minute, "-1m": 5 * time.Minute} {
		b := epochBinding("b", production)
		if timeout != "" {
			b.Spec.Assessment = &v1alpha1.BindingAssessment{CollectionTimeout: v1alpha1.Duration(timeout)}
		}
		l := provider.DefaultLimits()
		l.Timeout = want
		if got := r.collectionLimits(b); got != l {
			t.Errorf("collectionTimeout %q: limits %+v, want %+v", timeout, got, l)
		}
	}
	r.CollectionLimits = provider.Limits{MaxObjects: 3}
	if got := r.collectionLimits(epochBinding("b", production)); got.MaxObjects != 3 || got.Timeout != 5*time.Minute || got.MaxBytes != provider.DefaultMaxBytes {
		t.Fatalf("override %+v", got)
	}
}

// threeNamespaces is the binding audit-prod over namespaces a, b and c,
// each with one pod and its passing report.
func threeNamespaces(t *testing.T) *assessEnv {
	e := newAssessEnv(t, nsObj("a", "environment", "production"), nsObj("b", "environment", "production"), nsObj("c", "environment", "production"),
		profileObj(t, "baseline", pol), epochBinding("audit-prod", production),
		privilegedPod("a", "web", "pod-a"), privilegedPod("b", "web", "pod-b"), privilegedPod("c", "web", "pod-c"))
	e.deliver("audit-prod")
	policy := e.enginePolicy()
	e.assess("audit-prod") // observe the workloads
	for _, p := range [][2]string{{"a", "pod-a"}, {"b", "pod-b"}, {"c", "pod-c"}} {
		e.report(p[0], p[1], policy, "pass", a0.Add(time.Minute))
	}
	e.now = a0.Add(2 * time.Minute)
	return e
}

// A limit met in namespace c stops the whole collection. The Kyverno
// adapter keeps a's and b's reports on a failed list, but the host uses
// none: every observation is missing and the evidence is incomplete, with
// the limitation saying why, never a truncated capture that passes. At the
// limit the result is the unbounded one.
func TestCollectionLimitIsExplicitlyIncomplete(t *testing.T) {
	e := threeNamespaces(t)
	e.assess("audit-prod")
	unbounded := *e.current("audit-prod")
	if unbounded.Evidence.Completeness != "Complete" || unbounded.Outcomes.Pass != 3 || len(collectionLimitations(unbounded)) != 0 {
		t.Fatalf("unbounded %+v", unbounded)
	}

	e.ar.CollectionLimits = provider.Limits{MaxObjects: 2}
	e.now = a0.Add(3 * time.Minute)
	e.assess("audit-prod")
	cur := e.current("audit-prod")
	want := "konstapel-kyverno/v1 evidence is not used: collection stopped (object-limit): the collection read more than 2 objects (at policyreports.wgpolicyk8s.io/v1alpha2 in namespace c)"
	if !slices.Equal(collectionLimitations(*cur), []string{want, "3 of 3 expected observations lack attributable evidence (missing 3, rejected 0, unresolved 0)"}) {
		t.Fatalf("limitations %q", cur.Limitations)
	}
	if ev, o := cur.Evidence, cur.Outcomes; ev.Completeness != "Incomplete" || ev.Expected != 3 || ev.Attributable != 0 || ev.Missing != 3 || o.Pass != 0 {
		t.Fatalf("evidence %+v outcomes %+v", ev, o)
	}
	c, _, _, err := e.ar.snapshot(context.Background(), e.bindingNamed("audit-prod"), e.now)
	if err != nil || c.Reports != nil || len(c.Expected) != 3 {
		t.Fatalf("snapshot reports %v, expected %d, %v", c.Reports, len(c.Expected), err)
	}

	// At the limit, the same instant gives the unbounded status.
	e.ar.CollectionLimits = provider.Limits{}
	e.now = a0.Add(4 * time.Minute)
	e.assess("audit-prod")
	unbounded = *e.current("audit-prod")
	e.ar.CollectionLimits = provider.Limits{MaxObjects: 3}
	e.assess("audit-prod")
	if at := *e.current("audit-prod"); asJSON(at) != asJSON(unbounded) || at.Evidence.Completeness != "Complete" {
		t.Fatalf("at the limit %s, unbounded %s", asJSON(at), asJSON(unbounded))
	}
}

// collectionLimitations are the current limitations other than the
// planner's (this environment configures no evidence publisher).
func collectionLimitations(cur v1alpha1.CurrentEvidence) []string {
	return slices.DeleteFunc(slices.Clone(cur.Limitations), func(l string) bool { return strings.HasPrefix(l, "scheduled snapshots are disabled") })
}

// blockReports makes every PolicyReport list wait until its context ends.
type blockReports struct{ client.Client }

func (c blockReports) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if gvk, err := apiutil.GVKForObject(list, c.Scheme()); err == nil && gvk.Kind == "PolicyReportList" {
		<-ctx.Done()
		return ctx.Err()
	}
	return c.Client.List(ctx, list, opts...)
}

// The binding's collection timeout is the collection's deadline: a report
// list that does not return in time stops collection with a limitation,
// and the reconcile itself completes and records it.
func TestCollectionDeadlineIsTheCollectionTimeout(t *testing.T) {
	b := epochBinding("audit-prod", production)
	b.Spec.Assessment = &v1alpha1.BindingAssessment{CollectionTimeout: "300ms"}
	e := newAssessEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol), b, privilegedPod("prod", "web", "pod-1"))
	e.deliver("audit-prod")
	e.report("prod", "pod-1", e.enginePolicy(), "pass", a0.Add(time.Minute))
	e.ar.Client = blockReports{e.c}
	e.now = a0.Add(2 * time.Minute)
	start := time.Now()
	e.assess("audit-prod")
	if d := time.Since(start); d < 300*time.Millisecond || d > time.Minute {
		t.Fatalf("collection took %s", d)
	}
	cur := e.current("audit-prod")
	if l := collectionLimitations(*cur); len(l) == 0 || !strings.HasPrefix(l[0], "konstapel-kyverno/v1 evidence is not used: collection stopped (timeout): the collection exceeded its 300ms deadline") {
		t.Fatalf("limitations %q", cur.Limitations)
	}
	if cur.Evidence.Completeness != "Incomplete" || cur.Evidence.Missing != 1 || cur.Outcomes.Pass != 0 {
		t.Fatalf("evidence %+v outcomes %+v", cur.Evidence, cur.Outcomes)
	}
}

// Leadership lost while reports are listed cancels the reconcile: it
// returns the cancellation, writes no status and keeps the earlier current
// evidence, instead of recording the namespaces read so far as a result.
func TestLeadershipLossDuringCollectionRecordsNothing(t *testing.T) {
	e := threeNamespaces(t)
	e.assess("audit-prod")
	before := e.bindingNamed("audit-prod").Status
	rec := recordCalls(e)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec.fail = func(kind, ns string) error {
		if kind == "PolicyReportList" && ns == "b" {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	e.now = a0.Add(3 * time.Minute)
	_, err := e.ar.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "audit-prod"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("reconcile error %v", err)
	}
	if got := rec.reportLists(); !slices.Equal(got, []string{"PolicyReportList a", "PolicyReportList b"}) {
		t.Fatalf("report lists %v", got)
	}
	if len(rec.writes) != 0 {
		t.Fatalf("a canceled reconcile wrote %v", rec.writes)
	}
	if after := e.bindingNamed("audit-prod").Status; asJSON(after) != asJSON(before) {
		t.Fatalf("status changed:\n%s\n%s", asJSON(after), asJSON(before))
	}
}

// Leadership lost during a run's closing collection freezes nothing: no
// closure is written and the run keeps collecting. The next leader's poll
// closes it from a complete collection under the same run.
func TestLeadershipLossAtRunClosureFreezesNothing(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", production)))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	e.report("prod", "pod-1", e.enginePolicy(), "pass", a0.Add(time.Minute))
	e.now = a0.Add(5*time.Minute + time.Second)
	rec := recordCalls(e.assessEnv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec.fail = func(kind, ns string) error {
		if kind == "PolicyReportList" {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	run := e.run(name)
	staged := asJSON(e.staged(run))
	if _, err := e.rr.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("reconcile error %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.rr.staging(run), "closed.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a canceled poll froze a closure: %v", err)
	}
	if r := e.run(name); r.Status.Phase != v1alpha1.RunCollecting || r.Status.Summary != nil || asJSON(e.staged(r)) != staged {
		t.Fatalf("run changed: %+v", r.Status)
	}

	rec.fail = nil
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Summary == nil {
		t.Fatalf("run %+v", r.Status)
	}
	if ev, o := r.Status.Summary.Evidence, r.Status.Summary.Outcomes; ev.Completeness != "Complete" || ev.Attributable != 1 || o.Pass != 1 {
		t.Fatalf("evidence %+v outcomes %+v", ev, o)
	}
}

// A run whose closing collection meets a limit closes with explicitly
// incomplete evidence, not with a truncated capture: the evidence it could
// not keep is missing.
func TestRunClosesIncompleteWhenACollectionLimitIsMet(t *testing.T) {
	for limit, complete := range map[int]bool{1: false, 2: true} {
		e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", production)))
		e.deliver("audit-prod")
		e.assess("audit-prod")
		name := e.schedule("audit-prod").ActiveRun.Name
		e.step(name)
		policy := e.enginePolicy()
		e.report("prod", "pod-1", policy, "pass", a0.Add(time.Minute))
		e.report("prod", "pod-gone", policy, "fail", a0.Add(time.Minute)) // about no frozen workload
		e.ar.CollectionLimits = provider.Limits{MaxObjects: limit}
		e.now = a0.Add(5*time.Minute + time.Second)
		e.step(name)
		r := e.run(name)
		if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Summary == nil {
			t.Fatalf("limit %d: run %+v", limit, r.Status)
		}
		ev, o := r.Status.Summary.Evidence, r.Status.Summary.Outcomes
		switch {
		case complete && (ev.Completeness != "Complete" || o.Pass != 1):
			t.Fatalf("limit %d: evidence %+v outcomes %+v", limit, ev, o)
		case !complete && (ev.Completeness != "Incomplete" || ev.Missing != 1 || ev.Attributable != 0 || o.Pass != 0):
			t.Fatalf("limit %d: evidence %+v outcomes %+v", limit, ev, o)
		}
	}
}

// extraReports adds n PolicyReports about no frozen workload to every
// PolicyReport list of namespace ns, as a large cluster would.
type extraReports struct {
	client.Client
	ns string
	n  int
}

func (x extraReports) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if err := x.Client.List(ctx, list, opts...); err != nil {
		return err
	}
	u, ok := list.(*unstructured.UnstructuredList)
	if !ok || u.GetKind() != PolicyReportGVK.Kind+"List" || (&client.ListOptions{}).ApplyOptions(opts).Namespace != x.ns {
		return nil
	}
	for i := range x.n {
		name := "bulk-" + strconv.Itoa(i)
		u.Items = append(u.Items, unstructured.Unstructured{Object: map[string]any{
			"apiVersion": PolicyReportGVK.GroupVersion().String(), "kind": PolicyReportGVK.Kind,
			"metadata": map[string]any{"name": name, "namespace": x.ns, "uid": "uid-" + name},
			"scope":    map[string]any{"apiVersion": "v1", "kind": "Pod", "namespace": x.ns, "name": name, "uid": "gone-" + name},
		}})
	}
	return nil
}

// The configured limits (Options.CollectionLimits, from the --collection-*
// flags) are the ones provider.Collect enforces. A namespace with 100,001
// reports is above the default object limit, so its evidence is
// incomplete; a raised limit completes the same collection, and a lowered
// one makes a small collection incomplete.
func TestConfiguredCollectionLimitsReachTheCollection(t *testing.T) {
	raised := provider.Limits{PageSize: provider.DefaultPageSize, MaxPages: provider.DefaultMaxPages, MaxObjects: 200_000, MaxBytes: provider.DefaultMaxBytes}
	lowered := provider.Limits{PageSize: 1, MaxPages: 3, MaxObjects: 2, MaxBytes: provider.MinMaxBytes}
	for _, l := range []provider.Limits{raised, lowered} {
		if err := l.ValidateConfiguration(); err != nil {
			t.Fatalf("%+v: %v", l, err)
		}
	}
	e := threeNamespaces(t)
	e.ar.Client = extraReports{Client: e.ar.Client, ns: "c", n: provider.DefaultMaxObjects - 2}
	for i, tc := range []struct {
		limits   provider.Limits
		complete bool
		stop     string
	}{
		{limits: provider.Limits{}, stop: "the collection read more than 100000 objects (at policyreports.wgpolicyk8s.io/v1alpha2 in namespace c)"},
		{limits: raised, complete: true},
	} {
		e.ar.CollectionLimits = tc.limits
		e.now = a0.Add(time.Duration(3+i) * time.Minute)
		e.assess("audit-prod")
		checkCollection(t, *e.current("audit-prod"), tc.limits, tc.complete, tc.stop)
	}

	e = threeNamespaces(t)
	e.ar.CollectionLimits = lowered
	e.assess("audit-prod")
	checkCollection(t, *e.current("audit-prod"), lowered, false, "the collection read more than 2 objects (at policyreports.wgpolicyk8s.io/v1alpha2 in namespace c)")
}

func checkCollection(t *testing.T, cur v1alpha1.CurrentEvidence, l provider.Limits, complete bool, stop string) {
	t.Helper()
	ev, o := cur.Evidence, cur.Outcomes
	if complete {
		if ev.Completeness != "Complete" || ev.Attributable != 3 || o.Pass != 3 || len(collectionLimitations(cur)) != 0 {
			t.Fatalf("limits %+v: evidence %+v outcomes %+v limitations %q", l, ev, o, cur.Limitations)
		}
		return
	}
	want := "konstapel-kyverno/v1 evidence is not used: collection stopped (object-limit): " + stop
	if ev.Completeness != "Incomplete" || ev.Missing != 3 || o.Pass != 0 || !slices.Contains(cur.Limitations, want) {
		t.Fatalf("limits %+v: evidence %+v outcomes %+v limitations %q", l, ev, o, cur.Limitations)
	}
}
