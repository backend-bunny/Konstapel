package controller

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
)

// Collection characterization (add-assessment-provider-contract 2.1): what
// the assessment snapshot reads from the cluster, and what it makes of it.
// These tests pin the Kyverno collection path's existing behavior so that
// routing it through the provider collection adapter cannot change it.

// recordingClient records every list the assessment makes and every write
// it attempts, and can fail chosen lists.
type recordingClient struct {
	client.Client
	mu     sync.Mutex
	lists  []string // "<Kind> <namespace>"
	writes []string
	fail   func(kind, namespace string) error
}

func recordCalls(e *assessEnv) *recordingClient {
	rec := &recordingClient{Client: e.c}
	e.ar.Client = rec
	return rec
}

func (c *recordingClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	gvk, err := apiutil.GVKForObject(list, c.Scheme())
	if err != nil {
		return err
	}
	o := &client.ListOptions{}
	o.ApplyOptions(opts)
	c.mu.Lock()
	c.lists = append(c.lists, gvk.Kind+" "+o.Namespace)
	fail := c.fail
	c.mu.Unlock()
	if fail != nil {
		if err := fail(gvk.Kind, o.Namespace); err != nil {
			return err
		}
	}
	return c.Client.List(ctx, list, opts...)
}

func (c *recordingClient) write(op string, obj client.Object) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, op+" "+obj.GetName())
}

func (c *recordingClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	c.write("create", obj)
	return c.Client.Create(ctx, obj, opts...)
}

func (c *recordingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.write("update", obj)
	return c.Client.Update(ctx, obj, opts...)
}

func (c *recordingClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	c.write("patch", obj)
	return c.Client.Patch(ctx, obj, patch, opts...)
}

func (c *recordingClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	c.write("delete", obj)
	return c.Client.Delete(ctx, obj, opts...)
}

func (c *recordingClient) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	c.write("deleteAllOf", obj)
	return c.Client.DeleteAllOf(ctx, obj, opts...)
}

func (c *recordingClient) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
	c.mu.Lock()
	c.writes = append(c.writes, "apply")
	c.mu.Unlock()
	return c.Client.Apply(ctx, obj, opts...)
}

func (c *recordingClient) Status() client.SubResourceWriter {
	c.mu.Lock()
	c.writes = append(c.writes, "status")
	c.mu.Unlock()
	return c.Client.Status()
}

func (c *recordingClient) SubResource(sub string) client.SubResourceClient {
	c.mu.Lock()
	c.writes = append(c.writes, "subresource "+sub)
	c.mu.Unlock()
	return c.Client.SubResource(sub)
}

// reportLists are the PolicyReport lists made, in order.
func (c *recordingClient) reportLists() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, l := range c.lists {
		if strings.Contains(l, "PolicyReport") {
			out = append(out, l)
		}
	}
	return out
}

// reset clears all records.
func (c *recordingClient) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lists, c.writes = nil, nil
}

func (e *assessEnv) bindingNamed(name string) *v1alpha1.ComplianceBinding {
	e.t.Helper()
	b := &v1alpha1.ComplianceBinding{}
	if err := e.c.Get(context.Background(), client.ObjectKey{Name: name}, b); err != nil {
		e.t.Fatal(err)
	}
	return b
}

func reportUIDs(reports []assessment.Object) []string {
	var out []string
	for _, r := range reports {
		out = append(out, assessment.Str(assessment.At(r, "metadata", "uid")))
	}
	slices.Sort(out)
	return out
}

var production = map[string]v1alpha1.LabelValue{"environment": "production"}

// The snapshot reads PolicyReports only in the namespaces its subjects
// select, one namespaced list each in name order, never cluster-wide and
// never ClusterPolicyReports; it writes nothing. Another namespace's report
// does not enter the capture.
func TestSnapshotReadsReportsOnlyInScopeNamespacesAndWritesNothing(t *testing.T) {
	e := newAssessEnv(t, nsObj("b", "environment", "production"), nsObj("a", "environment", "production"), nsObj("other", "environment", "dev"),
		profileObj(t, "baseline", pol), epochBinding("audit-prod", production),
		privilegedPod("a", "web", "pod-a"), privilegedPod("b", "web", "pod-b"), privilegedPod("other", "web", "pod-o"))
	e.deliver("audit-prod")
	policy := e.enginePolicy()
	for _, p := range [][2]string{{"a", "pod-a"}, {"b", "pod-b"}, {"other", "pod-o"}} {
		e.report(p[0], p[1], policy, "pass", a0.Add(time.Minute))
	}
	rec := recordCalls(e)
	c, limits, _, err := e.ar.snapshot(context.Background(), e.bindingNamed("audit-prod"), a0.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.reportLists(); !slices.Equal(got, []string{"PolicyReportList a", "PolicyReportList b"}) {
		t.Fatalf("report lists %v", got)
	}
	if len(rec.writes) != 0 {
		t.Fatalf("the snapshot wrote %v", rec.writes)
	}
	if got := reportUIDs(c.Reports); !slices.Equal(got, []string{"report-pod-a", "report-pod-b"}) {
		t.Fatalf("captured reports %v", got)
	}
	if len(c.Expected) != 2 || len(limits) != 0 {
		t.Fatalf("expected %d, limitations %v", len(c.Expected), limits)
	}
}

// A failed report list is a limitation, not a reconcile error: collection
// stops there, keeps the reports earlier namespaces returned, and the
// namespaces it did not read have missing evidence, never a pass.
func TestReportListFailureIsALimitationAndKeepsEarlierNamespaces(t *testing.T) {
	e := newAssessEnv(t, nsObj("a", "environment", "production"), nsObj("b", "environment", "production"), nsObj("c", "environment", "production"),
		profileObj(t, "baseline", pol), epochBinding("audit-prod", production),
		privilegedPod("a", "web", "pod-a"), privilegedPod("b", "web", "pod-b"), privilegedPod("c", "web", "pod-c"))
	e.deliver("audit-prod")
	policy := e.enginePolicy()
	e.assess("audit-prod") // observe the workloads
	for _, p := range [][2]string{{"a", "pod-a"}, {"b", "pod-b"}, {"c", "pod-c"}} {
		e.report(p[0], p[1], policy, "pass", a0.Add(time.Minute))
	}
	rec := recordCalls(e)
	rec.fail = func(kind, ns string) error {
		if kind == "PolicyReportList" && ns == "b" {
			return errors.New("injected list failure")
		}
		return nil
	}
	e.now = a0.Add(2 * time.Minute)
	e.assess("audit-prod")
	if got := rec.reportLists(); !slices.Equal(got, []string{"PolicyReportList a", "PolicyReportList b"}) {
		t.Fatalf("report lists %v", got)
	}
	cur := e.current("audit-prod")
	if !slices.Contains(cur.Limitations, "policy reports unavailable: injected list failure") {
		t.Fatalf("limitations %v", cur.Limitations)
	}
	if ev, o := cur.Evidence, cur.Outcomes; ev.Completeness != "Incomplete" || ev.Expected != 3 || ev.Attributable != 1 || ev.Missing != 2 || o.Pass != 1 {
		t.Fatalf("evidence %+v outcomes %+v", ev, o)
	}
	c, _, _, err := e.ar.snapshot(context.Background(), e.bindingNamed("audit-prod"), e.now)
	if err != nil {
		t.Fatal(err)
	}
	if got := reportUIDs(c.Reports); !slices.Equal(got, []string{"report-pod-a"}) {
		t.Fatalf("captured reports %v", got)
	}
}

// Zero targets read no reports at all and the capture holds none; with
// targets but the assessment capability unavailable, no report is read
// either.
func TestNoReportsAreReadWithoutTargetsOrReportCapability(t *testing.T) {
	b := bindingObj("nobody", "baseline", v1alpha1.ModeAudit, map[string]v1alpha1.LabelValue{"environment": "none"})
	e := newAssessEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol), b,
		epochBinding("audit-prod", production), privilegedPod("prod", "web", "pod-1"))
	e.deliver("audit-prod")
	e.report("prod", "pod-1", e.enginePolicy(), "pass", a0.Add(time.Minute))
	e.deliver("nobody")
	rec := recordCalls(e)
	c, _, _, err := e.ar.snapshot(context.Background(), e.bindingNamed("nobody"), a0.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.reportLists(); len(got) != 0 || c.Reports != nil || len(c.Expected) != 0 {
		t.Fatalf("zero targets: lists %v, reports %v, expected %d", got, c.Reports, len(c.Expected))
	}
	e.assess("nobody")
	if cur := e.current("nobody"); cur.Evidence.Completeness != "NoTargets" {
		t.Fatalf("zero targets: %+v", cur.Evidence)
	}

	rec.reset()
	e.ar.Reports = func(context.Context) (bool, error) { return false, errors.New("reports withheld") }
	c, limits, _, err := e.ar.snapshot(context.Background(), e.bindingNamed("audit-prod"), a0.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got := rec.reportLists(); len(got) != 0 || c.Reports != nil || len(c.Expected) != 1 ||
		!slices.Contains(limits, "policy reports unavailable: reports withheld") {
		t.Fatalf("capability unavailable: lists %v, reports %v, expected %d, limitations %v", got, c.Reports, len(c.Expected), limits)
	}
}

// One report result naming two workloads is shared evidence: each workload
// keeps its own expected observation and is credited once.
func TestSharedReportResultAttributesEachWorkloadOnce(t *testing.T) {
	e := newAssessEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol), epochBinding("audit-prod", production),
		privilegedPod("prod", "web", "pod-1"), privilegedPod("prod", "api", "pod-2"))
	e.deliver("audit-prod")
	policy := e.enginePolicy()
	e.assess("audit-prod")
	at := a0.Add(time.Minute)
	r := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "shared", "namespace": "prod"},
		"results": []any{map[string]any{"policy": policy, "result": "pass", "source": "KyvernoValidatingPolicy",
			"properties": map[string]any{"cel.validationIndex": "0"},
			"timestamp":  map[string]any{"seconds": at.Unix(), "nanos": int64(0)},
			"resources": []any{
				map[string]any{"apiVersion": "v1", "kind": "Pod", "namespace": "prod", "name": "web", "uid": "pod-1"},
				map[string]any{"apiVersion": "v1", "kind": "Pod", "namespace": "prod", "name": "api", "uid": "pod-2"},
			}}},
	}}
	r.SetGroupVersionKind(PolicyReportGVK)
	r.SetUID("report-shared")
	if err := e.c.Create(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	e.now = a0.Add(2 * time.Minute)
	e.assess("audit-prod")
	cur := e.current("audit-prod")
	if ev, o := cur.Evidence, cur.Outcomes; ev.Completeness != "Complete" || ev.Expected != 2 || ev.Attributable != 2 || o.Pass != 2 || o.Fail+o.Unknown != 0 {
		t.Fatalf("evidence %+v outcomes %+v", ev, o)
	}
}

// A replaced workload (same name, new UID) and a recreated namespace (same
// name, new UID) do not inherit the previous instance's reports: the
// current snapshot expects the new identities and their evidence is
// missing until the engine evaluates them.
func TestReplacedIdentitiesDoNotInheritReports(t *testing.T) {
	e := newAssessEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol), epochBinding("audit-prod", production),
		privilegedPod("prod", "web", "pod-1"))
	e.deliver("audit-prod")
	policy := e.enginePolicy()
	e.assess("audit-prod")
	e.report("prod", "pod-1", policy, "pass", a0.Add(time.Minute))
	e.now = a0.Add(2 * time.Minute)
	e.assess("audit-prod")
	if cur := e.current("audit-prod"); cur.Evidence.Completeness != "Complete" || cur.Outcomes.Pass != 1 {
		t.Fatalf("baseline %+v", cur.Evidence)
	}

	ctx := context.Background()
	if err := e.c.Delete(ctx, privilegedPod("prod", "web", "pod-1")); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Create(ctx, privilegedPod("prod", "web", "pod-2")); err != nil {
		t.Fatal(err)
	}
	e.now = a0.Add(3 * time.Minute)
	e.assess("audit-prod")
	if cur := e.current("audit-prod"); cur.Evidence.Expected != 1 || cur.Evidence.Missing != 1 || cur.Outcomes.Pass != 0 {
		t.Fatalf("replaced workload inherited evidence: %+v %+v", cur.Evidence, cur.Outcomes)
	}

	// The namespace is recreated; the report about the old instance's pod
	// stays in the namespace of that name.
	e.report("prod", "pod-2", policy, "pass", a0.Add(4*time.Minute))
	if err := e.c.Delete(ctx, privilegedPod("prod", "web", "pod-2")); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "prod"}}); err != nil {
		t.Fatal(err)
	}
	ns := nsObj("prod", "environment", "production")
	ns.UID = types.UID("uid-prod-recreated")
	if err := e.c.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Create(ctx, privilegedPod("prod", "web", "pod-3")); err != nil {
		t.Fatal(err)
	}
	e.now = a0.Add(5 * time.Minute)
	c, _, _, err := e.ar.snapshot(ctx, e.bindingNamed("audit-prod"), e.now)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Expected) != 1 || c.Expected[0].NamespaceUID != "uid-prod-recreated" || c.Expected[0].Workload.UID != "pod-3" {
		t.Fatalf("expected %+v", c.Expected)
	}
	e.assess("audit-prod")
	if cur := e.current("audit-prod"); cur.Evidence.Expected != 1 || cur.Evidence.Missing != 1 || cur.Outcomes.Pass != 0 {
		t.Fatalf("recreated namespace inherited evidence: %+v %+v", cur.Evidence, cur.Outcomes)
	}
}

// A run's frozen workload replaced during collection stays expected and
// becomes unresolved; the replacement's report never satisfies it.
func TestRunKeepsReplacedWorkloadUnresolved(t *testing.T) {
	e := newRunEnv(t, shortTimeout(epochBinding("audit-prod", production)))
	e.deliver("audit-prod")
	e.assess("audit-prod")
	name := e.schedule("audit-prod").ActiveRun.Name
	e.step(name)
	ctx := context.Background()
	if err := e.c.Delete(ctx, privilegedPod("prod", "web", "pod-1")); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Create(ctx, privilegedPod("prod", "web", "pod-2")); err != nil {
		t.Fatal(err)
	}
	e.report("prod", "pod-2", e.enginePolicy(), "pass", a0.Add(time.Minute))
	e.now = a0.Add(90 * time.Second)
	e.step(name)
	e.now = a0.Add(5*time.Minute + time.Second)
	e.step(name)
	r := e.run(name)
	if r.Status.Phase != v1alpha1.RunCompleted || r.Status.Summary == nil {
		t.Fatalf("run %+v", r.Status)
	}
	if ev, o := r.Status.Summary.Evidence, r.Status.Summary.Outcomes; ev.Expected != 1 || ev.Unresolved != 1 || o.Pass != 0 {
		t.Fatalf("replaced workload: evidence %+v outcomes %+v", ev, o)
	}
}
