package kyverno_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/publication"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

const cluster = "kube-system:c"

var (
	started             = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	evaluated           = started.Add(time.Minute)
	closed              = started.Add(2 * time.Minute)
	policyReport        = schema.GroupVersionKind{Group: "wgpolicyk8s.io", Version: "v1alpha2", Kind: "PolicyReport"}
	clusterPolicyReport = schema.GroupVersionKind{Group: "wgpolicyk8s.io", Version: "v1alpha2", Kind: "ClusterPolicyReport"}
)

func enginePolicy(name string, validations int) assessment.Object {
	vs := make([]any, validations)
	for i := range vs {
		vs[i] = map[string]any{"expression": "check-" + strconv.Itoa(i)}
	}
	return assessment.Object{"apiVersion": "policies.kyverno.io/v1", "kind": "ValidatingPolicy", "metadata": map[string]any{"name": name},
		"spec": map[string]any{"validations": vs}}
}

func subject(ns, policy string, resources ...string) targeting.EvidenceSubject {
	return targeting.EvidenceSubject{Cluster: cluster, Namespace: ns, NamespaceUID: types.UID("uid-" + ns), BindingName: "b", BindingUID: "uid-b",
		Revision: "rev-1", EnginePolicy: policy, LogicalPolicy: policy, Mode: v1alpha1.ModeAudit, Checks: []string{}, Resources: resources,
		BundleName: "bundle", BundleDigest: "sha256:bundle", SourceDigest: "sha256:source"}
}

func pod(ns, name, uid string) collector.ListedObject {
	return collector.ListedObject{Resource: "/v1/pods", NamespaceUID: "uid-" + ns, Object: assessment.Object{"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"namespace": ns, "name": name, "uid": uid}, "spec": map[string]any{"containers": []any{map[string]any{"name": "c"}}}}}
}

// frozenInput is the host-frozen inventory: Pod checks in namespaces a and b,
// and a Service check in a. The host lists no Services, so that subject is
// unsupported and has no expected observations.
func frozenInput() kyverno.InventoryInput {
	return kyverno.InventoryInput{Cluster: cluster, Started: started, MappingSHA256: "sha256:mapping",
		Subjects: []targeting.EvidenceSubject{subject("a", "kp-pods", "/v1/pods"), subject("a", "kp-services", "/v1/services"), subject("b", "kp-pods", "/v1/pods")},
		Stale:    []targeting.StaleScope{}, EnginePolicies: []assessment.Object{enginePolicy("kp-pods", 2), enginePolicy("kp-services", 1)},
		Workloads: []collector.ListedObject{pod("a", "web", "w1"), pod("a", "api", "w2"), pod("b", "web", "w3")}}
}

var scope = provider.Scope{Cluster: cluster, Namespaces: []provider.Namespace{{Name: "a", UID: "uid-a"}, {Name: "b", UID: "uid-b"}}}

func result(policy, outcome, index string, at time.Time, resources ...map[string]any) map[string]any {
	r := map[string]any{"policy": policy, "result": outcome, "source": "KyvernoValidatingPolicy",
		"timestamp": map[string]any{"seconds": at.Unix(), "nanos": int64(0)}}
	if index != "" {
		r["properties"] = map[string]any{"cel.validationIndex": index}
	}
	if len(resources) > 0 {
		refs := make([]any, len(resources))
		for i, x := range resources {
			refs[i] = x
		}
		r["resources"] = refs
	}
	return r
}

func ref(kind, ns, name, uid string) map[string]any {
	return map[string]any{"apiVersion": "v1", "kind": kind, "namespace": ns, "name": name, "uid": uid}
}

func report(gvk schema.GroupVersionKind, ns, name string, results ...map[string]any) client.Object {
	rs := make([]any, len(results))
	for i, r := range results {
		rs[i] = r
	}
	u := &unstructured.Unstructured{Object: map[string]any{"results": rs}}
	u.SetGroupVersionKind(gvk)
	u.SetNamespace(ns)
	u.SetName(name)
	u.SetUID(types.UID("report-" + ns + "-" + name))
	return u
}

// reports: one shared result passing every validation for w1 and w2; a
// Service result (unsupported subject); a failure for w1's replaced
// predecessor; w3's indexed results; and reports outside the scope.
func reports() []client.Object {
	return []client.Object{
		report(policyReport, "a", "shared", result("kp-pods", "pass", "", evaluated, ref("Pod", "a", "web", "w1"), ref("Pod", "a", "api", "w2"))),
		report(policyReport, "a", "service", result("kp-services", "fail", "", evaluated, ref("Service", "a", "svc", "s1"))),
		report(policyReport, "a", "replaced", result("kp-pods", "fail", "0", evaluated, ref("Pod", "a", "web", "w1-previous"))),
		report(policyReport, "b", "web", result("kp-pods", "pass", "0", evaluated, ref("Pod", "b", "web", "w3")), result("kp-pods", "fail", "1", evaluated, ref("Pod", "b", "web", "w3"))),
		report(policyReport, "c", "outside", result("kp-pods", "fail", "0", evaluated, ref("Pod", "c", "web", "w9"))),
		report(clusterPolicyReport, "", "cluster", result("kp-pods", "fail", "0", evaluated, ref("Pod", "a", "web", "w1"))),
	}
}

func fakeCluster(objs ...client.Object) *conformance.RecordingClient {
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(policyReport, meta.RESTScopeNamespace)
	mapper.Add(clusterPolicyReport, meta.RESTScopeRoot)
	return conformance.NewRecordingClient(fake.NewClientBuilder().WithRESTMapper(mapper).WithObjects(objs...).Build())
}

// collect runs the adapters as the host does.
func collect(t *testing.T, c client.Reader, in kyverno.InventoryInput, s provider.Scope) (collector.CaptureV2, []string) {
	t.Helper()
	got, limits, err := kyverno.Collect(context.Background(), s, provider.ClientSources(c, kyverno.Descriptor(), s))
	if err != nil {
		t.Fatal(err)
	}
	capture, err := kyverno.Inventory(in)
	if err != nil {
		t.Fatal(err)
	}
	capture.Reports = got
	capture.Window.Closed = closed
	return capture, limits
}

// direct is the path the controller took before the adapters: list each
// scope namespace's PolicyReports, keep earlier namespaces on a failure,
// and freeze the scope with collector.FreezeScope.
func direct(t *testing.T, c client.Reader, in kyverno.InventoryInput, s provider.Scope) (collector.CaptureV2, []string) {
	t.Helper()
	var got []assessment.Object
	var limits []string
	for _, ns := range s.Namespaces {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(policyReport.GroupVersion().WithKind("PolicyReportList"))
		if err := c.List(context.Background(), list, client.InNamespace(ns.Name)); err != nil {
			limits = append(limits, "policy reports unavailable: "+err.Error())
			break
		}
		rs := make([]assessment.Object, 0, len(list.Items))
		for _, it := range list.Items {
			rs = append(rs, it.Object)
		}
		got = append(got, rs...)
	}
	capture, err := collector.FreezeScope(in.Cluster, in.Started, in.MappingSHA256, in.Subjects, in.Stale, in.EnginePolicies, in.Workloads)
	if err != nil {
		t.Fatal(err)
	}
	capture.Reports = got
	capture.Window.Closed = closed
	return capture, limits
}

func boundaries(c collector.CaptureV2) []collector.Boundary {
	var out []collector.Boundary
	for _, w := range c.Workloads {
		out = append(out, collector.Boundary{WorkloadUID: w.UID, StateSHA256: w.StateSHA256, Since: started})
	}
	return out
}

func evaluate(t *testing.T, c collector.CaptureV2) collector.Evaluation {
	t.Helper()
	ev, err := c.Evaluate(boundaries(c), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// byWorkload maps "uid#index" to the observation's state and outcome.
func byWorkload(c collector.CaptureV2, ev collector.Evaluation) map[string]string {
	keys := map[string]collector.Expected{}
	for _, e := range c.Expected {
		keys[e.Key()] = e
	}
	out := map[string]string{}
	for _, o := range ev.Observations {
		e := keys[o.Key]
		out[e.Workload.UID+"#"+strconv.Itoa(e.Check.Index)] = string(o.State) + "/" + o.Outcome
	}
	return out
}

// The adapters produce exactly the capture, limitations and evaluation of
// the direct path. Shared evidence credits each workload once, the
// unsupported Service subject has no expected observation and its report
// establishes nothing, the replaced predecessor's and out-of-scope reports
// are not evidence, and ClusterPolicyReports are never read.
func TestCollectionMatchesTheDirectPath(t *testing.T) {
	rec := fakeCluster(reports()...)
	got, limits := collect(t, rec, frozenInput(), scope)
	calls := rec.Calls()
	want, wantLimits := direct(t, rec, frozenInput(), scope)
	if asJSON(got) != asJSON(want) || !slices.Equal(limits, wantLimits) {
		t.Fatalf("adapter capture differs from the direct path:\n%s\n%s", asJSON(got), asJSON(want))
	}
	ev := evaluate(t, got)
	if asJSON(ev) != asJSON(evaluate(t, want)) {
		t.Fatal("adapter evaluation differs from the direct path")
	}
	if wantCalls := []conformance.Call{{Verb: "list", Kind: "PolicyReportList", Namespace: "a"}, {Verb: "list", Kind: "PolicyReportList", Namespace: "b"}}; !slices.Equal(calls, wantCalls) {
		t.Fatalf("requests %v, want %v", calls, wantCalls)
	}
	if len(limits) != 0 || len(got.Reports) != 4 {
		t.Fatalf("limitations %v, %d reports", limits, len(got.Reports))
	}
	wantStates := map[string]string{
		"w1#0": "Attributable/pass", "w1#1": "Attributable/pass", "w2#0": "Attributable/pass", "w2#1": "Attributable/pass",
		"w3#0": "Attributable/pass", "w3#1": "Attributable/fail",
	}
	if states := byWorkload(got, ev); asJSON(states) != asJSON(wantStates) {
		t.Fatalf("observations %v, want %v", states, wantStates)
	}
	if ev.Evidence.Completeness != publication.Complete || ev.Outcomes.Pass != 5 || ev.Outcomes.Fail != 1 {
		t.Fatalf("evidence %+v outcomes %+v", ev.Evidence, ev.Outcomes)
	}
	for _, e := range got.Expected {
		if e.Check.EnginePolicy == "kp-services" {
			t.Fatalf("unsupported subject has an expected observation: %+v", e)
		}
	}
}

// Without reports every expected observation is missing: the inventory is
// unchanged, nothing passes and the evidence is incomplete.
func TestMissingReportsStayMissing(t *testing.T) {
	rec := fakeCluster()
	got, limits := collect(t, rec, frozenInput(), scope)
	want, _ := direct(t, rec, frozenInput(), scope)
	if asJSON(got) != asJSON(want) || got.Reports != nil || len(limits) != 0 {
		t.Fatalf("capture differs or not empty: %s", asJSON(got.Reports))
	}
	ev := evaluate(t, got)
	if ev.Evidence.Expected != 6 || ev.Evidence.Missing != 6 || ev.Evidence.Completeness != publication.Incomplete || ev.Outcomes != (publication.OutcomeCounts{}) {
		t.Fatalf("evidence %+v outcomes %+v", ev.Evidence, ev.Outcomes)
	}
}

// Zero targets read nothing and are NoTargets, never a pass.
func TestZeroTargetsReadNothing(t *testing.T) {
	rec := fakeCluster(reports()...)
	in := frozenInput()
	in.Subjects, in.Workloads = []targeting.EvidenceSubject{}, nil
	got, limits := collect(t, rec, in, provider.Scope{Cluster: cluster})
	if calls := rec.Calls(); len(calls) != 0 || got.Reports != nil || len(limits) != 0 {
		t.Fatalf("requests %v, reports %v, limitations %v", calls, got.Reports, limits)
	}
	ev := evaluate(t, got)
	if ev.Evidence.Completeness != publication.NoTargets || ev.Evidence.Expected != 0 || ev.Outcomes != (publication.OutcomeCounts{}) {
		t.Fatalf("evidence %+v outcomes %+v", ev.Evidence, ev.Outcomes)
	}
}

// A failed list stops collection with a limitation; earlier namespaces'
// reports are kept, later namespaces are not read, and their observations
// are missing.
func TestListFailureIsALimitation(t *testing.T) {
	rec := fakeCluster(reports()...)
	rec.Fail = func(c conformance.Call) error {
		if c.Namespace == "a" {
			return errors.New("injected list failure")
		}
		return nil
	}
	in := frozenInput()
	in.Subjects = append(in.Subjects, subject("c", "kp-pods", "/v1/pods"))
	in.Workloads = append(in.Workloads, pod("c", "web", "w9"))
	wide := provider.Scope{Cluster: cluster, Namespaces: []provider.Namespace{{Name: "b", UID: "uid-b"}, {Name: "a", UID: "uid-a"}, {Name: "c", UID: "uid-c"}}}
	got, limits := collect(t, rec, in, wide)
	calls := rec.Calls()
	rec.Reset()
	want, wantLimits := direct(t, rec, in, wide)
	if asJSON(got) != asJSON(want) || !slices.Equal(limits, wantLimits) {
		t.Fatal("adapter capture differs from the direct path")
	}
	if !slices.Equal(limits, []string{"policy reports unavailable: injected list failure"}) {
		t.Fatalf("limitations %v", limits)
	}
	if wantCalls := []conformance.Call{{Verb: "list", Kind: "PolicyReportList", Namespace: "b"}, {Verb: "list", Kind: "PolicyReportList", Namespace: "a"}}; !slices.Equal(calls, wantCalls) {
		t.Fatalf("requests %v", calls)
	}
	ev := evaluate(t, got)
	states := byWorkload(got, ev)
	if states["w3#0"] != "Attributable/pass" || states["w1#0"] != "Missing/" || states["w9#0"] != "Missing/" || ev.Evidence.Completeness != publication.Incomplete {
		t.Fatalf("observations %v", states)
	}
}

// Frozen identities keep their expected observations when replaced during
// collection. A replaced workload and a recreated namespace become
// unresolved, even though the reports still name the frozen UIDs; their
// untouched sibling stays attributable.
func TestReplacedIdentitiesCannotBeAttributed(t *testing.T) {
	rec := fakeCluster(reports()...)
	got, _ := collect(t, rec, frozenInput(), scope)
	frozen := len(got.Expected)
	at := started.Add(90 * time.Second)
	tr := collector.NewTracker(&got)
	replacement := collector.Workload{Resource: "/v1/pods", Namespace: "a", NamespaceUID: "uid-a", Name: "web", UID: "w1-new", StateSHA256: "x"}
	tr.Workload(at, replacement, false)
	recreated := frozenInput().Subjects
	for i := range recreated {
		if recreated[i].Namespace == "b" {
			recreated[i].NamespaceUID = "uid-b-recreated"
		}
	}
	tr.Configuration(at, recreated, nil)
	ev := evaluate(t, got)
	states := byWorkload(got, ev)
	want := map[string]string{"w1#0": "Unresolved/", "w1#1": "Unresolved/", "w2#0": "Attributable/pass", "w2#1": "Attributable/pass", "w3#0": "Unresolved/", "w3#1": "Unresolved/"}
	if len(got.Expected) != frozen || asJSON(states) != asJSON(want) {
		t.Fatalf("observations %v, want %v", states, want)
	}
	var kinds []collector.ChangeKind
	for _, ch := range got.ScopeChanges {
		kinds = append(kinds, ch.Kind)
	}
	if !slices.Contains(kinds, collector.WorkloadReplaced) || !slices.Contains(kinds, collector.NamespaceRecreated) || !slices.Contains(kinds, collector.NamespaceLeft) {
		t.Fatalf("scope changes %v", kinds)
	}
}

// The collector's only read is the descriptor's, and it is the shape the
// assessment capability requires.
func TestCollectorUsesTheDeclaredRead(t *testing.T) {
	d := kyverno.Descriptor()
	if len(d.Reads) != 1 || asJSON(d.Reads[0]) != asJSON(kyverno.Reports()) {
		t.Fatalf("reads %+v", d.Reads)
	}
	if r := kyverno.Reports(); r.Kind != policyReport.Kind || r.Group != policyReport.Group || r.Version != policyReport.Version || !r.Namespaced {
		t.Fatalf("read %+v", r)
	}
	// A host that grants no Kyverno read gets an error, not silent
	// missing evidence.
	other := d
	other.Reads = []provider.Read{{Group: "example.io", Version: "v1", Resource: "others", Kind: "Other", Namespaced: true, Verbs: []string{"list"}}}
	if _, _, err := kyverno.Collect(context.Background(), scope, provider.ClientSources(fakeCluster(), other, scope)); err == nil {
		t.Fatal("collection without the declared read succeeded")
	}
}
