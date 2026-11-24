package provider_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
)

var (
	engineReport  = schema.GroupVersionKind{Group: "reports.example.io", Version: "v1", Kind: "EngineReport"}
	postureReport = schema.GroupVersionKind{Group: "reports.example.io", Version: "v1", Kind: "PostureReport"}
)

func object(gvk schema.GroupVersionKind, ns, name string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gvk)
	u.SetNamespace(ns)
	u.SetName(name)
	return u
}

// cluster is a fake cluster with engine reports in namespaces a, b and
// other, and two cluster-scoped posture reports, behind a recording client.
func cluster(t *testing.T) *conformance.RecordingClient {
	t.Helper()
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(engineReport, meta.RESTScopeNamespace)
	mapper.Add(postureReport, meta.RESTScopeRoot)
	c := fake.NewClientBuilder().WithRESTMapper(mapper).WithObjects(
		object(engineReport, "a", "ra"), object(engineReport, "b", "rb"), object(engineReport, "other", "ro"),
		object(postureReport, "", "p1"), object(postureReport, "", "p2")).Build()
	return conformance.NewRecordingClient(c)
}

var twoNamespaces = provider.Scope{Cluster: "c", Namespaces: []provider.Namespace{{Name: "a", UID: "uid-a"}, {Name: "b", UID: "uid-b"}}}

func names(objs []map[string]any) []string {
	var out []string
	for _, o := range objs {
		out = append(out, (&unstructured.Unstructured{Object: o}).GetName())
	}
	slices.Sort(out)
	return out
}

// A collector gets a reader only for a read its descriptor declares, with
// the exact resource shape and the list verb.
func TestSourcesGrantOnlyDeclaredListReads(t *testing.T) {
	rec := cluster(t)
	declared := enforcing().Reads[0]
	src := provider.ClientSources(rec, enforcing(), twoNamespaces)
	if _, err := src.Source(declared); err != nil {
		t.Fatal(err)
	}
	other := declared
	other.Resource, other.Kind = "otherreports", "OtherReport"
	wrongKind, wrongScope := declared, declared
	wrongKind.Kind = "Secret"
	wrongScope.Namespaced = false
	getOnly := enforcing()
	getOnly.Reads[0].Verbs = []string{"get", "watch"}
	invalid := enforcing()
	invalid.Reads[0].Verbs = []string{"list", "delete"}
	for name, tc := range map[string]struct {
		d    provider.Descriptor
		read provider.Read
		want string
	}{
		"undeclared read":      {enforcing(), other, "does not declare a read"},
		"another provider's":   {reporting(), declared, "does not declare a read"},
		"different kind":       {enforcing(), wrongKind, "declares"},
		"different scope":      {enforcing(), wrongScope, "declares"},
		"no list verb":         {getOnly, declared, "does not declare list"},
		"invalid descriptor":   {invalid, declared, "not read-only"},
		"read of another kind": {enforcing(), provider.Read{Version: "v1", Resource: "secrets", Kind: "Secret", Namespaced: true, Verbs: []string{"list"}}, "does not declare a read"},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := provider.ClientSources(rec, tc.d, twoNamespaces).Source(tc.read)
			if err == nil || r != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("reader %v, error %v; want %q", r, err, tc.want)
			}
		})
	}
	if calls := rec.Calls(); len(calls) != 0 {
		t.Fatalf("granting readers made requests: %v", calls)
	}
}

// A namespaced reader lists only scope namespaces, one namespaced list
// each; it never lists cluster-wide, and a refused read makes no request.
// Only list requests are ever made, through a client that could write.
func TestNamespacedReaderStaysInScope(t *testing.T) {
	rec := cluster(t)
	r, err := provider.ClientSources(rec, enforcing(), twoNamespaces).Source(enforcing().Reads[0])
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for ns, want := range map[string][]string{"a": {"ra"}, "b": {"rb"}} {
		got, err := r.List(ctx, ns)
		if err != nil || !slices.Equal(names(got), want) {
			t.Fatalf("list %s: %v %v", ns, names(got), err)
		}
	}
	for _, ns := range []string{"other", "", "A"} {
		if got, err := r.List(ctx, ns); !errors.Is(err, provider.ErrOutOfScope) || got != nil {
			t.Errorf("list %q: %v %v", ns, names(got), err)
		}
	}
	calls := rec.Calls()
	slices.SortFunc(calls, func(x, y conformance.Call) int { return strings.Compare(x.Namespace, y.Namespace) })
	want := []conformance.Call{{Verb: "list", Kind: "EngineReportList", Namespace: "a"}, {Verb: "list", Kind: "EngineReportList", Namespace: "b"}}
	if !slices.Equal(calls, want) {
		t.Fatalf("requests %v, want %v", calls, want)
	}
}

// A cluster-scoped reader lists once with no namespace and only for a
// non-empty scope; an empty scope (no targets) permits no read at all.
func TestClusterScopedReaderNeedsAScope(t *testing.T) {
	rec := cluster(t)
	read := reporting().Reads[0]
	r, err := provider.ClientSources(rec, reporting(), twoNamespaces).Source(read)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if got, err := r.List(ctx, ""); err != nil || !slices.Equal(names(got), []string{"p1", "p2"}) {
		t.Fatalf("cluster list: %v %v", names(got), err)
	}
	if _, err := r.List(ctx, "a"); !errors.Is(err, provider.ErrOutOfScope) {
		t.Fatalf("namespaced list of a cluster-scoped read: %v", err)
	}
	for _, scope := range []provider.Scope{{Cluster: "c"}, {Cluster: "c", Namespaces: []provider.Namespace{}}} {
		empty, err := provider.ClientSources(rec, reporting(), scope).Source(read)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := empty.List(ctx, ""); !errors.Is(err, provider.ErrOutOfScope) {
			t.Fatalf("empty scope read: %v", err)
		}
	}
	empty, _ := provider.ClientSources(rec, enforcing(), provider.Scope{Cluster: "c"}).Source(enforcing().Reads[0])
	if _, err := empty.List(ctx, "a"); !errors.Is(err, provider.ErrOutOfScope) {
		t.Fatalf("empty scope namespaced read: %v", err)
	}
	if calls := rec.Calls(); !slices.Equal(calls, []conformance.Call{{Verb: "list", Kind: "PostureReportList"}}) {
		t.Fatalf("requests %v", calls)
	}
}

// A source failure is the reader's error, unchanged, for the adapter to
// report; it is not retried or hidden.
func TestReaderReturnsSourceErrors(t *testing.T) {
	rec := cluster(t)
	boom := errors.New("injected")
	rec.Fail = func(c conformance.Call) error {
		if c.Namespace == "b" {
			return boom
		}
		return nil
	}
	r, _ := provider.ClientSources(rec, enforcing(), twoNamespaces).Source(enforcing().Reads[0])
	if _, err := r.List(context.Background(), "b"); err != boom {
		t.Fatalf("error %v", err)
	}
	if n := len(rec.Calls()); n != 1 {
		t.Fatalf("%d requests", n)
	}
}

// The recording fixture classifies every write, including subresource
// writes, and lets reads through.
func TestRecordingClientSeesWrites(t *testing.T) {
	rec := cluster(t)
	ctx := context.Background()
	o := object(engineReport, "a", "new")
	_ = rec.Create(ctx, o)
	_ = rec.Update(ctx, o)
	_ = rec.Patch(ctx, o, client.Merge)
	_ = rec.Status().Update(ctx, o)
	_ = rec.Delete(ctx, o)
	_ = rec.DeleteAllOf(ctx, object(engineReport, "", ""), client.InNamespace("b"))
	_ = rec.Get(ctx, client.ObjectKey{Namespace: "a", Name: "ra"}, object(engineReport, "", ""))
	var verbs []string
	for _, w := range rec.Writes() {
		verbs = append(verbs, w.Verb)
	}
	if want := []string{"create", "update", "patch", "status update", "delete", "deletecollection"}; !slices.Equal(verbs, want) {
		t.Fatalf("writes %v, want %v", verbs, want)
	}
	if calls := rec.Calls(); calls[len(calls)-1] != (conformance.Call{Verb: "get", Kind: "EngineReport", Namespace: "a"}) {
		t.Fatalf("last call %+v", calls[len(calls)-1])
	}
}
