package provider_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
)

// Collection bounds (add-assessment-provider-contract 2.3): the host, not
// the adapter, bounds every collection and decides what a stopped one
// means.

// pagedCluster has n engine reports in namespace a, 2 in b and 1 in other,
// served in pages, behind a recording client.
func pagedCluster(t *testing.T, n int) (*conformance.RecordingClient, *conformance.PagingClient) {
	t.Helper()
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(engineReport, meta.RESTScopeNamespace)
	mapper.Add(postureReport, meta.RESTScopeRoot)
	var objs []client.Object
	for i := range n {
		objs = append(objs, object(engineReport, "a", fmt.Sprintf("ra-%03d", i)))
	}
	objs = append(objs, object(engineReport, "b", "rb-0"), object(engineReport, "b", "rb-1"), object(engineReport, "other", "ro"),
		object(postureReport, "", "p1"), object(postureReport, "", "p2"))
	pager := conformance.NewPagingClient(fake.NewClientBuilder().WithRESTMapper(mapper).WithObjects(objs...).Build())
	return conformance.NewRecordingClient(pager), pager
}

// collected is what a test adapter returns: the objects of each namespace
// it listed, in order.
type collected map[string][]string

// careless lists every scope namespace and keeps whatever it got, ignoring
// errors: the worst adapter the host must still bound. Its result would
// look complete for every namespace that returned before a failure.
func careless(scope provider.Scope) func(context.Context, provider.Sources) (collected, []string, error) {
	return func(ctx context.Context, src provider.Sources) (collected, []string, error) {
		r, err := src.Source(enforcing().Reads[0])
		if err != nil {
			return nil, nil, err
		}
		out := collected{}
		for _, ns := range scope.Namespaces {
			objs, err := r.List(ctx, ns.Name)
			if err != nil {
				continue
			}
			out[ns.Name] = names(objs)
		}
		return out, []string{"adapter limitation"}, nil
	}
}

func limits(f func(*provider.Limits)) provider.Limits {
	l := provider.DefaultLimits()
	f(&l)
	return l
}

func kinds(calls []conformance.Call) []string {
	var out []string
	for _, c := range calls {
		out = append(out, c.Verb+" "+c.Kind+" "+c.Namespace)
	}
	return out
}

// The default limits are the documented ones: the binding's default
// collection timeout and the preview observation's object, byte and page
// size bounds.
func TestDefaultLimits(t *testing.T) {
	want := provider.Limits{Timeout: 5 * time.Minute, PageSize: 500, MaxPages: 20_000, MaxObjects: 100_000, MaxBytes: 512 << 20}
	if got := provider.DefaultLimits(); got != want || got.Validate() != nil {
		t.Fatalf("defaults %+v", got)
	}
	if got := (provider.Limits{MaxObjects: 3, Timeout: -1}).WithDefaults(); got.MaxObjects != 3 || got.Timeout != want.Timeout || got.PageSize != want.PageSize {
		t.Fatalf("with defaults %+v", got)
	}
	for _, l := range []provider.Limits{{}, limits(func(l *provider.Limits) { l.MaxBytes = 0 }), limits(func(l *provider.Limits) { l.PageSize = -1 })} {
		if l.Validate() == nil {
			t.Errorf("limits %+v validated", l)
		}
		if _, _, err := provider.Collect(context.Background(), cluster(t), enforcing(), twoNamespaces, l, careless(twoNamespaces)); err == nil {
			t.Errorf("collection under %+v ran", l)
		}
	}
}

// A list is read page by page until its continuation ends. The result is
// the complete list, the same as one unpaginated list, and within the
// limits the adapter's result is returned unchanged.
func TestPaginatedListIsComplete(t *testing.T) {
	rec, pager := pagedCluster(t, 7)
	l := limits(func(l *provider.Limits) { l.PageSize = 3 })
	got, lims, err := provider.Collect(context.Background(), rec, enforcing(), twoNamespaces, l, careless(twoNamespaces))
	if err != nil || !slices.Equal(lims, []string{"adapter limitation"}) {
		t.Fatalf("collection: %v %v", lims, err)
	}
	if len(got["a"]) != 7 || got["a"][0] != "ra-000" || got["a"][6] != "ra-006" || !slices.Equal(got["b"], []string{"rb-0", "rb-1"}) {
		t.Fatalf("collected %v", got)
	}
	if want := []string{"list EngineReportList a", "list EngineReportList a", "list EngineReportList a", "list EngineReportList b"}; !slices.Equal(kinds(rec.Calls()), want) {
		t.Fatalf("requests %v", kinds(rec.Calls()))
	}
	if n := len(pager.Pages()); n != 4 {
		t.Fatalf("%d pages", n)
	}
	whole, _ := pagedCluster(t, 7)
	unpaged, _, err := provider.Collect(context.Background(), whole, enforcing(), twoNamespaces, provider.DefaultLimits(), careless(twoNamespaces))
	if err != nil || !maps.EqualFunc(unpaged, got, slices.Equal) || len(whole.Calls()) != 2 {
		t.Fatalf("unpaginated %v %v %v", unpaged, err, whole.Calls())
	}
	// Exactly at a bound is within it.
	exact := limits(func(l *provider.Limits) { l.PageSize, l.MaxObjects, l.MaxPages = 3, 9, 4 })
	if again, lims, err := provider.Collect(context.Background(), rec, enforcing(), twoNamespaces, exact, careless(twoNamespaces)); err != nil || len(again["a"]) != 7 || len(lims) != 1 || lims[0] != "adapter limitation" {
		t.Fatalf("at the bounds: %v %v %v", again, lims, err)
	}
}

// An expired continuation restarts the list once from its first page; the
// restarted list is one consistent snapshot, and its discarded pages do
// not count against the object limit. A second expiry stops the collection.
func TestExpiredContinuationRestartsOnce(t *testing.T) {
	rec, pager := pagedCluster(t, 7)
	expiries := 1
	pager.Fault = func(p conformance.Page) conformance.PageFault {
		if p.Namespace == "a" && p.Number == 2 && expiries > 0 {
			expiries--
			return conformance.PageExpired
		}
		return conformance.PageOK
	}
	l := limits(func(l *provider.Limits) { l.PageSize, l.MaxObjects = 3, 9 })
	got, _, err := provider.Collect(context.Background(), rec, enforcing(), twoNamespaces, l, careless(twoNamespaces))
	if err != nil || len(got["a"]) != 7 || len(got["b"]) != 2 {
		t.Fatalf("restarted collection %v %v", got, err)
	}
	var numbers []int
	for _, p := range pager.Pages() {
		if p.Namespace == "a" {
			numbers = append(numbers, p.Number)
		}
	}
	if !slices.Equal(numbers, []int{0, 1, 2, 0, 1, 2}) {
		t.Fatalf("pages of a %v", numbers)
	}

	expiries = 2
	got, lims, err := provider.Collect(context.Background(), rec, enforcing(), twoNamespaces, l, careless(twoNamespaces))
	if err != nil || got != nil || len(lims) != 1 || !strings.Contains(lims[0], "(pagination-expired)") || !strings.HasPrefix(lims[0], "engine/v1 evidence is not used") {
		t.Fatalf("twice expired: %v %v %v", got, lims, err)
	}
}

// Every bound stops the whole collection. Once stopped, later reads are
// refused without a request, and even an adapter that ignores the error
// and returns the namespaces it did read gets no result back: only the
// limitation, never a truncated result that looks complete.
func TestBoundsStopTheWholeCollection(t *testing.T) {
	// The JSON size of each engine report object in namespace a.
	probe, _ := pagedCluster(t, 1)
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(engineReport.GroupVersion().WithKind("EngineReportList"))
	if err := probe.List(context.Background(), list, client.InNamespace("a")); err != nil || len(list.Items) != 1 {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(list.Items[0].Object)
	size := int64(len(raw))
	for name, tc := range map[string]struct {
		n     int
		l     func(*provider.Limits)
		fault func(conformance.Page) conformance.PageFault
		code  provider.StopCode
		// requests are the list requests made before the stop.
		requests int
	}{
		"objects":           {n: 3, l: func(l *provider.Limits) { l.MaxObjects = 4 }, code: provider.StopObjectLimit, requests: 2},
		"objects in a page": {n: 5, l: func(l *provider.Limits) { l.PageSize, l.MaxObjects = 2, 4 }, code: provider.StopObjectLimit, requests: 3},
		"bytes":             {n: 3, l: func(l *provider.Limits) { l.MaxBytes = 4*size - 1 }, code: provider.StopByteLimit, requests: 2},
		"oversized object":  {n: 1, l: func(l *provider.Limits) { l.MaxBytes = size - 1 }, code: provider.StopByteLimit, requests: 1},
		"requests":          {n: 5, l: func(l *provider.Limits) { l.PageSize, l.MaxPages = 2, 3 }, code: provider.StopPageLimit, requests: 3},
		"endless pages": {n: 3, l: func(l *provider.Limits) { l.PageSize, l.MaxPages = 2, 50 }, code: provider.StopPageLimit, requests: 50,
			fault: func(p conformance.Page) conformance.PageFault {
				if p.Number > 0 {
					return conformance.PageEmpty
				}
				return conformance.PageOK
			}},
		"repeated page": {n: 5, l: func(l *provider.Limits) { l.PageSize = 2 }, code: provider.StopInvalidList, requests: 2,
			fault: func(p conformance.Page) conformance.PageFault {
				if p.Number == 1 {
					return conformance.PageRepeated
				}
				return conformance.PageOK
			}},
	} {
		t.Run(name, func(t *testing.T) {
			rec, pager := pagedCluster(t, tc.n)
			pager.Fault = tc.fault
			l := limits(tc.l)
			got, lims, err := provider.Collect(context.Background(), rec, enforcing(), twoNamespaces, l, careless(twoNamespaces))
			if err != nil || got != nil || len(lims) != 1 || !strings.Contains(lims[0], "("+string(tc.code)+")") {
				t.Fatalf("result %v, limitations %v, error %v", got, lims, err)
			}
			if n := len(rec.Calls()); n != tc.requests {
				t.Fatalf("%d requests %v, want %d", n, kinds(rec.Calls()), tc.requests)
			}
			if w := rec.Writes(); len(w) != 0 {
				t.Fatalf("writes %v", w)
			}
		})
	}
}

// A bound that the adapter's own readers meet is returned to the adapter as
// the collection's LimitError, and every later read returns the same one.
func TestStoppedCollectionRefusesLaterReads(t *testing.T) {
	rec, _ := pagedCluster(t, 3)
	l := limits(func(l *provider.Limits) { l.MaxObjects = 2 })
	var errs []error
	_, _, err := provider.Collect(context.Background(), rec, enforcing(), twoNamespaces, l, func(ctx context.Context, src provider.Sources) (any, []string, error) {
		r, _ := src.Source(enforcing().Reads[0])
		for _, ns := range []string{"a", "b", "a"} {
			_, err := r.List(ctx, ns)
			errs = append(errs, err)
		}
		return nil, nil, nil
	})
	var stop *provider.LimitError
	if err != nil || len(errs) != 3 || !errors.As(errs[0], &stop) || stop.Code != provider.StopObjectLimit ||
		!errors.Is(errs[1], provider.ErrCollectionStopped) || errs[1] != errs[0] || errs[2] != errs[0] {
		t.Fatalf("errors %v, %v", errs, err)
	}
	if n := len(rec.Calls()); n != 1 {
		t.Fatalf("%d requests after the stop", n)
	}
}

// The host's deadline stops the collection: a read after it is refused
// without a request, and an adapter that overruns its deadline gets no
// result even if all its reads had completed.
func TestDeadlineStopsTheCollection(t *testing.T) {
	rec, _ := pagedCluster(t, 3)
	l := limits(func(l *provider.Limits) { l.Timeout = 250 * time.Millisecond })
	slow := func(ctx context.Context, src provider.Sources) (collected, []string, error) {
		r, _ := src.Source(enforcing().Reads[0])
		a, err := r.List(ctx, "a")
		if err != nil {
			return nil, nil, err
		}
		<-ctx.Done()
		b, _ := r.List(ctx, "b")
		return collected{"a": names(a), "b": names(b)}, nil, nil
	}
	got, lims, err := provider.Collect(context.Background(), rec, enforcing(), twoNamespaces, l, slow)
	if err != nil || got != nil || len(lims) != 1 || !strings.Contains(lims[0], "(timeout): the collection exceeded its 250ms deadline") {
		t.Fatalf("result %v, limitations %v, error %v", got, lims, err)
	}
	if want := []string{"list EngineReportList a"}; !slices.Equal(kinds(rec.Calls()), want) {
		t.Fatalf("requests %v", kinds(rec.Calls()))
	}

	rec.Reset()
	overrun := func(ctx context.Context, src provider.Sources) (collected, []string, error) {
		out, lims, err := careless(twoNamespaces)(ctx, src)
		<-ctx.Done()
		return out, lims, err
	}
	got, lims, err = provider.Collect(context.Background(), rec, enforcing(), twoNamespaces, l, overrun)
	if err != nil || got != nil || len(lims) != 1 || !strings.Contains(lims[0], "(timeout)") || len(rec.Calls()) != 2 {
		t.Fatalf("overrun: %v %v %v %v", got, lims, err, rec.Calls())
	}
}

// Ending the host's context (leadership loss, shutdown) is an error, not a
// limitation: the caller records nothing from the pass. Reads stop at the
// cancellation, whatever the adapter does with the error.
func TestCancellationIsAnError(t *testing.T) {
	rec, _ := pagedCluster(t, 3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec.Fail = func(c conformance.Call) error {
		if c.Namespace == "b" {
			cancel() // leadership is lost while b is listed
			return ctx.Err()
		}
		return nil
	}
	three := provider.Scope{Cluster: "c", Namespaces: append(slices.Clone(twoNamespaces.Namespaces), provider.Namespace{Name: "other", UID: "uid-other"})}
	got, lims, err := provider.Collect(ctx, rec, enforcing(), three, provider.DefaultLimits(), careless(three))
	if !errors.Is(err, context.Canceled) || got != nil || lims != nil {
		t.Fatalf("result %v, limitations %v, error %v", got, lims, err)
	}
	if want := []string{"list EngineReportList a", "list EngineReportList b"}; !slices.Equal(kinds(rec.Calls()), want) {
		t.Fatalf("requests after cancellation %v", kinds(rec.Calls()))
	}
	// Already canceled: nothing is read.
	rec.Reset()
	if _, _, err := provider.Collect(ctx, rec, enforcing(), twoNamespaces, provider.DefaultLimits(), careless(twoNamespaces)); !errors.Is(err, context.Canceled) || len(rec.Calls()) != 0 {
		t.Fatalf("canceled before collection: %v %v", err, rec.Calls())
	}
}

// A source failure is not a bound: the adapter sees the source's error
// unchanged and its result, limitations and errors are returned as they
// are. Collection never retries it.
func TestSourceFailuresAreTheAdapters(t *testing.T) {
	rec, _ := pagedCluster(t, 3)
	boom := errors.New("injected")
	rec.Fail = func(c conformance.Call) error {
		if c.Namespace == "a" {
			return boom
		}
		return nil
	}
	var seen error
	got, lims, err := provider.Collect(context.Background(), rec, enforcing(), twoNamespaces, provider.DefaultLimits(),
		func(ctx context.Context, src provider.Sources) (collected, []string, error) {
			r, _ := src.Source(enforcing().Reads[0])
			_, seen = r.List(ctx, "a")
			b, err := r.List(ctx, "b")
			return collected{"b": names(b)}, []string{"a unavailable"}, err
		})
	if seen != boom || err != nil || !slices.Equal(got["b"], []string{"rb-0", "rb-1"}) || !slices.Equal(lims, []string{"a unavailable"}) {
		t.Fatalf("seen %v; result %v %v %v", seen, got, lims, err)
	}
	adapterErr := errors.New("adapter error")
	if _, _, err := provider.Collect(context.Background(), rec, enforcing(), twoNamespaces, provider.DefaultLimits(),
		func(context.Context, provider.Sources) (any, []string, error) { return nil, nil, adapterErr }); err != adapterErr {
		t.Fatalf("adapter error %v", err)
	}
}

// The readers an adapter gets cannot write by construction: neither the
// Sources nor a SourceReader is a client writer, status writer or
// subresource client, so the adapter has no way to reach one. Through
// every bound and fault above, the recording client saw only lists.
func TestCollectionCannotWrite(t *testing.T) {
	rec, _ := pagedCluster(t, 3)
	_, _, err := provider.Collect(context.Background(), rec, enforcing(), twoNamespaces, provider.DefaultLimits(),
		func(ctx context.Context, src provider.Sources) (any, []string, error) {
			r, err := src.Source(enforcing().Reads[0])
			if err != nil {
				return nil, nil, err
			}
			for _, v := range []any{src, r} {
				if _, ok := v.(client.Writer); ok {
					t.Errorf("%T is a client.Writer", v)
				}
				if _, ok := v.(client.StatusClient); ok {
					t.Errorf("%T is a client.StatusClient", v)
				}
				if _, ok := v.(client.SubResourceClientConstructor); ok {
					t.Errorf("%T is a client.SubResourceClientConstructor", v)
				}
				if _, ok := v.(client.Reader); ok {
					t.Errorf("%T is a client.Reader", v)
				}
			}
			_, err = r.List(ctx, "a")
			return nil, nil, err
		})
	if err != nil || len(rec.Writes()) != 0 {
		t.Fatalf("%v, writes %v", err, rec.Writes())
	}
	for _, c := range rec.Calls() {
		if c.Verb != "list" || c.Write() {
			t.Fatalf("request %+v", c)
		}
	}
}
