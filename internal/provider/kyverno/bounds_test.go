package kyverno_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/collector"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// The Kyverno collection under the host's bounds (add-assessment-provider-
// contract 2.3).

// pagedFakeCluster serves the reports in pages, as the API server does.
func pagedFakeCluster(objs ...client.Object) (*conformance.RecordingClient, *conformance.PagingClient) {
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(policyReport, meta.RESTScopeNamespace)
	mapper.Add(clusterPolicyReport, meta.RESTScopeRoot)
	pager := conformance.NewPagingClient(fake.NewClientBuilder().WithRESTMapper(mapper).WithObjects(objs...).Build())
	return conformance.NewRecordingClient(pager), pager
}

// bounded runs the adapters as the controller does: collection through the
// host's bounds, then the inventory.
func bounded(ctx context.Context, t *testing.T, c client.Reader, l provider.Limits) (collector.CaptureV2, []string, error) {
	t.Helper()
	got, limits, err := provider.Collect(ctx, c, kyverno.Descriptor(), scope, l,
		func(ctx context.Context, src provider.Sources) ([]assessment.Object, []string, error) {
			return kyverno.Collect(ctx, scope, src)
		})
	if err != nil {
		return collector.CaptureV2{}, nil, err
	}
	capture, err := kyverno.Inventory(frozenInput())
	if err != nil {
		t.Fatal(err)
	}
	capture.Reports = got
	capture.Window.Closed = closed
	return capture, limits, nil
}

// padding adds n reports about workloads outside the inventory to
// namespace ns. They attribute nothing.
func padding(ns string, n int) []client.Object {
	var out []client.Object
	for i := range n {
		out = append(out, report(policyReport, ns, fmt.Sprintf("zz-other-%04d", i), result("kp-pods", "fail", "0", evaluated, ref("Pod", ns, "other", fmt.Sprintf("other-%d", i)))))
	}
	return out
}

// Within the default limits the bounded, paginated collection is exactly
// the direct path: a namespace with more reports than a page is read in
// pages and its capture, limitations and evaluation are unchanged.
func TestBoundedCollectionMatchesTheDirectPath(t *testing.T) {
	objs := append(reports(), padding("a", 1_100)...)
	rec, pager := pagedFakeCluster(objs...)
	got, limits, err := bounded(context.Background(), t, rec, provider.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	calls := rec.Calls()
	want, wantLimits := direct(t, fakeCluster(objs...), frozenInput(), scope)
	slices.SortFunc(want.Reports, func(x, y assessment.Object) int { return strings.Compare(asJSON(x), asJSON(y)) })
	sorted := slices.Clone(got.Reports)
	slices.SortFunc(sorted, func(x, y assessment.Object) int { return strings.Compare(asJSON(x), asJSON(y)) })
	if len(got.Reports) != 1_104 || asJSON(sorted) != asJSON(want.Reports) || !slices.Equal(limits, wantLimits) || len(limits) != 0 {
		t.Fatalf("bounded collection differs from the direct path: %d reports, %v", len(got.Reports), limits)
	}
	if asJSON(evaluate(t, got)) != asJSON(evaluate(t, want)) {
		t.Fatal("bounded evaluation differs from the direct path")
	}
	pagesOf := map[string]int{}
	for _, c := range calls {
		pagesOf[c.Namespace]++
	}
	if pagesOf["a"] != 3 || pagesOf["b"] != 1 || len(calls) != 4 || len(pager.Pages()) != 4 || len(rec.Writes()) != 0 {
		t.Fatalf("requests %v", calls)
	}
}

// A bound met in namespace b discards the whole collection: although the
// adapter keeps namespace a's reports on a failed list, none is used. Every
// expected observation is missing, the evidence is incomplete and the
// limitation says why; the truncated reports never make it look complete.
func TestStoppedCollectionUsesNoReports(t *testing.T) {
	for name, l := range map[string]func(*provider.Limits){
		"objects":  func(l *provider.Limits) { l.MaxObjects = 4 },
		"requests": func(l *provider.Limits) { l.PageSize, l.MaxPages = 2, 2 },
	} {
		t.Run(name, func(t *testing.T) {
			rec, _ := pagedFakeCluster(append(reports(), padding("b", 2)...)...)
			lim := provider.DefaultLimits()
			l(&lim)
			got, limits, err := bounded(context.Background(), t, rec, lim)
			if err != nil {
				t.Fatal(err)
			}
			if got.Reports != nil || len(limits) != 1 || !strings.HasPrefix(limits[0], "konstapel-kyverno/v1 evidence is not used: collection stopped") {
				t.Fatalf("reports %d, limitations %v", len(got.Reports), limits)
			}
			ev := evaluate(t, got)
			if ev.Evidence.Completeness != publication.Incomplete || ev.Evidence.Expected != 6 || ev.Evidence.Missing != 6 || ev.Outcomes != (publication.OutcomeCounts{}) {
				t.Fatalf("evidence %+v outcomes %+v", ev.Evidence, ev.Outcomes)
			}
			if len(rec.Writes()) != 0 {
				t.Fatalf("writes %v", rec.Writes())
			}
		})
	}
}

// Leadership loss while namespace b is listed is an error: no capture, no
// limitation, and namespace a's reports are not returned either.
func TestCanceledCollectionIsAnError(t *testing.T) {
	rec, _ := pagedFakeCluster(reports()...)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec.Fail = func(c conformance.Call) error {
		if c.Namespace == "b" {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	if _, limits, err := bounded(ctx, t, rec, provider.DefaultLimits()); !errors.Is(err, context.Canceled) || limits != nil {
		t.Fatalf("limitations %v, error %v", limits, err)
	}
	if len(rec.Calls()) != 2 || len(rec.Writes()) != 0 {
		t.Fatalf("requests %v", rec.Calls())
	}
}
