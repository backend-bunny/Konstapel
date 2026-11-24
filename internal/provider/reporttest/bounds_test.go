package reporttest_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

// The reporting adapter under the host's bounds (add-assessment-provider-
// contract 2.3), and the proof that it writes nothing.

var scanJob = schema.GroupVersionKind{Group: "scanner.example.io", Version: "v1", Kind: "ScanJob"}

// scannerCluster is a cluster with postures, the workloads they describe
// and a scanner's own objects, served in pages behind the recording
// fixture. A reporting adapter could be tempted to create a scan, label a
// workload or repair a report there; it must not.
func scannerCluster(objs ...client.Object) (*conformance.RecordingClient, *conformance.PagingClient) {
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(postureGVK, meta.RESTScopeRoot)
	mapper.Add(scanJob, meta.RESTScopeNamespace)
	mapper.Add(schema.GroupVersionKind{Version: "v1", Kind: "Pod"}, meta.RESTScopeNamespace)
	job := &unstructured.Unstructured{}
	job.SetGroupVersionKind(scanJob)
	job.SetNamespace("shop")
	job.SetName("scan-web")
	objs = append(objs, job, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web", UID: "w-web"}})
	pager := conformance.NewPagingClient(fake.NewClientBuilder().WithRESTMapper(mapper).WithObjects(objs...).Build())
	return conformance.NewRecordingClient(pager), pager
}

func shopPostures() []client.Object {
	return []client.Object{
		posture("p-shop", digestA, at.Add(-10*time.Minute), map[string]any{"no-critical": "Passed", "signed": "Violated"}),
		posture("p-other", digestZ, at.Add(-5*time.Minute), map[string]any{"no-critical": "Violated"}),
		posture("p-bad", "not-a-digest", at.Add(-5*time.Minute), map[string]any{"no-critical": "Passed"}),
	}
}

func boundedPostures(ctx context.Context, c client.Reader, l provider.Limits) ([]reporttest.Report, []string, error) {
	return provider.Collect(ctx, c, reporttest.Descriptor(), postureScope, l,
		func(ctx context.Context, src provider.Sources) ([]reporttest.Report, []string, error) {
			return reporttest.Collect(ctx, postureScope, subjects, src)
		})
}

// In every outcome, bounded or not, the reporting adapter makes only its
// one declared read, a cluster-scoped list of postures, page by page: no
// create, update, patch, apply, delete or subresource request of any kind,
// so no scan is triggered and no report or workload is changed. Within
// the limits its result is the unbounded one; a bound discards it.
func TestReportingCollectionUnderHostBounds(t *testing.T) {
	unbounded, unboundedLimits := collectPostures(t, postureCluster(shopPostures()...), postureScope, subjects)
	huge := map[string]any{"no-critical": "Passed", "signed": strings.Repeat("x", 4096)}
	for name, tc := range map[string]struct {
		objs   []client.Object
		limits func(*provider.Limits)
		fail   func(context.CancelFunc) func(conformance.Call) error
		// stop is the expected bound; "" expects the unbounded result.
		stop     provider.StopCode
		canceled bool
		// lists is the number of list requests.
		lists int
	}{
		"within the limits": {lists: 1},
		"paginated":         {limits: func(l *provider.Limits) { l.PageSize = 1 }, lists: 3},
		"at the bounds":     {limits: func(l *provider.Limits) { l.PageSize, l.MaxPages, l.MaxObjects = 1, 3, 3 }, lists: 3},
		"objects":           {limits: func(l *provider.Limits) { l.MaxObjects = 2 }, stop: provider.StopObjectLimit, lists: 1},
		"oversized posture": {objs: []client.Object{posture("p-huge", digestA, at, huge)}, limits: func(l *provider.Limits) { l.MaxBytes = 4096 },
			stop: provider.StopByteLimit, lists: 1},
		"requests": {limits: func(l *provider.Limits) { l.PageSize, l.MaxPages = 1, 2 }, stop: provider.StopPageLimit, lists: 2},
		"deadline": {limits: func(l *provider.Limits) { l.Timeout = time.Nanosecond }, stop: provider.StopTimeout, lists: 0},
		"leadership lost": {fail: func(cancel context.CancelFunc) func(conformance.Call) error {
			return func(conformance.Call) error { cancel(); return context.Canceled }
		}, canceled: true, lists: 1},
	} {
		t.Run(name, func(t *testing.T) {
			rec, _ := scannerCluster(append(shopPostures(), tc.objs...)...)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.fail != nil {
				rec.Fail = tc.fail(cancel)
			}
			l := provider.DefaultLimits()
			if tc.limits != nil {
				tc.limits(&l)
			}
			reports, limits, err := boundedPostures(ctx, rec, l)
			switch {
			case tc.canceled:
				if !errors.Is(err, context.Canceled) || reports != nil || limits != nil {
					t.Fatalf("canceled: %v %v %v", reports, limits, err)
				}
			case tc.stop != "":
				if err != nil || reports != nil || len(limits) != 1 || !strings.Contains(limits[0], "("+string(tc.stop)+")") ||
					!strings.HasPrefix(limits[0], "konstapel-reporttest/v1 evidence is not used") {
					t.Fatalf("stopped: %v %v %v", reports, limits, err)
				}
				// Without its reports every attributable subject is
				// missing: nothing passes.
				if got := check(t, subjects, []reporttest.Report{}); got.Evidence.Attributable != 0 || got.Outcomes.Pass != 0 {
					t.Fatalf("evidence %+v", got.Evidence)
				}
			default:
				if err != nil || asJSON(reports) != asJSON(unbounded) || !slices.Equal(limits, unboundedLimits) {
					t.Fatalf("within the limits: %v %v %v, want %v %v", reports, limits, err, unbounded, unboundedLimits)
				}
			}
			if w := rec.Writes(); len(w) != 0 {
				t.Fatalf("the reporting adapter wrote %v", w)
			}
			calls := rec.Calls()
			for _, c := range calls {
				if c != (conformance.Call{Verb: "list", Kind: "PostureList"}) {
					t.Fatalf("request %+v", c)
				}
			}
			if len(calls) != tc.lists {
				t.Fatalf("%d list requests, want %d", len(calls), tc.lists)
			}
		})
	}
}

// A source failure and an object of another layout are the adapter's own
// limitations, passed through unchanged by the host: they are not bounds.
func TestReportingLimitationsPassThrough(t *testing.T) {
	rec, _ := scannerCluster(shopPostures()...)
	reports, limits, err := boundedPostures(context.Background(), rec, provider.DefaultLimits())
	if err != nil || len(reports) != 1 || len(limits) != 1 || !strings.Contains(limits[0], `posture "p-bad" is not used as evidence`) {
		t.Fatalf("%v %v %v", reports, limits, err)
	}
	rec.Fail = func(conformance.Call) error { return errors.New("injected") }
	reports, limits, err = boundedPostures(context.Background(), rec, provider.DefaultLimits())
	if err != nil || len(reports) != 0 || !slices.Equal(limits, []string{"postures unavailable: injected"}) || len(rec.Writes()) != 0 {
		t.Fatalf("%v %v %v", reports, limits, err)
	}
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
