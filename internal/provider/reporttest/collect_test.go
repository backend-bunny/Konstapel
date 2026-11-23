package reporttest_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

var (
	postureGVK = schema.GroupVersionKind{Group: "reporttest.konstapel.io", Version: "v1", Kind: "Posture"}
	at         = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	digestA    = "sha256:" + strings.Repeat("a", 64)
	digestZ    = "sha256:" + strings.Repeat("f", 64)
)

func posture(name, digest string, evaluated time.Time, verdicts map[string]any) client.Object {
	u := &unstructured.Unstructured{Object: map[string]any{"digest": digest, "verdicts": verdicts,
		"evaluatedAt": evaluated.Format(time.RFC3339), "updatedAt": at.Add(-time.Second).Format(time.RFC3339)}}
	u.SetGroupVersionKind(postureGVK)
	u.SetName(name)
	return u
}

func postureCluster(objs ...client.Object) *conformance.RecordingClient {
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(postureGVK, meta.RESTScopeRoot)
	return conformance.NewRecordingClient(fake.NewClientBuilder().WithRESTMapper(mapper).WithObjects(objs...).Build())
}

// Two workloads in different namespaces run the same image; a third
// container runs a tag-only image.
var (
	subjects = []reporttest.Subject{
		{NamespaceUID: "ns-shop", WorkloadUID: "w-web", Container: "app", Image: "registry.example/shop@" + digestA},
		{NamespaceUID: "ns-api", WorkloadUID: "w-api", Container: "server", Image: "registry.example/shop@" + digestA},
		{NamespaceUID: "ns-api", WorkloadUID: "w-api", Container: "sidecar", Image: "registry.example/proxy:latest"},
	}
	postureScope = provider.Scope{Cluster: "c", Namespaces: []provider.Namespace{{Name: "api", UID: "ns-api"}, {Name: "shop", UID: "ns-shop"}}}
	checks       = []string{"no-critical", "signed"}
)

func collectPostures(t *testing.T, c client.Reader, s provider.Scope, subs []reporttest.Subject) ([]reporttest.Report, []string) {
	t.Helper()
	reports, limits, err := reporttest.Collect(context.Background(), s, subs, provider.ClientSources(c, reporttest.Descriptor(), s))
	if err != nil {
		t.Fatal(err)
	}
	return reports, limits
}

// check evaluates collected evidence through the shared conformance
// invariants and returns the result.
func check(t *testing.T, subs []reporttest.Subject, reports []reporttest.Report) conformance.Expected {
	t.Helper()
	in, err := json.Marshal(reporttest.Input{PayloadVersion: reporttest.PayloadVersion, MaxEvidenceAge: "1h", Subjects: subs, Checks: checks, Reports: reports})
	if err != nil {
		t.Fatal(err)
	}
	got, errs := conformance.Check(reporttest.Adapter{}, conformance.Case{Version: conformance.CaseVersion, Provider: reporttest.Contract, EvaluationTime: at, Input: in})
	for _, e := range errs {
		t.Error(e)
	}
	return got
}

func states(e conformance.Expected) map[string]string {
	out := map[string]string{}
	for _, o := range e.Observations {
		out[o.Subject+" "+o.Check] = string(o.State) + "/" + o.Raw
	}
	return out
}

// The shared, cluster-scoped source is listed once; only the report for an
// image the frozen subjects run is kept, and it is evidence for each
// subject running that image, credited once each. Another image's report
// is never retained, a malformed object is a limitation rather than
// evidence, and a tag-only image is unresolved. Collection makes only that
// one list request: no write of any kind.
func TestReportingCollectionKeepsOnlyAttributableSharedEvidence(t *testing.T) {
	bad := posture("p-bad", "not-a-digest", at.Add(-5*time.Minute), map[string]any{"no-critical": "Passed"})
	rec := postureCluster(
		posture("p-shop", digestA, at.Add(-10*time.Minute), map[string]any{"no-critical": "Passed", "signed": "Violated"}),
		posture("p-other", digestZ, at.Add(-5*time.Minute), map[string]any{"no-critical": "Violated"}), bad)
	reports, limits := collectPostures(t, rec, postureScope, subjects)
	if len(reports) != 1 || reports[0].ID != "p-shop" || reports[0].Digest != digestA || reports[0].UpdatedAt == nil {
		t.Fatalf("reports %+v", reports)
	}
	if len(limits) != 1 || !strings.Contains(limits[0], `posture "p-bad" is not used as evidence`) {
		t.Fatalf("limitations %v", limits)
	}
	if calls := rec.Calls(); !slices.Equal(calls, []conformance.Call{{Verb: "list", Kind: "PostureList"}}) {
		t.Fatalf("requests %v", calls)
	}
	got := check(t, subjects, reports)
	want := map[string]string{
		"ns-shop/w-web/app no-critical": "Attributable/Passed", "ns-shop/w-web/app signed": "Attributable/Violated",
		"ns-api/w-api/server no-critical": "Attributable/Passed", "ns-api/w-api/server signed": "Attributable/Violated",
		"ns-api/w-api/sidecar no-critical": "Unresolved/", "ns-api/w-api/sidecar signed": "Unresolved/",
	}
	if s := states(got); !mapsEqual(s, want) {
		t.Fatalf("observations %v, want %v", s, want)
	}
	if got.Outcomes.Pass != 2 || got.Outcomes.Fail != 2 || got.Evidence.Expected != 6 || got.Evidence.Attributable != 4 || got.Evidence.Unresolved != 2 {
		t.Fatalf("evidence %+v outcomes %+v", got.Evidence, got.Outcomes)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Without reports, or when the source cannot be listed, every attributable
// subject is missing and nothing passes; a failed list is a limitation.
func TestReportingCollectionWithoutReportsIsMissing(t *testing.T) {
	for name, fail := range map[string]bool{"no reports": false, "source unavailable": true} {
		t.Run(name, func(t *testing.T) {
			rec := postureCluster()
			if fail {
				rec.Fail = func(conformance.Call) error { return errors.New("injected") }
			}
			reports, limits := collectPostures(t, rec, postureScope, subjects)
			if len(reports) != 0 || fail != slices.Equal(limits, []string{"postures unavailable: injected"}) || !fail && len(limits) != 0 {
				t.Fatalf("reports %v limitations %v", reports, limits)
			}
			got := check(t, subjects, reports)
			if got.Evidence.Missing != 4 || got.Evidence.Unresolved != 2 || got.Outcomes != (conformance.Expected{}).Outcomes {
				t.Fatalf("evidence %+v outcomes %+v", got.Evidence, got.Outcomes)
			}
		})
	}
}

// No subjects, or only subjects no report can be attributed to, read
// nothing; a subject outside the host-frozen scope is refused before any
// read.
func TestReportingCollectionReadsNothingItCannotUse(t *testing.T) {
	rec := postureCluster(posture("p-shop", digestA, at.Add(-time.Minute), map[string]any{"signed": "Passed"}))
	for name, subs := range map[string][]reporttest.Subject{"no subjects": nil, "tag-only": subjects[2:]} {
		reports, limits := collectPostures(t, rec, postureScope, subs)
		if len(reports) != 0 || len(limits) != 0 {
			t.Fatalf("%s: reports %v limitations %v", name, reports, limits)
		}
	}
	if got := check(t, nil, nil); got.Evidence.Completeness != "NoTargets" {
		t.Fatalf("zero targets: %+v", got.Evidence)
	}
	narrow := provider.Scope{Cluster: "c", Namespaces: []provider.Namespace{{Name: "shop", UID: "ns-shop"}}}
	if _, _, err := reporttest.Collect(context.Background(), narrow, subjects, provider.ClientSources(rec, reporttest.Descriptor(), narrow)); err == nil ||
		!strings.Contains(err.Error(), "outside the collection scope") {
		t.Fatalf("out-of-scope subject: %v", err)
	}
	if calls := rec.Calls(); len(calls) != 0 {
		t.Fatalf("requests %v", calls)
	}
}
