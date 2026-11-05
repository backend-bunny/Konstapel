package publication_test

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/crdtest"
	"github.com/backend-bunny/Konstapel/internal/publication"
)

// jsonFields returns every JSON field path of a type, so the backend contract
// and the CRD status cannot drift apart silently.
func jsonFields(ty reflect.Type, prefix string, out map[string]bool) {
	for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice {
		ty = ty.Elem()
	}
	if ty.Kind() != reflect.Struct || ty.PkgPath() == "time" || strings.HasSuffix(ty.PkgPath(), "apis/meta/v1") {
		return
	}
	for i := range ty.NumField() {
		f := ty.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		out[prefix+name] = true
		jsonFields(f.Type, prefix+name+".", out)
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestAPIStatusMatchesContract(t *testing.T) {
	a, b := map[string]bool{}, map[string]bool{}
	jsonFields(reflect.TypeOf(publication.Status{}), "", a)
	jsonFields(reflect.TypeOf(v1alpha1.PublicationStatus{}), "", b)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("publication.Status and v1alpha1.PublicationStatus differ:\n%v\n%v", keys(a), keys(b))
	}
	a, b = map[string]bool{}, map[string]bool{}
	jsonFields(reflect.TypeOf(publication.RunSummary{}.Evidence), "", a)
	jsonFields(reflect.TypeOf(v1alpha1.EvidenceSummary{}), "", b)
	c, d := map[string]bool{}, map[string]bool{}
	jsonFields(reflect.TypeOf(publication.OutcomeCounts{}), "", c)
	jsonFields(reflect.TypeOf(v1alpha1.OutcomeCounts{}), "", d)
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(c, d) {
		t.Fatal("summary types differ between contract and API")
	}
}

func TestAPIStatusRoundTripsAndValidatesInCRD(t *testing.T) {
	crds := crdtest.Load(t, "../../config/crd/bases")
	st := publication.Committed(receipt())
	st.OwnedObjects = []publication.OwnedObject{{Role: publication.ObjectArchive, AttemptID: "a1", Key: st.Commit.ArchiveKey, VersionID: "a1"}}
	failed := publication.Status{Phase: publication.PhaseFailed, PublicationID: "pub-2", Availability: publication.AvailabilityUnavailable, Cleanup: publication.Cleanup{State: publication.CleanupNotDue}, Failure: &publication.Failure{Reason: "BackendUnavailable", Retryable: true, At: receipt().PublishedAt}}
	for _, s := range []publication.Status{st, failed} {
		back := publication.FromAPI(publication.ToAPI(s))
		x, _ := json.Marshal(s)
		y, _ := json.Marshal(back)
		if string(x) != string(y) {
			t.Fatalf("conversion is lossy:\n%s\n%s", x, y)
		}
		sum := publication.SummaryToAPI(publication.Summarize(fixtures()["namespace-complete"], s))
		run := v1alpha1.AssessmentRun{Spec: v1alpha1.AssessmentRunSpec{BindingRef: v1alpha1.BindingReference{Name: "b"}, Scope: v1alpha1.RunScopeBinding}}
		run.APIVersion, run.Kind, run.Name = v1alpha1.GroupVersion.String(), "AssessmentRun", "run"
		pub := publication.ToAPI(s)
		run.Status.Publication, run.Status.Summary = &pub, &sum
		raw, _ := json.Marshal(run)
		var o map[string]any
		_ = json.Unmarshal(raw, &o)
		if errs := crds["AssessmentRun"].Validate(o); len(errs) > 0 {
			t.Fatalf("status rejected by CRD schema: %v", errs.ToAggregate())
		}
	}
}
