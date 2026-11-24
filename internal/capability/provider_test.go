package capability

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

// The Assessment requirements exactly as internal/capability hard-coded
// them before they were derived from the Kyverno descriptor (5f1c19f).
// Changing the Kyverno descriptor's reads or prerequisites changes what the
// controller requires of the cluster, and must change this on purpose.
var assessmentBefore = []Resource{
	{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "policyreports", Kind: "PolicyReport", Namespaced: true,
		Verbs: []string{"get", "list", "watch"}, Access: []string{"get", "list", "watch"}},
	{Group: "wgpolicyk8s.io", Version: "v1alpha2", Resource: "clusterpolicyreports", Kind: "ClusterPolicyReport",
		Verbs: []string{"get", "list", "watch"}},
}

func TestAssessmentIsTheKyvernoDescriptorsPrerequisites(t *testing.T) {
	if got := ForProvider(kyverno.Descriptor()); !reflect.DeepEqual(got, assessmentBefore) {
		t.Fatalf("Kyverno prerequisites %+v, want the former Assessment requirements %+v", got, assessmentBefore)
	}
	if !reflect.DeepEqual(Requirements[Assessment], assessmentBefore) {
		t.Fatalf("Assessment requirements %+v, want %+v", Requirements[Assessment], assessmentBefore)
	}
}

func TestForProviderDerivesReadsThenPrerequisites(t *testing.T) {
	d := reporttest.Descriptor()
	d.Requires = []provider.Prerequisite{{Group: "reporttest.konstapel.io", Version: "v1", Resource: "scans", Kind: "Scan", Namespaced: true, Verbs: []string{"list"}}}
	d.Reads = append(d.Reads, provider.Read{Group: "", Version: "v1", Resource: "configmaps", Kind: "ConfigMap", Namespaced: true, Verbs: []string{"get"}})
	want := []Resource{
		{Group: "reporttest.konstapel.io", Version: "v1", Resource: "postures", Kind: "Posture", Verbs: []string{"get", "list"}, Access: []string{"get", "list"}},
		{Version: "v1", Resource: "configmaps", Kind: "ConfigMap", Namespaced: true, Verbs: []string{"get"}, Access: []string{"get"}},
		{Group: "reporttest.konstapel.io", Version: "v1", Resource: "scans", Kind: "Scan", Namespaced: true, Verbs: []string{"list"}},
	}
	got := ForProvider(d)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("requirements %+v, want %+v", got, want)
	}
	got[0].Access[0] = "delete"
	if d.Reads[0].Verbs[0] != "get" {
		t.Fatal("requirements share the descriptor's verbs")
	}
}

// postures is the test-only reporting provider's served source.
func postures() *metav1.APIResourceList {
	return &metav1.APIResourceList{GroupVersion: "reporttest.konstapel.io/v1", APIResources: []metav1.APIResource{
		{Name: "postures", Kind: "Posture", Verbs: all},
	}}
}

// recordingDiscovery records the group/versions discovery is asked for.
type recordingDiscovery struct {
	*fakediscovery.FakeDiscovery
	mu    sync.Mutex
	asked []string
}

func (d *recordingDiscovery) ServerResourcesForGroupVersionWithContext(ctx context.Context, gv string) (*metav1.APIResourceList, error) {
	d.mu.Lock()
	d.asked = append(d.asked, gv)
	d.mu.Unlock()
	return d.FakeDiscovery.ServerResourcesForGroupVersionWithContext(ctx, gv)
}

func (d *recordingDiscovery) reset() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.asked
	d.asked = nil
	return out
}

type providerEnv struct {
	*env
	rec *recordingDiscovery
	p   *Providers
}

// newProviderEnv checks the Kyverno provider and the test-only reporting
// provider through one monitor over lists.
func newProviderEnv(t *testing.T, lists []*metav1.APIResourceList) *providerEnv {
	t.Helper()
	e := newEnv(lists)
	rec := &recordingDiscovery{FakeDiscovery: e.disc}
	e.m.Discovery = rec
	p, err := NewProviders(e.m, kyverno.Descriptor(), reporttest.Descriptor())
	if err != nil {
		t.Fatal(err)
	}
	return &providerEnv{env: e, rec: rec, p: p}
}

func (e *providerEnv) expect(t *testing.T, what string, got Result, want Reason, contains string) {
	t.Helper()
	if got.Reason != want || !strings.Contains(got.Message, contains) {
		t.Fatalf("%s: got %s %q, want %s containing %q", what, got.Reason, got.Message, want, contains)
	}
}

// For the installed Kyverno provider the per-provider checks are the
// existing capabilities: the same result, reason and message in every
// state the capability tests cover.
func TestKyvernoAvailabilityIsTheExistingCapabilities(t *testing.T) {
	forbidden := func(e *env) {
		e.disc.PrependReactor("get", "resource", func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{}, "", errors.New("discovery denied"))
		})
	}
	transport := func(e *env) {
		e.disc.PrependReactor("get", "resource", func(clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("dial tcp: connection refused")
		})
	}
	for name, setup := range map[string]func(*env){
		"available":          func(*env) {},
		"reports not served": func(e *env) { e.disc.Resources = e.disc.Resources[:1] },
		"engine not served":  func(e *env) { e.disc.Resources = e.disc.Resources[1:] },
		"cluster reports missing": func(e *env) {
			e.disc.Resources[1].APIResources = e.disc.Resources[1].APIResources[:1]
		},
		"reports cluster-scoped": func(e *env) { e.disc.Resources[1].APIResources[0].Namespaced = false },
		"reports without watch":  func(e *env) { e.disc.Resources[1].APIResources[0].Verbs = []string{"get", "list"} },
		"report watch denied":    func(e *env) { e.denied["policyreports/watch"] = true },
		"engine delete denied":   func(e *env) { e.denied["validatingpolicies/delete"] = true },
		"discovery forbidden":    forbidden,
		"transport failure":      transport,
		"review fails": func(e *env) {
			e.m.Review = func(context.Context, authorizationv1.ResourceAttributes) (bool, string, error) {
				return false, "", errors.New("timeout")
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newProviderEnv(t, slices.Concat(served(), []*metav1.APIResourceList{postures()}))
			setup(e.env)
			ctx := context.Background()
			for _, c := range []struct {
				what      string
				want, got func(context.Context) (bool, error)
			}{
				{"evidence", e.m.Engine(Assessment), e.p.EvidenceCheck(kyverno.Contract)},
				{"enforcement", e.m.Engine(Delivery), e.p.EnforcementCheck(kyverno.Contract)},
			} {
				wantOK, wantErr := c.want(ctx)
				gotOK, gotErr := c.got(ctx)
				if gotOK != wantOK || ReasonOf(gotErr) != ReasonOf(wantErr) || errorText(gotErr) != errorText(wantErr) {
					t.Fatalf("%s: provider check (%t, %v), capability (%t, %v)", c.what, gotOK, gotErr, wantOK, wantErr)
				}
			}
			if got, want := e.p.Evidence(ctx, kyverno.Contract), e.m.Check(ctx, Assessment); got != want {
				t.Fatalf("evidence %+v, Assessment %+v", got, want)
			}
		})
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// One provider's missing or unsupported API, denied read or unreachable
// dependency is attributed to it alone; the other provider stays usable.
func TestProviderAvailabilityIsIndependent(t *testing.T) {
	const rt = "Assessment(konstapel-reporttest/v1): "
	for name, tc := range map[string]struct {
		setup    func(*providerEnv)
		provider string
		want     Reason
		contains string
	}{
		"reporting API not served": {func(e *providerEnv) { e.disc.Resources = served() }, reporttest.Contract,
			APINotServed, rt + "reporttest.konstapel.io/v1 is not served"},
		"reporting resource missing": {func(e *providerEnv) { e.disc.Resources[2].APIResources = nil }, reporttest.Contract,
			ResourceMissing, rt + "reporttest.konstapel.io/v1 is served without postures"},
		"reporting source namespaced": {func(e *providerEnv) { e.disc.Resources[2].APIResources[0].Namespaced = true }, reporttest.Contract,
			UnsupportedResource, rt + "reporttest.konstapel.io/v1/postures is namespaced, want cluster-scoped"},
		"reporting source another kind": {func(e *providerEnv) { e.disc.Resources[2].APIResources[0].Kind = "Scan" }, reporttest.Contract,
			UnsupportedResource, "has kind Scan, want Posture"},
		"reporting source cannot list": {func(e *providerEnv) { e.disc.Resources[2].APIResources[0].Verbs = []string{"get", "watch"} }, reporttest.Contract,
			UnsupportedResource, "does not support list"},
		"reporting list denied": {func(e *providerEnv) { e.denied["postures/list"] = true }, reporttest.Contract,
			AccessDenied, rt + "the service account may not list (RBAC: denied) postures.reporttest.konstapel.io"},
		"reporting review unreachable": {func(e *providerEnv) {
			review := e.m.Review
			e.m.Review = func(ctx context.Context, a authorizationv1.ResourceAttributes) (bool, string, error) {
				if a.Resource == "postures" {
					return false, "", errors.New("connection refused")
				}
				return review(ctx, a)
			}
		}, reporttest.Contract, Unavailable, rt + "authorization check for get postures failed: connection refused"},
		"Kyverno reports not served": {func(e *providerEnv) {
			e.disc.Resources = slices.Delete(e.disc.Resources, 1, 2)
		}, kyverno.Contract, APINotServed, "Assessment: wgpolicyk8s.io/v1alpha2 is not served"},
		"Kyverno report list denied": {func(e *providerEnv) { e.denied["policyreports/list"] = true }, kyverno.Contract,
			AccessDenied, "Assessment: the service account may not list"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newProviderEnv(t, slices.Concat(served(), []*metav1.APIResourceList{postures()}))
			tc.setup(e)
			ctx := context.Background()
			e.expect(t, tc.provider, e.p.Evidence(ctx, tc.provider), tc.want, tc.contains)
			if ok, err := e.p.EvidenceCheck(tc.provider)(ctx); ok || ReasonOf(err) != tc.want {
				t.Fatalf("%s check: %t %v", tc.provider, ok, err)
			}
			other := kyverno.Contract
			if tc.provider == kyverno.Contract {
				other = reporttest.Contract
			}
			e.expect(t, other, e.p.Evidence(ctx, other), Available, "available")
			// Kyverno enforcement is the delivery capability, which neither
			// provider's evidence source affects.
			e.expect(t, "Kyverno enforcement", e.p.Enforcement(ctx, kyverno.Contract), Available, "PolicyDelivery: available")
		})
	}
}

// A reporting-only provider never enforces: its enforcement is explicitly
// NotApplicable, never Available, whatever the engine's state, and checking
// it reads nothing. Its evidence check asks only about its own source.
func TestReportingOnlyEnforcementIsNotApplicable(t *testing.T) {
	for name, lists := range map[string][]*metav1.APIResourceList{
		"everything served": slices.Concat(served(), []*metav1.APIResourceList{postures()}),
		"no engine":         {served()[1], postures()},
		"nothing served":    nil,
	} {
		t.Run(name, func(t *testing.T) {
			e := newProviderEnv(t, lists)
			ctx := context.Background()
			r := e.p.Enforcement(ctx, reporttest.Contract)
			e.expect(t, "reporting enforcement", r, NotApplicable,
				"Assessment(konstapel-reporttest/v1): enforcement is not applicable: konstapel-reporttest/v1 is reporting-only")
			if r.Available() {
				t.Fatal("reporting-only enforcement is available")
			}
			if ok, err := e.p.EnforcementCheck(reporttest.Contract)(ctx); ok || ReasonOf(err) != NotApplicable {
				t.Fatalf("reporting enforcement check: %t %v", ok, err)
			}
			if asked := e.rec.reset(); len(asked) != 0 || len(e.reviews) != 0 {
				t.Fatalf("reporting enforcement consulted discovery %v or access %v", asked, e.reviews)
			}
			_ = e.p.Evidence(ctx, reporttest.Contract)
			if asked := e.rec.reset(); !slices.Equal(asked, []string{"reporttest.konstapel.io/v1"}) {
				t.Fatalf("reporting evidence asked discovery for %v", asked)
			}
			for _, a := range e.reviews {
				if a.Resource != "postures" || a.Group != "reporttest.konstapel.io" || a.Namespace != "" || (a.Verb != "get" && a.Verb != "list") {
					t.Fatalf("reporting evidence reviewed %+v", a)
				}
			}
		})
	}
}

// Availability recovers without a restart: a result is reused for at most
// the TTL, and the next check sees the dependency's current state.
func TestProviderAvailabilityRecoversWithoutRestart(t *testing.T) {
	now := time.Unix(0, 0)
	e := newProviderEnv(t, served())
	e.m.TTL, e.m.Now = 15*time.Second, func() time.Time { return now }
	ctx := context.Background()
	step := func(what string, want Reason) {
		t.Helper()
		e.expect(t, what, e.p.Evidence(ctx, reporttest.Contract), want, "")
		e.expect(t, what+": Kyverno", e.p.Evidence(ctx, kyverno.Contract), Available, "available")
	}
	step("source absent", APINotServed)
	e.disc.Resources = slices.Concat(served(), []*metav1.APIResourceList{postures()}) // the source is installed
	step("cached for the TTL", APINotServed)
	now = now.Add(16 * time.Second)
	step("installed", Available)
	e.denied["postures/get"] = true // access is revoked
	now = now.Add(16 * time.Second)
	step("access revoked", AccessDenied)
	delete(e.denied, "postures/get")
	now = now.Add(16 * time.Second)
	step("access restored", Available)
	e.disc.Resources = served() // removed again; a NoMatch refreshes at once
	e.m.Refresh()
	step("removed", APINotServed)
}

func TestNewProvidersRejectsInconsistentProviders(t *testing.T) {
	m := &Monitor{}
	drifted := kyverno.Descriptor()
	drifted.Reads[0].Verbs = []string{"get", "list"}
	unrequired := kyverno.Descriptor()
	unrequired.Requires = nil
	delivering := reporttest.Descriptor()
	delivering.Checks[0].Delivery = true
	delivering.Checks[0].Modes = []v1alpha1.EnforcementMode{v1alpha1.ModeAudit, v1alpha1.ModeDeny}
	invalid := reporttest.Descriptor()
	invalid.Reads[0].Verbs = []string{"list", "create"}
	for name, tc := range map[string]struct {
		m     *Monitor
		descs []provider.Descriptor
		want  string
	}{
		"no monitor":                   {nil, []provider.Descriptor{kyverno.Descriptor()}, "no monitor"},
		"given twice":                  {m, []provider.Descriptor{kyverno.Descriptor(), kyverno.Descriptor()}, "given twice"},
		"drifted Kyverno read":         {m, []provider.Descriptor{drifted}, "differ from the Assessment capability"},
		"Kyverno without prerequisite": {m, []provider.Descriptor{unrequired}, "differ from the Assessment capability"},
		"another delivering provider":  {m, []provider.Descriptor{delivering}, "only konstapel-kyverno/v1 has a delivery capability"},
		"invalid descriptor":           {m, []provider.Descriptor{invalid}, "not read-only"},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := NewProviders(tc.m, tc.descs...)
			if err == nil || p != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, %v; want an error mentioning %q", p, err, tc.want)
			}
		})
	}
}

func TestInstalledProviderAvailability(t *testing.T) {
	e := newEnv(served())
	p, err := NewProviders(e.m, installed.Registry().Descriptors()...)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Contracts(); !slices.Equal(got, []string{kyverno.Contract}) || p.Name(kyverno.Contract) != Assessment {
		t.Fatalf("contracts %v, Kyverno capability %q", got, p.Name(kyverno.Contract))
	}
	ctx := context.Background()
	// A provider this build does not install is never available.
	for _, r := range []Result{p.Evidence(ctx, reporttest.Contract), p.Enforcement(ctx, reporttest.Contract)} {
		if r.Reason != Unavailable || !strings.Contains(r.Message, "provider konstapel-reporttest/v1 is not installed") {
			t.Fatalf("uninstalled provider: %+v", r)
		}
	}
	if p.Name(reporttest.Contract) != "" {
		t.Fatal("uninstalled provider has a capability name")
	}
}
