package controller

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	clienttesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/backend-bunny/Konstapel/api/v1alpha1"
	"github.com/backend-bunny/Konstapel/internal/capability"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/installed"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

// Provider availability and evidence watches (add-assessment-provider-
// contract 2.2), with the Kyverno provider and the test-only reporting
// provider checked through one capability monitor over fake discovery.

var allVerbs = []string{"get", "list", "watch", "create", "update", "patch", "delete"}

func engineAPI() *metav1.APIResourceList {
	return &metav1.APIResourceList{GroupVersion: "policies.kyverno.io/v1", APIResources: []metav1.APIResource{
		{Name: "validatingpolicies", Kind: "ValidatingPolicy", Verbs: allVerbs}}}
}

func reportsAPI() *metav1.APIResourceList {
	return &metav1.APIResourceList{GroupVersion: "wgpolicyk8s.io/v1alpha2", APIResources: []metav1.APIResource{
		{Name: "policyreports", Kind: "PolicyReport", Namespaced: true, Verbs: allVerbs},
		{Name: "clusterpolicyreports", Kind: "ClusterPolicyReport", Verbs: allVerbs}}}
}

func posturesAPI() *metav1.APIResourceList {
	return &metav1.APIResourceList{GroupVersion: "reporttest.konstapel.io/v1", APIResources: []metav1.APIResource{
		{Name: "postures", Kind: "Posture", Verbs: allVerbs}}}
}

// clusterAPIs is discovery and access review over APIs that tests install,
// remove, allow and deny while checks run.
type clusterAPIs struct {
	*fakediscovery.FakeDiscovery
	mu     sync.Mutex
	served map[string]*metav1.APIResourceList
	denied map[string]bool // "resource/verb"
}

func newClusterAPIs(lists ...*metav1.APIResourceList) *clusterAPIs {
	a := &clusterAPIs{FakeDiscovery: &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{}}, served: map[string]*metav1.APIResourceList{}, denied: map[string]bool{}}
	a.serve(lists...)
	return a
}

func (a *clusterAPIs) ServerResourcesForGroupVersionWithContext(_ context.Context, gv string) (*metav1.APIResourceList, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if l, ok := a.served[gv]; ok {
		return l.DeepCopy(), nil
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{}, gv)
}

func (a *clusterAPIs) serve(lists ...*metav1.APIResourceList) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, l := range lists {
		a.served[l.GroupVersion] = l
	}
}

func (a *clusterAPIs) remove(gv string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.served, gv)
}

func (a *clusterAPIs) deny(resourceVerb string, denied bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.denied[resourceVerb] = denied
}

func (a *clusterAPIs) review(_ context.Context, attrs authorizationv1.ResourceAttributes) (bool, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.denied[attrs.Resource+"/"+attrs.Verb], "RBAC: denied", nil
}

// providersOver checks descriptors through a monitor over apis whose
// results are never reused, so each check sees the current state.
func providersOver(t *testing.T, apis *clusterAPIs, descriptors ...provider.Descriptor) *capability.Providers {
	t.Helper()
	p, err := capability.NewProviders(&capability.Monitor{Discovery: apis, Review: apis.review, TTL: time.Nanosecond}, descriptors...)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// watchingReporttest is the test-only reporting provider with its source
// declared watchable, so the host gives it an evidence watch. The
// unmodified provider declares no watch and gets none.
func watchingReporttest() provider.Descriptor {
	d := reporttest.Descriptor()
	d.Reads[0].Verbs = append(d.Reads[0].Verbs, "watch")
	return d
}

// The installed providers' watches are exactly the report watch the
// assessment controller registered before 2.2: one PolicyReport watch with
// its historic name, gated on the Kyverno provider's evidence (the
// Assessment capability).
func TestProviderWatchesKeepTheKyvernoReportWatch(t *testing.T) {
	before := schema.GroupVersionKind{Group: "wgpolicyk8s.io", Version: "v1alpha2", Kind: "PolicyReport"}
	if PolicyReportGVK != before {
		t.Fatalf("PolicyReportGVK %v, want %v", PolicyReportGVK, before)
	}
	var gated []string
	ws := providerWatches(installed.Registry().Descriptors(), func(c string) EngineAvailable {
		gated = append(gated, c)
		return func(context.Context) (bool, error) { return true, nil }
	})
	if len(ws) != 1 || ws[0].name != "assessment-policy-reports" || ws[0].gvk != before || !slices.Equal(gated, []string{kyverno.Contract}) {
		t.Fatalf("watches %+v gated on %v", ws, gated)
	}
	if ws := providerWatches([]provider.Descriptor{reporttest.Descriptor()}, nil); len(ws) != 0 {
		t.Fatalf("a provider without a watch verb got watches %+v", ws)
	}
	ws = providerWatches([]provider.Descriptor{watchingReporttest()}, func(string) EngineAvailable { return nil })
	if len(ws) != 1 || ws[0].name != "assessment-konstapel-reporttest-postures" ||
		ws[0].gvk != (schema.GroupVersionKind{Group: "reporttest.konstapel.io", Version: "v1", Kind: "Posture"}) {
		t.Fatalf("watchable reporting source: %+v", ws)
	}
}

// Each provider's evidence watch starts once its own prerequisites are met,
// never because another provider's are, and a provider that becomes
// available later gets its watch without a restart, exactly once.
func TestProviderWatchesStartIndependentlyAndRecover(t *testing.T) {
	for name, tc := range map[string]struct {
		missing  func(*clusterAPIs)
		restore  func(*clusterAPIs)
		healthy  string
		recovers string
	}{
		"reporting source not served": {func(a *clusterAPIs) { a.remove("reporttest.konstapel.io/v1") }, func(a *clusterAPIs) { a.serve(posturesAPI()) },
			"assessment-policy-reports", "assessment-konstapel-reporttest-postures"},
		"reporting source watch denied": {func(a *clusterAPIs) { a.deny("postures/watch", true) }, func(a *clusterAPIs) { a.deny("postures/watch", false) },
			"assessment-policy-reports", "assessment-konstapel-reporttest-postures"},
		"Kyverno reports not served": {func(a *clusterAPIs) { a.remove("wgpolicyk8s.io/v1alpha2") }, func(a *clusterAPIs) { a.serve(reportsAPI()) },
			"assessment-konstapel-reporttest-postures", "assessment-policy-reports"},
		"Kyverno report list denied": {func(a *clusterAPIs) { a.deny("policyreports/list", true) }, func(a *clusterAPIs) { a.deny("policyreports/list", false) },
			"assessment-konstapel-reporttest-postures", "assessment-policy-reports"},
	} {
		t.Run(name, func(t *testing.T) {
			apis := newClusterAPIs(engineAPI(), reportsAPI(), posturesAPI())
			tc.missing(apis)
			descriptors := []provider.Descriptor{kyverno.Descriptor(), watchingReporttest()}
			p := providersOver(t, apis, descriptors...)
			var mu sync.Mutex
			registered := map[string]int{}
			ctx, cancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			defer func() { cancel(); wg.Wait() }()
			for _, w := range providerWatches(descriptors, func(c string) EngineAvailable { return p.EvidenceCheck(c) }) {
				dw := &deferredWatch{name: w.name, available: w.available, poll: 5 * time.Millisecond, register: func() error {
					mu.Lock()
					defer mu.Unlock()
					registered[w.name]++
					return nil
				}}
				wg.Add(1)
				go func() { defer wg.Done(); _ = dw.Start(ctx) }()
			}
			count := func(name string) int {
				mu.Lock()
				defer mu.Unlock()
				return registered[name]
			}
			waitFor := func(what string, ok func() bool) {
				t.Helper()
				deadline := time.Now().Add(5 * time.Second)
				for !ok() {
					if time.Now().After(deadline) {
						t.Fatalf("%s: registered %v", what, registered)
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
			waitFor("healthy provider's watch", func() bool { return count(tc.healthy) == 1 })
			time.Sleep(50 * time.Millisecond) // several polls
			if n := count(tc.recovers); n != 0 {
				t.Fatalf("unavailable provider's watch registered %d times", n)
			}
			tc.restore(apis)
			waitFor("recovered provider's watch", func() bool { return count(tc.recovers) == 1 })
			time.Sleep(50 * time.Millisecond)
			if count(tc.healthy) != 1 || count(tc.recovers) != 1 {
				t.Fatalf("watches registered more than once: %v", registered)
			}
		})
	}
}

// The capability trigger follows every installed provider's evidence on
// its own: a reporting source's change re-reconciles bindings (its only
// recovery path without a watch), and nothing else changes.
func TestCapabilityTriggerFollowsEachProvider(t *testing.T) {
	apis := newClusterAPIs(engineAPI(), reportsAPI())
	p := providersOver(t, apis, kyverno.Descriptor(), reporttest.Descriptor())
	checks := []EngineAvailable{p.EnforcementCheck(kyverno.Contract)}
	for _, c := range p.Contracts() {
		checks = append(checks, p.EvidenceCheck(c))
	}
	c := fake.NewClientBuilder().WithScheme(Scheme()).WithObjects(bindingObj("a", "baseline", v1alpha1.ModeAudit, nil)).Build()
	out := make(chan event.GenericEvent, 16)
	trig := &capabilityTrigger{name: "test", client: c, checks: checks, out: []chan<- event.GenericEvent{out}, poll: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = trig.Start(ctx) }()
	drain := func(want int, within time.Duration) {
		t.Helper()
		got := 0
		deadline := time.After(within)
		for {
			select {
			case <-out:
				got++
			case <-deadline:
				if got != want {
					t.Fatalf("got %d binding events, want %d", got, want)
				}
				return
			}
		}
	}
	drain(1, 300*time.Millisecond) // initial state: reporting source absent
	drain(0, 100*time.Millisecond)
	apis.serve(posturesAPI())
	drain(1, 300*time.Millisecond)
	apis.deny("postures/list", true)
	drain(1, 300*time.Millisecond)
	if ok, err := p.EvidenceCheck(kyverno.Contract)(ctx); !ok {
		t.Fatalf("Kyverno evidence affected: %v", err)
	}
}

// An unavailable or denied provider does not degrade a healthy one: the
// Kyverno assessment, with its availability checked per provider, keeps
// delivering and assessing while the reporting source is absent or denied.
// When the Kyverno reports go away, the reporting provider stays available
// and the Kyverno assessment reports the existing limitation; it recovers
// without a restart.
func TestUnavailableProviderDoesNotDegradeKyverno(t *testing.T) {
	apis := newClusterAPIs(engineAPI(), reportsAPI())
	p := providersOver(t, apis, kyverno.Descriptor(), reporttest.Descriptor())
	e := newAssessEnv(t, nsObj("prod", "environment", "production"), profileObj(t, "baseline", pol), epochBinding("audit-prod", production),
		privilegedPod("prod", "web", "pod-1"))
	e.tr.Engine = p.EnforcementCheck(kyverno.Contract)
	e.ar.Engine = p.EnforcementCheck(kyverno.Contract)
	e.ar.Reports = p.EvidenceCheck(kyverno.Contract)
	ctx := context.Background()
	e.deliver("audit-prod")
	policy := e.enginePolicy()
	e.assess("audit-prod")
	e.report("prod", "pod-1", policy, "pass", a0.Add(time.Minute))
	e.now = a0.Add(2 * time.Minute)

	complete := func(state string) {
		t.Helper()
		e.assess("audit-prod")
		cur := e.current("audit-prod")
		if cur.Evidence.Completeness != "Complete" || cur.Outcomes.Pass != 1 || slices.ContainsFunc(cur.Limitations, func(l string) bool {
			return strings.Contains(l, "unavailable") || strings.Contains(l, "reporttest")
		}) {
			t.Fatalf("%s: Kyverno assessment %+v %+v %v", state, cur.Evidence, cur.Outcomes, cur.Limitations)
		}
	}
	if r := p.Evidence(ctx, reporttest.Contract); r.Reason != capability.APINotServed {
		t.Fatalf("reporting source absent: %+v", r)
	}
	complete("reporting source absent")
	apis.serve(posturesAPI())
	apis.deny("postures/get", true)
	if r := p.Evidence(ctx, reporttest.Contract); r.Reason != capability.AccessDenied {
		t.Fatalf("reporting source denied: %+v", r)
	}
	complete("reporting source denied")

	apis.deny("postures/get", false)
	apis.remove("wgpolicyk8s.io/v1alpha2")
	if r := p.Evidence(ctx, reporttest.Contract); !r.Available() {
		t.Fatalf("reporting provider degraded by Kyverno's reports: %+v", r)
	}
	e.assess("audit-prod")
	cur := e.current("audit-prod")
	if cur.Evidence.Completeness == "Complete" || cur.Outcomes.Pass != 0 ||
		!slices.Contains(cur.Limitations, "policy reports unavailable: Assessment: wgpolicyk8s.io/v1alpha2 is not served") {
		t.Fatalf("Kyverno reports absent: %+v %+v %v", cur.Evidence, cur.Outcomes, cur.Limitations)
	}
	// Delivery is independent of either provider's evidence source.
	e.deliver("audit-prod")
	if c := meta.FindStatusCondition(e.bindingNamed("audit-prod").Status.Conditions, v1alpha1.ConditionEngineReady); c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("delivery affected by evidence availability: %+v", c)
	}
	if got := e.enginePolicy(); got != policy {
		t.Fatalf("applied policy changed: %s, want %s", got, policy)
	}

	apis.serve(reportsAPI())
	complete("Kyverno reports restored")
}
