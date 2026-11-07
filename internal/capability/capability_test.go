package capability

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakediscovery "k8s.io/client-go/discovery/fake"
	clienttesting "k8s.io/client-go/testing"
)

var all = []string{"get", "list", "watch", "create", "update", "patch", "delete"}

func served() []*metav1.APIResourceList {
	return []*metav1.APIResourceList{
		{GroupVersion: "policies.kyverno.io/v1", APIResources: []metav1.APIResource{
			{Name: "validatingpolicies", Kind: "ValidatingPolicy", Verbs: all},
			{Name: "policyexceptions", Kind: "PolicyException", Namespaced: true, Verbs: all},
		}},
		{GroupVersion: "wgpolicyk8s.io/v1alpha2", APIResources: []metav1.APIResource{
			{Name: "policyreports", Kind: "PolicyReport", Namespaced: true, Verbs: all},
			{Name: "clusterpolicyreports", Kind: "ClusterPolicyReport", Verbs: all},
		}},
	}
}

type env struct {
	disc    *fakediscovery.FakeDiscovery
	denied  map[string]bool // "resource/verb"
	reviews []authorizationv1.ResourceAttributes
	m       *Monitor
}

func newEnv(lists []*metav1.APIResourceList) *env {
	e := &env{disc: &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{Resources: lists}}, denied: map[string]bool{}}
	e.m = &Monitor{Discovery: e.disc, TTL: time.Nanosecond, Review: func(_ context.Context, a authorizationv1.ResourceAttributes) (bool, string, error) {
		e.reviews = append(e.reviews, a)
		if a.Resource == "boom" {
			return false, "", errors.New("connection refused")
		}
		return !e.denied[a.Resource+"/"+a.Verb], "RBAC: denied", nil
	}}
	return e
}

func (e *env) check(t *testing.T, n Name, want Reason, contains string) {
	t.Helper()
	r := e.m.Check(context.Background(), n)
	if r.Reason != want || !strings.Contains(r.Message, contains) {
		t.Fatalf("%s: got %s %q, want %s containing %q", n, r.Reason, r.Message, want, contains)
	}
}

func TestAllCapabilitiesAvailable(t *testing.T) {
	e := newEnv(served())
	for _, n := range []Name{Delivery, Assessment, Exceptions} {
		e.check(t, n, Available, "available")
	}
	// Access is reviewed only for operations the implementation performs:
	// validatingpolicies (7 verbs) and policyreports (3), never cluster
	// reports or exceptions.
	for _, a := range e.reviews {
		if a.Resource != "validatingpolicies" && a.Resource != "policyreports" {
			t.Fatalf("unexpected access review %+v", a)
		}
	}
	if len(e.reviews) != 10 {
		t.Fatalf("reviews %d", len(e.reviews))
	}
}

func TestDistinctIncompatibilities(t *testing.T) {
	without := func(resource string) []*metav1.APIResourceList {
		lists := served()
		for _, l := range lists {
			kept := l.APIResources[:0]
			for _, r := range l.APIResources {
				if r.Name != resource {
					kept = append(kept, r)
				}
			}
			l.APIResources = kept
		}
		return lists
	}
	// The group/version is not served at all.
	e := newEnv(served()[1:])
	e.check(t, Delivery, APINotServed, "policies.kyverno.io/v1 is not served")
	e.check(t, Exceptions, APINotServed, "not served")
	e.check(t, Assessment, Available, "available") // independent capability
	// Served without the resource.
	newEnv(without("policyexceptions")).check(t, Exceptions, ResourceMissing, "without policyexceptions")
	newEnv(without("clusterpolicyreports")).check(t, Assessment, ResourceMissing, "clusterpolicyreports")
	// Wrong scope, kind, or verbs.
	lists := served()
	lists[1].APIResources[0].Namespaced = false
	newEnv(lists).check(t, Assessment, UnsupportedResource, "policyreports is cluster-scoped, want namespaced")
	lists = served()
	lists[0].APIResources[0].Kind = "ClusterPolicy"
	newEnv(lists).check(t, Delivery, UnsupportedResource, "kind ClusterPolicy")
	lists = served()
	lists[0].APIResources[0].Verbs = []string{"get", "list"}
	newEnv(lists).check(t, Delivery, UnsupportedResource, "does not support watch, create")
}

func TestDeniedAccessIsNotMissingAPI(t *testing.T) {
	e := newEnv(served())
	e.denied["policyreports/watch"] = true
	e.check(t, Assessment, AccessDenied, "may not watch (RBAC: denied) policyreports.wgpolicyk8s.io")
	e.check(t, Delivery, Available, "available")
	// Forbidden discovery is denied access, not an absent API.
	f := newEnv(served())
	f.disc.PrependReactor("get", "resource", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{}, "", errors.New("discovery denied"))
	})
	f.check(t, Delivery, AccessDenied, "discovery of policies.kyverno.io/v1 is forbidden")
}

func TestTransportFailuresAreUnavailable(t *testing.T) {
	e := newEnv(served())
	e.disc.PrependReactor("get", "resource", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("dial tcp: connection refused")
	})
	e.check(t, Delivery, Unavailable, "connection refused")
	r := newEnv(served())
	r.m.Review = func(context.Context, authorizationv1.ResourceAttributes) (bool, string, error) {
		return false, "", errors.New("timeout")
	}
	r.check(t, Delivery, Unavailable, "authorization check")
}

// Results are cached for TTL and recover as soon as the dependency returns.
func TestCacheAndRecovery(t *testing.T) {
	now := time.Unix(0, 0)
	e := newEnv(served()[1:])
	e.m.TTL, e.m.Now = 15*time.Second, func() time.Time { return now }
	e.check(t, Delivery, APINotServed, "not served")
	e.disc.Resources = served() // the engine is installed
	e.check(t, Delivery, APINotServed, "not served")
	now = now.Add(16 * time.Second)
	e.check(t, Delivery, Available, "available")
	e.disc.Resources = served()[1:] // and removed again
	e.m.Refresh()
	ok, err := e.m.Engine(Delivery)(context.Background())
	if ok || ReasonOf(err) != APINotServed {
		t.Fatalf("engine adapter: %v %v", ok, err)
	}
}
