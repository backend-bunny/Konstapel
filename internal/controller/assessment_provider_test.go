package controller

import (
	"context"
	"slices"
	"testing"

	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/targeting"
)

// The report watch and the collector use the same, declared read.
func TestReportWatchMatchesTheDeclaredRead(t *testing.T) {
	r := kyverno.Reports()
	if PolicyReportGVK.Group != r.Group || PolicyReportGVK.Version != r.Version || PolicyReportGVK.Kind != r.Kind || !r.Namespaced {
		t.Fatalf("watch %v, collector read %+v", PolicyReportGVK, r)
	}
}

// The host derives the collection scope from the subjects alone: their
// namespace instances in name order and the resources they match.
func TestCollectionScopeIsTheSubjects(t *testing.T) {
	scope, resources := collectionScope("kube-system:c", []targeting.EvidenceSubject{
		{Namespace: "b", NamespaceUID: "uid-b", Resources: []string{"/v1/pods", "apps/v1/deployments"}},
		{Namespace: "a", NamespaceUID: "uid-a", Resources: []string{"/v1/pods"}},
		{Namespace: "b", NamespaceUID: "uid-b", Resources: []string{"/v1/services"}},
	})
	want := []provider.Namespace{{Name: "a", UID: "uid-a"}, {Name: "b", UID: "uid-b"}}
	if scope.Cluster != "kube-system:c" || !slices.Equal(scope.Namespaces, want) ||
		!slices.Equal(resources, []string{"/v1/pods", "/v1/services", "apps/v1/deployments"}) {
		t.Fatalf("scope %+v resources %v", scope, resources)
	}
	if empty, res := collectionScope("c", nil); len(empty.Namespaces) != 0 || len(res) != 0 {
		t.Fatalf("zero targets: %+v %v", empty, res)
	}
}

// Workload listing is host-owned: each collected resource is listed in
// each scope namespace only; a resource the controller does not collect is
// a limitation and is not listed, and ephemeral containers are assessed on
// their pod.
func TestUnsupportedSubjectResourcesAreLimitations(t *testing.T) {
	e := newAssessEnv(t, nsObj("a"), nsObj("b"), nsObj("other"), privilegedPod("a", "web", "pod-a"), privilegedPod("other", "web", "pod-o"))
	rec := recordCalls(e)
	scope := provider.Scope{Cluster: "c", Namespaces: []provider.Namespace{{Name: "a", UID: "uid-a"}, {Name: "b", UID: "uid-b"}}}
	listed, limits, err := e.ar.listWorkloads(context.Background(), scope, []string{"/v1/pods", "/v1/pods/ephemeralcontainers", "/v1/services"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(limits, []string{"resource /v1/services is not collected"}) {
		t.Fatalf("limitations %v", limits)
	}
	if !slices.Equal(rec.lists, []string{"PodList a", "PodList b"}) || len(rec.writes) != 0 {
		t.Fatalf("lists %v writes %v", rec.lists, rec.writes)
	}
	if len(listed) != 1 || listed[0].Resource != "/v1/pods" || listed[0].NamespaceUID != "uid-a" {
		t.Fatalf("listed %+v", listed)
	}
}
