package installed_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/yaml"

	"github.com/backend-bunny/Konstapel/internal/assessment"
	"github.com/backend-bunny/Konstapel/internal/capability"
	"github.com/backend-bunny/Konstapel/internal/provider"
	"github.com/backend-bunny/Konstapel/internal/provider/conformance"
	"github.com/backend-bunny/Konstapel/internal/provider/kyverno"
	"github.com/backend-bunny/Konstapel/internal/provider/reporttest"
)

// The capability/permission matrix and collection limits of
// docs/assessment-providers.md (add-assessment-provider-contract 2.4),
// computed from the descriptors, the capability requirements, the recorded
// collection requests and the shipped controller ClusterRole.

// collectionPages are the pages the Kyverno adapter reads, under the
// default limits, for a scope of namespaces a (1,001 reports) and b (one).
func collectionPages(t *testing.T) []conformance.Page {
	t.Helper()
	gvk := schema.GroupVersionKind{Group: "wgpolicyk8s.io", Version: "v1alpha2", Kind: "PolicyReport"}
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(gvk, meta.RESTScopeNamespace)
	var objs []client.Object
	for i := range 1_001 {
		objs = append(objs, unstructuredObject(gvk, "a", fmt.Sprintf("r-%04d", i)))
	}
	objs = append(objs, unstructuredObject(gvk, "b", "r"))
	pager := conformance.NewPagingClient(fake.NewClientBuilder().WithRESTMapper(mapper).WithObjects(objs...).Build())
	rec := conformance.NewRecordingClient(pager)
	scope := provider.Scope{Cluster: "c", Namespaces: []provider.Namespace{{Name: "a", UID: "uid-a"}, {Name: "b", UID: "uid-b"}}}
	reports, limits, err := provider.Collect(context.Background(), rec, kyverno.Descriptor(), scope, provider.DefaultLimits(),
		func(ctx context.Context, src provider.Sources) ([]assessment.Object, []string, error) {
			return kyverno.Collect(ctx, scope, src)
		})
	if err != nil || len(reports) != 1_002 || len(limits) != 0 || len(rec.Writes()) != 0 {
		t.Fatalf("paged collection: %d reports, %v, %v", len(reports), limits, err)
	}
	return pager.Pages()
}

func unstructuredObject(gvk schema.GroupVersionKind, ns, name string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gvk)
	u.SetNamespace(ns)
	u.SetName(name)
	return u
}

// reportingRequests are the API requests the test-only reporting adapter
// makes for subjects in two namespaces: one cluster-scoped list.
func reportingRequests(t *testing.T) []conformance.Call {
	t.Helper()
	gvk := schema.GroupVersionKind{Group: reporttest.Postures().Group, Version: reporttest.Postures().Version, Kind: reporttest.Postures().Kind}
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(gvk, meta.RESTScopeRoot)
	rec := conformance.NewRecordingClient(fake.NewClientBuilder().WithRESTMapper(mapper).WithObjects(unstructuredObject(gvk, "", "p")).Build())
	scope := provider.Scope{Cluster: "c", Namespaces: []provider.Namespace{{Name: "a", UID: "uid-a"}, {Name: "b", UID: "uid-b"}}}
	subjects := []reporttest.Subject{
		{NamespaceUID: "uid-a", WorkloadUID: "w-a", Container: "c", Image: "registry.example/app@sha256:" + strings.Repeat("a", 64)},
		{NamespaceUID: "uid-b", WorkloadUID: "w-b", Container: "c", Image: "registry.example/app@sha256:" + strings.Repeat("b", 64)},
	}
	_, _, err := provider.Collect(context.Background(), rec, reporttest.Descriptor(), scope, provider.DefaultLimits(),
		func(ctx context.Context, src provider.Sources) ([]reporttest.Report, []string, error) {
			return reporttest.Collect(ctx, scope, subjects, src)
		})
	if err != nil || len(rec.Writes()) != 0 {
		t.Fatalf("reporting collection: %v, writes %v", err, rec.Writes())
	}
	return rec.Calls()
}

// documentedLimits are provider.DefaultLimits as the guide shows them.
func documentedLimits() map[string]any {
	l := provider.DefaultLimits()
	return map[string]any{"timeout": l.Timeout.String(), "pageSize": l.PageSize, "maxPages": l.MaxPages, "maxObjects": l.MaxObjects, "maxBytes": l.MaxBytes}
}

type matrixRead struct {
	Resource string   `json:"resource"`
	Scope    string   `json:"scope"`
	Verbs    []string `json:"verbs"`
}

type matrixResource struct {
	Resource string   `json:"resource"`
	Verbs    []string `json:"verbs"`
}

type matrixRow struct {
	Provider    string `json:"provider"`
	Evidence    string `json:"evidenceCapability"`
	Enforcement string `json:"enforcement"`
	// Collection is what the adapter's narrow readers requested, as the
	// recording fixture saw it.
	Collection []matrixRead `json:"collection"`
	// Watches are the host's cluster-wide watches for the provider.
	Watches []string `json:"hostWatches"`
	// Discovery and AccessReview are the availability checks.
	Discovery    []matrixResource `json:"discovery"`
	AccessReview []matrixResource `json:"accessReview"`
	// Role is what the shipped controller ClusterRole grants on the
	// provider's resources, for every namespace.
	Role []matrixResource `json:"controllerRole"`
}

// controllerRole is the shipped konstapel-controller ClusterRole.
func controllerRole(t *testing.T) rbacv1.ClusterRole {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "config/rbac/controller/role.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range strings.Split(string(raw), "\n---") {
		var r rbacv1.ClusterRole
		if err := yaml.Unmarshal([]byte(doc), &r); err != nil {
			t.Fatal(err)
		}
		if r.Kind == "ClusterRole" && r.Name == "konstapel-controller" {
			return r
		}
	}
	t.Fatal("no konstapel-controller ClusterRole")
	return rbacv1.ClusterRole{}
}

// granted are the verbs the role grants on a resource, sorted.
func granted(role rbacv1.ClusterRole, group, resource string) []string {
	verbs := []string{}
	for _, rule := range role.Rules {
		if (slices.Contains(rule.APIGroups, group) || slices.Contains(rule.APIGroups, "*")) &&
			(slices.Contains(rule.Resources, resource) || slices.Contains(rule.Resources, "*")) {
			for _, v := range rule.Verbs {
				if !slices.Contains(verbs, v) {
					verbs = append(verbs, v)
				}
			}
		}
	}
	slices.Sort(verbs)
	return verbs
}

func resourceID(r capability.Resource) string { return r.Resource + "." + r.Group + "/" + r.Version }

// capabilityMatrix is one row per provider: the Kyverno provider and the
// test-only reporting provider.
func capabilityMatrix(t *testing.T) []matrixRow {
	t.Helper()
	providers, err := capability.NewProviders(&capability.Monitor{}, kyverno.Descriptor(), reporttest.Descriptor())
	if err != nil {
		t.Fatal(err)
	}
	role := controllerRole(t)
	requests := map[string][]conformance.Call{kyverno.Contract: collectionRequests(t), reporttest.Contract: reportingRequests(t)}
	var rows []matrixRow
	for _, d := range []provider.Descriptor{kyverno.Descriptor(), reporttest.Descriptor()} {
		c := d.Contract()
		row := matrixRow{Provider: c, Evidence: string(providers.Name(c)), Enforcement: string(capability.Delivery),
			Collection: []matrixRead{}, Watches: []string{}, Discovery: []matrixResource{}, AccessReview: []matrixResource{}, Role: []matrixResource{}}
		// Kyverno's enforcement is the delivery owner's capability; any
		// other provider's is answered without a check.
		if c != kyverno.Contract {
			res := providers.Enforcement(context.Background(), c)
			if res.Reason != capability.NotApplicable {
				t.Fatalf("%s enforcement %+v", c, res)
			}
			row.Enforcement = string(res.Reason)
		}
		for _, r := range d.Reads {
			read := matrixRead{Resource: r.ID(), Scope: "cluster", Verbs: []string{}}
			for _, call := range requests[c] {
				if call.Kind != r.Kind+"List" {
					t.Fatalf("%s requested %+v outside its reads", c, call)
				}
				if call.Namespace != "" {
					read.Scope = "namespaced"
				}
				if !slices.Contains(read.Verbs, call.Verb) {
					read.Verbs = append(read.Verbs, call.Verb)
				}
			}
			row.Collection = append(row.Collection, read)
			if slices.Contains(r.Verbs, "watch") {
				row.Watches = append(row.Watches, r.ID())
			}
		}
		for _, r := range capability.ForProvider(d) {
			row.Discovery = append(row.Discovery, matrixResource{Resource: resourceID(r), Verbs: r.Verbs})
			if len(r.Access) > 0 {
				row.AccessReview = append(row.AccessReview, matrixResource{Resource: resourceID(r), Verbs: r.Access})
			}
			row.Role = append(row.Role, matrixResource{Resource: r.Resource + "." + r.Group, Verbs: granted(role, r.Group, r.Resource)})
		}
		rows = append(rows, row)
	}
	return rows
}

// controllerRoleWrites are the ClusterRole's write grants: none is a
// provider read, and every feature's service account shares them.
func controllerRoleWrites(t *testing.T) []matrixResource {
	t.Helper()
	var out []matrixResource
	for _, rule := range controllerRole(t).Rules {
		var writes []string
		for _, v := range rule.Verbs {
			if !slices.Contains([]string{"get", "list", "watch"}, v) {
				writes = append(writes, v)
			}
		}
		if len(writes) == 0 {
			continue
		}
		for _, g := range rule.APIGroups {
			for _, r := range rule.Resources {
				// resource.group/subresource, as kubectl names them
				base, sub, _ := strings.Cut(r, "/")
				name := base
				if g != "" {
					name += "." + g
				}
				if sub != "" {
					name += "/" + sub
				}
				out = append(out, matrixResource{Resource: name, Verbs: writes})
			}
		}
	}
	slices.SortFunc(out, func(a, b matrixResource) int { return strings.Compare(a.Resource, b.Resource) })
	return out
}

// The narrow readers are narrower than the controller's effective RBAC,
// and that RBAC is what makes the production provider available: the
// shipped ClusterRole grants every Kyverno read and access-reviewed verb
// in every namespace, nothing on the test-only provider's source, and
// writes no provider reader can reach.
func TestReadersAreNarrowerThanTheControllerRole(t *testing.T) {
	role := controllerRole(t)
	for _, r := range capability.ForProvider(kyverno.Descriptor()) {
		g := granted(role, r.Group, r.Resource)
		for _, v := range r.Access {
			if !slices.Contains(g, v) {
				t.Errorf("the controller role does not grant %s on %s, which the Assessment capability reviews", v, resourceID(r))
			}
		}
	}
	for _, r := range reporttest.Descriptor().Reads {
		if g := granted(role, r.Group, r.Resource); len(g) != 0 {
			t.Errorf("the shipped controller role grants %v on the test-only source %s", g, r.ID())
		}
	}
	for _, row := range capabilityMatrix(t) {
		for _, c := range row.Collection {
			if !slices.Equal(c.Verbs, []string{"list"}) {
				t.Errorf("%s collection requested %v", row.Provider, c.Verbs)
			}
		}
	}
	if len(controllerRoleWrites(t)) == 0 {
		t.Fatal("the controller role has no writes; the comparison is not working")
	}
}
