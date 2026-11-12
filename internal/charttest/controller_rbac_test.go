package charttest

import (
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

const controllerNS = "konstapel-system"

// grant is one (namespace, resource, verb, name) the controller
// ServiceAccount is allowed; namespace "" is cluster-wide and name "" any
// object.
type grant struct{ ns, resource, verb, name string }

func (g grant) String() string {
	ns, name := g.ns, g.name
	if ns == "" {
		ns = "<cluster>"
	}
	if name == "" {
		name = "<any>"
	}
	return fmt.Sprintf("%s %s %s %s", ns, g.resource, g.verb, name)
}

// controllerGrants is the union of every rule bound to the controller
// ServiceAccount by any RoleBinding or ClusterRoleBinding in the render,
// expanded per resource, verb and name. It fails the test on wildcards.
func controllerGrants(t *testing.T, docs []map[string]any) []grant {
	t.Helper()
	var out []grant
	for _, b := range docs {
		if b["kind"] != "RoleBinding" && b["kind"] != "ClusterRoleBinding" {
			continue
		}
		bound := false
		for _, s := range at(b, "subjects").([]any) {
			s := s.(map[string]any)
			if s["kind"] == "ServiceAccount" && s["name"] == "konstapel-controller" && s["namespace"] == controllerNS {
				bound = true
			}
		}
		if !bound {
			continue
		}
		ns := ""
		if b["kind"] == "RoleBinding" {
			ns, _ = metadata(b)["namespace"].(string)
		}
		roleKind, roleName := at(b, "roleRef", "kind").(string), at(b, "roleRef", "name").(string)
		role := find(docs, roleKind, roleName)
		if role == nil {
			t.Fatalf("%s %s binds missing %s %s", b["kind"], metadata(b)["name"], roleKind, roleName)
		}
		if roleKind == "Role" && metadata(role)["namespace"] != ns {
			t.Fatalf("Role %s is in %v, bound in %s", roleName, metadata(role)["namespace"], ns)
		}
		for _, r := range role["rules"].([]any) {
			r := r.(map[string]any)
			if strings.Contains(fmt.Sprint(r), "*") {
				t.Fatalf("%s %s has a wildcard rule: %v", roleKind, roleName, r)
			}
			if r["nonResourceURLs"] != nil {
				t.Fatalf("%s %s grants non-resource URLs: %v", roleKind, roleName, r)
			}
			groups, _ := r["apiGroups"].([]any)
			names, _ := r["resourceNames"].([]any)
			if len(names) == 0 {
				names = []any{""}
			}
			for _, g := range groups {
				for _, res := range r["resources"].([]any) {
					resource := res.(string)
					if g != "" {
						resource = g.(string) + "/" + resource
					}
					for _, v := range r["verbs"].([]any) {
						for _, n := range names {
							out = append(out, grant{ns, resource, v.(string), n.(string)})
						}
					}
				}
			}
		}
	}
	return out
}

// allowed reports whether the grants authorize verb on resource in ns, for
// the named object ("" for a request without a name, such as an unselected
// list, a watch, or a create).
func allowed(gs []grant, ns, resource, verb, name string) bool {
	return slices.ContainsFunc(gs, func(g grant) bool {
		return (g.ns == "" || g.ns == ns) && g.resource == resource && g.verb == verb && (g.name == "" || g.name == name)
	})
}

// secretConfigMapGrants are the grants on core Secrets and ConfigMaps,
// sorted and de-duplicated.
func secretConfigMapGrants(gs []grant) []string {
	var out []string
	for _, g := range gs {
		if g.resource == "secrets" || g.resource == "configmaps" {
			out = append(out, g.String())
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// The effective Secret and ConfigMap access of the controller ServiceAccount
// is exactly what implemented features need (docs/charts.md, "Controller
// ServiceAccount boundary"): unrestricted get of Secrets and ConfigMaps and
// create of ConfigMaps in the controller namespace, because their names come
// from CR specs or are derived at runtime, plus the bundle Role's named
// grants. Nothing lists or watches Secrets, nothing lists or watches
// ConfigMaps other than the named bundle sources ConfigMap, nothing updates,
// patches or deletes either kind, and no ClusterRole grants either kind.
func TestRuntimeChartControllerSecretConfigMapAccess(t *testing.T) {
	base := []string{
		"konstapel-system configmaps create <any>",
		"konstapel-system configmaps get <any>",
		"konstapel-system secrets get <any>",
	}
	for name, c := range map[string]struct {
		set  []string
		want []string
	}{
		"bundles off": {nil, base},
		"bundles on": {
			[]string{"bundles.sourcesConfigMap=" + sourcesCM, "bundles.referencedConfigMaps={registry-ca}", "bundles.referencedSecrets={registry-cred,org-key}"},
			append(slices.Clone(base),
				"konstapel-system configmaps get konstapel-bundle-sources",
				"konstapel-system configmaps get registry-ca",
				"konstapel-system configmaps list konstapel-bundle-sources",
				"konstapel-system configmaps watch konstapel-bundle-sources",
				"konstapel-system secrets get org-key",
				"konstapel-system secrets get registry-cred",
			),
		},
	} {
		t.Run(name, func(t *testing.T) {
			docs, out, err := render(t, controllerNS, append([]string{"image.digest=" + digest}, c.set...)...)
			if err != nil {
				t.Fatal(out)
			}
			gs := controllerGrants(t, docs)
			want := slices.Clone(c.want)
			sort.Strings(want)
			if got := secretConfigMapGrants(gs); !reflect.DeepEqual(got, want) {
				t.Fatalf("effective Secret/ConfigMap grants\n got %q\nwant %q", got, want)
			}
			bundles := len(c.set) > 0
			for _, q := range []struct {
				ns, resource, verb, name string
				want                     bool
			}{
				// Needed: by-name reads and ConfigMap creation in the
				// controller namespace.
				{controllerNS, "secrets", "get", "s3-credentials", true},
				{controllerNS, "configmaps", "get", "konstapel-evidence-destination", true},
				{controllerNS, "configmaps", "create", "", true},
				{controllerNS, "configmaps", "list", sourcesCM, bundles},
				{controllerNS, "configmaps", "watch", sourcesCM, bundles},
				// Not needed by any feature.
				{controllerNS, "secrets", "list", "", false},
				{controllerNS, "secrets", "watch", "", false},
				{controllerNS, "secrets", "create", "", false},
				{controllerNS, "secrets", "update", "s3-credentials", false},
				{controllerNS, "secrets", "patch", "s3-credentials", false},
				{controllerNS, "secrets", "delete", "s3-credentials", false},
				{controllerNS, "configmaps", "list", "", false},
				{controllerNS, "configmaps", "watch", "", false},
				{controllerNS, "configmaps", "list", "registry-ca", false},
				{controllerNS, "configmaps", "update", "konstapel-evidence-destination", false},
				{controllerNS, "configmaps", "patch", "konstapel-evidence-destination", false},
				{controllerNS, "configmaps", "delete", "konstapel-evidence-destination", false},
				{controllerNS, "configmaps", "deletecollection", "", false},
				{"default", "secrets", "get", "s3-credentials", false},
				{"kube-system", "secrets", "get", "s3-credentials", false},
				{"default", "configmaps", "get", "konstapel-evidence-destination", false},
				{"default", "configmaps", "create", "", false},
			} {
				if got := allowed(gs, q.ns, q.resource, q.verb, q.name); got != q.want {
					t.Errorf("%s %s %s %q: allowed=%v, want %v", q.ns, q.resource, q.verb, q.name, got, q.want)
				}
			}
		})
	}
}
